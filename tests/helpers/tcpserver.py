import queue
from multiprocessing import Process, Queue
import socket
import ssl
import tempfile
import traceback


def _start_tcp_server(port, server_queue: Queue, peer_queue: Queue, ipv6, verbose,
                      tls_cert=None, tls_key=None, tls_alpn=None):
    sock = socket.socket(
        socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM
    )
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("::1" if ipv6 else "127.0.0.1", port))
    sock.listen(8)

    tls_context = None
    if tls_cert and tls_key:
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if tls_alpn:
            tls_context.set_alpn_protocols(tls_alpn)
        # The stand-in service presents whatever certificate the test gave it, including
        # the under-2048-bit one that exists to prove firegex still protects a service
        # carrying one. The distribution's policy would refuse to load it otherwise.
        tls_context.set_ciphers("DEFAULT:@SECLEVEL=1")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as cert_file, \
             tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as key_file:
            cert_file.write(tls_cert)
            key_file.write(tls_key)
            cert_path, key_path = cert_file.name, key_file.name
        tls_context.load_cert_chain(cert_path, key_path)

    while True:
        connection, address = sock.accept()
        # What the *service* saw the connection come from. Reported across the process
        # boundary because that is the only way to check the client's own address
        # survived the proxy, which dials the service as the client rather than as
        # itself.
        peer_queue.put(address)
        if tls_context:
            try:
                connection = tls_context.wrap_socket(connection, server_side=True)
            except ssl.SSLError:
                connection.close()
                continue
        while True:
            try:
                buf = connection.recv(4096)
                if buf == b"":
                    break

                reply = buf  # Default to echo
                try:
                    # See if there is a custom reply, but don't block
                    custom_reply = server_queue.get(block=False)
                    reply = custom_reply
                except queue.Empty:
                    pass  # No custom reply, just echo

                if verbose:
                    print("SERVER: ", reply)
                connection.sendall(reply)
            except (ConnectionResetError, BrokenPipeError):
                break  # Client closed connection
            except Exception:
                if verbose:
                    traceback.print_exc()
                break  # Exit on other errors
        connection.close()


class TcpServer:
    def __init__(self, port, ipv6, proxy_port=None, verbose=False, tls_cert=None, tls_key=None,
                 tls_alpn=None):
        self.proxy_port = proxy_port
        self.ipv6 = ipv6
        self.port = port
        self.verbose = verbose
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        #: Application protocols this stand-in service is willing to speak, so a test can
        #: check that what the client is told is what the *service* chose.
        self.tls_alpn = tls_alpn
        self._server_data_queue = Queue()
        self._peer_queue = Queue()
        self._peers = []
        self._regen_process()

    def _regen_process(self):
        self.server = Process(
            target=_start_tcp_server,
            args=[self.port, self._server_data_queue, self._peer_queue, self.ipv6,
                  self.verbose, self.tls_cert, self.tls_key, self.tls_alpn],
        )

    def start(self):
        self.server.start()

    def stop(self):
        if self.server and self.server.is_alive():
            try:
                self.server.terminate()
                self.server.join()
                import time
                time.sleep(0.1)
            except AttributeError:
                pass
            self.server = None
        self._regen_process()

    def seen_peers(self, wait: float = 1.0):
        """Every address a connection has arrived from, drained from the server process.

        `wait` is not politeness. A `multiprocessing.Queue.put` hands the item to a feeder
        thread and returns, so a caller that closes its client and asks straight away can
        arrive before the bytes are on the pipe — and read an empty list as "the service
        never saw the connection", which is exactly the failure these are checking for.
        """
        first = not self._peers
        while True:
            try:
                self._peers.append(
                    self._peer_queue.get(timeout=wait) if first
                    else self._peer_queue.get(block=False))
                first = False
            except queue.Empty:
                return list(self._peers)

    def connect_client(self, source_ip: str | None = None, timeout: float = 1):
        self.client_sock = socket.socket(
            socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM
        )
        self.client_sock.settimeout(timeout)
        if source_ip:
            # A source the loopback default is not, so "the service saw the client"
            # cannot be satisfied by the address everything already has.
            self.client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.client_sock.bind((source_ip, 0))
        self.client_sock.connect(
            (
                "::1" if self.ipv6 else "127.0.0.1",
                self.proxy_port if self.proxy_port else self.port,
            )
        )

    def close_client(self):
        if self.client_sock:
            self.client_sock.close()

    def send_packet(self, packet, server_reply=None):
        if self.verbose:
            print("CLIENT: ", packet)
        if server_reply:
            self._server_data_queue.put(server_reply)
        self.client_sock.sendall(packet)

    def recv_packet(self, size: int = 4096):
        try:
            return self.client_sock.recv(size)
        except (TimeoutError, ConnectionResetError):
            if self.verbose:
                traceback.print_exc()
            return False

    def sendCheckData(self, data, get_data=False, timeout: float = 3):
        self.connect_client(timeout=timeout)
        self.send_packet(data)
        received_data = self.recv_packet()
        self.close_client()
        if get_data:
            return received_data
        return received_data == data
