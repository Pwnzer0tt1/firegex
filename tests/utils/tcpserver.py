from multiprocessing import Process, Queue
import socket
import traceback

class TcpServer:
    def __init__(self,port,ipv6,proxy_port=None, verbose=False):
        self.proxy_port = proxy_port
        self.ipv6 = ipv6
        self.port = port
        self.verbose = verbose
        self._server_data_queue = Queue()
        self._regen_process()

    def _regen_process(self):
        def _startServer(port, server_queue:Queue):
            sock = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('::1' if self.ipv6 else '127.0.0.1', port))
            sock.listen(8)
            while True:
                connection,address = sock.accept()
                while True:
                    try:
                        buf = connection.recv(4096)
                        if buf == b'':
                            break
                        try:
                            buf = server_queue.get(block=False)
                        except Exception:
                            pass
                        if self.verbose:
                            print("SERVER: ", buf)
                        connection.sendall(buf)
                    except Exception:
                        if self.verbose:
                            traceback.print_exc()
                connection.close()
        self.server = Process(target=_startServer,args=[self.port, self._server_data_queue])

    def start(self):
        self.server.start()
    
    def stop(self):
        self.server.terminate()
        self.server.join()
        self._regen_process()

    def connect_client(self):
        self.client_sock = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        self.client_sock.settimeout(1)
        self.client_sock.connect(('::1' if self.ipv6 else '127.0.0.1', self.proxy_port if self.proxy_port else self.port))      

    def close_client(self):
        if self.client_sock:
            self.client_sock.close()

    def send_packet(self, packet, server_reply=None):
        if self.verbose:
            print("CLIENT: ", packet)
        if server_reply:
            self._server_data_queue.put(server_reply)
        self.client_sock.sendall(packet)
    
    def recv_packet(self):
        try:
            return self.client_sock.recv(4096)
        except TimeoutError:
            if self.verbose:
                traceback.print_exc()
            return False
    
    def sendCheckData(self, data, get_data=False):
        self.connect_client()
        self.send_packet(data)
        received_data = self.recv_packet()
        self.close_client()
        if get_data:
            return received_data
        return received_data == data