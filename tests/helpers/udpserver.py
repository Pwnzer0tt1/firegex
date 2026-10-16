"""The stand-in UDP service, and a client that talks to it through firegex.

Deliberately not the TCP helper with the protocol swapped. A datagram exchange has no
connection to establish, so "was it refused" is "did an answer come back before the
timeout" rather than "did the socket close" — and there is nothing to keep open between
two datagrams, which is what makes a UDP flow's per-flow state worth testing at all.

A thread rather than a process: an echo loop on a socket needs no isolation, and closing
the socket is a cleaner way to stop it than killing a child.
"""

import socket
import threading
import time


class UdpEcho:
    def __init__(self, port: int, ipv6: bool = False):
        self.port = port
        self.ipv6 = ipv6
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        #: Every peer address a datagram arrived from, in order. What the *service* saw,
        #: which is the only way to check that the client's own address survived the
        #: relay rather than being replaced by firegex's.
        self.seen_peers: list[tuple] = []

    @property
    def host(self) -> str:
        return "::1" if self.ipv6 else "127.0.0.1"

    def start(self):
        family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

        # The thread holds its own reference. `stop()` closes the socket and then sets
        # the attribute to `None`, so a loop reading `self.sock` each time round races
        # with it and raises `AttributeError` on a `None` instead of the `OSError` that
        # is how this loop is meant to end.
        sock = self.sock

        def serve():
            while True:
                try:
                    data, peer = sock.recvfrom(65535)
                except OSError:
                    return  # the socket was closed; that is how this loop ends
                self.seen_peers.append(peer)
                try:
                    sock.sendto(data, peer)
                except OSError:
                    return

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        time.sleep(0.3)

    def stop(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None

    def exchange(self, payload: bytes, timeout: float = 1.5,
                 bind: str | None = None) -> bytes | None:
        """Send one datagram and return the answer, or `None` if none came back.

        `bind` puts the client on a chosen source address, which is how the transparency
        test can tell the address the service sees apart from the loopback default.
        """
        family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            if bind:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((bind, 0))
            sock.sendto(payload, (self.host, self.port))
            return sock.recvfrom(65535)[0]
        except (TimeoutError, OSError):
            return None
        finally:
            sock.close()

    def flow(self, timeout: float = 1.5) -> "HeldFlow":
        """One client socket kept across several exchanges — one flow, to conntrack.

        `exchange` opens a socket per datagram, so every one of them is a flow of its own
        and meets whatever rules are in force when it is sent. What a long-lived client
        does is keep its socket, and that is the case where what conntrack remembers
        decides where the next datagram goes.
        """
        return HeldFlow(self, timeout)

    def answered_from(self, payload: bytes, timeout: float = 1.5) -> tuple | None:
        """Which address the answer came back from.

        A reply has to appear to come from the address the client dialled: it leaves
        through the listener socket so conntrack rewrites it, and a client that sees an
        internal relay port instead simply drops it.
        """
        family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (self.host, self.port))
            return sock.recvfrom(65535)[1]
        except (TimeoutError, OSError):
            return None
        finally:
            sock.close()


class HeldFlow:
    """A UDP client that keeps its source port for as long as it is open. See `flow`."""

    def __init__(self, echo: UdpEcho, timeout: float):
        self.echo = echo
        self.sock = socket.socket(socket.AF_INET6 if echo.ipv6 else socket.AF_INET,
                                  socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def exchange(self, payload: bytes) -> bytes | None:
        """Send one datagram on this flow and return its echo, or `None` if none came.

        Answers to earlier datagrams arriving late are passed over rather than taken for
        this one's, which on one socket is a real possibility.
        """
        try:
            self.sock.sendto(payload, (self.echo.host, self.echo.port))
            deadline = time.monotonic() + (self.sock.gettimeout() or 1.5)
            while time.monotonic() < deadline:
                data = self.sock.recvfrom(65535)[0]
                if data == payload:
                    return data
        except (TimeoutError, OSError):
            pass
        return None

    def close(self):
        self.sock.close()

    def __enter__(self) -> "HeldFlow":
        return self

    def __exit__(self, *exc):
        self.close()
