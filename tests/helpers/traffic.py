"""Asking a protected service a question, the same way whichever layer is in front of it.

The suite used to branch on TLS at every single traffic check — `if args.tls: tls_connect
... else: server.sendCheckData ...` — about twenty times, which is twenty places for the
two halves to drift apart. They are the same question: *does this payload reach the
service and come back, or did a filter refuse it?* Only the transport differs, so only
the transport is behind this seam.

Retries are here for one reason and they cannot weaken a check. One TCP exchange is a
noisy way to observe a filter's decision — a connection that fails for its own reasons
looks exactly like one a filter refused — so `gets_through` retries. A filter that
refuses a payload refuses it on every attempt, so no amount of retrying turns a real
block into a pass. `is_blocked` does not retry for the mirrored reason: a single success
is proof it was not blocked.
"""

import time

from helpers.tls_helpers import tls_connect_send_recv


class Channel:
    """A client for a protected service, hiding only whether TLS is in the way."""

    #: How long to wait for an answer. One second — which this was — is tight for a
    #: proxied connection on a box that is also carrying the rest of the suite, and the
    #: failure mode is the worst one available: a slow answer read as a block.
    TIMEOUT = 3.0

    def __init__(self, server, port: int, ipv6: bool = False, tls: bool = False):
        self.server = server
        self.port = port
        self.ipv6 = ipv6
        self.tls = tls

    def echo(self, payload: bytes) -> bytes | None:
        """Send `payload` once and return what came back, or `None`/`False` if nothing did."""
        if self.tls:
            return tls_connect_send_recv(self.port, self.ipv6, payload,
                                         timeout=self.TIMEOUT)
        return self.server.sendCheckData(payload, get_data=True, timeout=self.TIMEOUT)

    def gets_through(self, payload: bytes, attempts: int = 5) -> bool:
        """Did this traffic reach the service and come back unchanged?"""
        for _ in range(attempts):
            if self.echo(payload) == payload:
                return True
            time.sleep(0.3)
        return False

    def is_blocked(self, payload: bytes) -> bool:
        """Was this traffic refused?

        A block is an absence: the connection is closed, or reset, or simply answers
        nothing. What must not come back is the payload itself, which is what the
        stand-in service echoes when the traffic reached it.
        """
        got = self.echo(payload)
        return not got or got != payload

    def split_across_writes(self, first: bytes, second: bytes,
                            pause: float = 0.3) -> bytes | None:
        """Send a payload in two writes, with a gap, and return what came back.

        The reason the matcher keeps per-connection state: a pattern that lands across
        two writes is still the pattern, however far apart the halves are.
        """
        if self.tls:
            # TLS records are written as they are handed over, so two `sendall` calls on
            # one session are two records — the same split, one layer up.
            return tls_connect_send_recv(self.port, self.ipv6, first,
                                         then=second, pause=pause)
        self.server.connect_client()
        try:
            self.server.send_packet(first)
            time.sleep(pause)
            self.server.send_packet(second)
            return self.server.recv_packet()
        finally:
            self.server.close_client()


def reaches(external, marker: bytes, attempts: int = 6) -> bool:
    """Did traffic aimed at the service land on the operator's own proxy instead?

    The stand-in proxy answers with a marker while the real service echoes, so the reply
    says which of the two the connection actually reached. Telling them apart by *which*
    one answers is the only way: Linux refuses a loopback connection to a port with no
    listener without emitting a packet, so no rule can rescue a test that stops the real
    service and waits to see nothing.
    """
    for _ in range(attempts):
        try:
            external.connect_client()
            try:
                external.send_packet(b"hello", server_reply=marker)
                if external.recv_packet() == marker:
                    return True
            finally:
                external.close_client()
        except OSError:
            pass
        time.sleep(0.4)
    return False
