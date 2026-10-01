"""Ports and the small network primitives the tests share.

Ports are asked for rather than derived from a base. The suite used to take a `--port`
and reach for `port + 2`, `port + 3`, `port + 5`, `port + 7`, `port + 9`, `port + 11`,
`port + 13` — which is fine until two of those runs overlap, or the host already has
something on one of them, and the failure reads as firegex refusing traffic.
"""

import socket


#: Every port this process has handed out. The kernel does not remember, and over a
#: whole run it will offer the same ephemeral port twice — which is fine for a socket
#: and not fine here, because a port is also half of a service's identity. Two services
#: claiming one `(ip, port, proto)` is refused by the backend, correctly, and it arrives
#: as `could not create the service 'rx-36375'` in the setup of whichever test asked
#: second: a failure that belongs entirely to the test that asked first.
_HANDED_OUT: set[int] = set()


def free_port(ipv6: bool = False, udp: bool = False) -> int:
    """A port nothing is listening on, and that this run has not used before.

    Probed on the transport it will actually be used for. TCP and UDP number their ports
    separately, so a port free for one says nothing about the other — and a QUIC stand-in
    handed a TCP-free port occasionally found it taken, which arrives as an
    `Address already in use` from inside a server thread and reads as a test failure with
    nothing to do with what it was testing.

    Not handed out twice, for the neighbouring reason: the kernel is answering "nothing
    is bound here", which is not the question a service asks. The number is remembered
    across families and transports rather than per pair, because two numbers cost nothing
    and one shared between a TCP test and a UDP test is one more thing to reason about.
    """
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    port = 0
    for _ in range(64):
        with socket.socket(family, kind) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("::1" if ipv6 else "127.0.0.1", 0))
            port = probe.getsockname()[1]
        if port not in _HANDED_OUT:
            break
    # Sixty-four collisions in a row means the ephemeral range is effectively exhausted,
    # and a port that is at least free right now is a better answer than an exception.
    _HANDED_OUT.add(port)
    return port


def loopback(ipv6: bool = False) -> str:
    return "::1" if ipv6 else "127.0.0.1"


def supports_ipv6() -> bool:
    """Whether this host can carry the IPv6 half of the suite at all."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
        return True
    except OSError:
        return False
