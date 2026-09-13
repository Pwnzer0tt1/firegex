"""Ports and the small network primitives the tests share.

Ports are asked for rather than derived from a base. The suite used to take a `--port`
and reach for `port + 2`, `port + 3`, `port + 5`, `port + 7`, `port + 9`, `port + 11`,
`port + 13` — which is fine until two of those runs overlap, or the host already has
something on one of them, and the failure reads as firegex refusing traffic.
"""

import socket


def free_port(ipv6: bool = False) -> int:
    """A port nothing is listening on, on the loopback address the caller will use."""
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("::1" if ipv6 else "127.0.0.1", 0))
        return probe.getsockname()[1]


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
