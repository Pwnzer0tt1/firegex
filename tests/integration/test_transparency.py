"""Your service goes on seeing who is talking to it.

Source preservation is unconditional: the engine always dials the service from the
client's own address, on TCP with `IP_TRANSPARENT` and on UDP with the same plus mark
`0x1339` and policy routing `table 1339`. `ct status dnat` is what separates the engine
answering a client from the service answering the engine, which is why redirect rather
than tproxy works even when the service is on this host.

This is what the interface used to carry a `NO CLIENT IP` badge for. Nothing gives it up
any more, which is why the badge — and the function that decided when to show it — are
gone.
"""

import pytest

from integration.conftest import start_and_settle
from helpers.traffic import Channel

pytestmark = pytest.mark.instance

#: A loopback address that is not the default, so "the service saw the client" cannot be
#: satisfied by the address everything already has.
CLIENT_SOURCE = "127.0.0.42"


def test_the_service_sees_the_real_client_address_on_tcp(api, protected, proxy_layer):
    if proxy_layer.ipv6:
        pytest.skip("the spare loopback address this uses is an IPv4 one")
    service_id, server, port = protected(proxy_layer, name="transp")
    start_and_settle(api, service_id)

    server.connect_client(source_ip=CLIENT_SOURCE)
    try:
        server.send_packet(b"TRANSPARENCY_TEST")
        assert server.recv_packet() == b"TRANSPARENCY_TEST"
    finally:
        server.close_client()

    peers = server.seen_peers()
    assert peers, "the service recorded no incoming connection at all"
    assert peers[-1][0] == CLIENT_SOURCE, (
        f"the service saw the connection come from {peers[-1][0]!r}; "
        f"the client's own address {CLIENT_SOURCE!r} was not preserved"
    )


def test_the_service_sees_the_real_client_address_on_udp(api, service, udp_stand_in,
                                                         proxy_layer):
    """UDP is relayed with one socket per address rather than recovered per datagram, and
    its dial carries the client's address just as TCP's does — plus `SELF_MARK`, or the
    redirect rule would catch the relay's own dial and loop."""
    if proxy_layer.ipv6:
        pytest.skip("the spare loopback address this uses is an IPv4 one")
    echo = udp_stand_in()
    service_id = service(f"utransp-{echo.port}", "127.0.0.1", echo.port, "proxy",
                         proto="udp")
    start_and_settle(api, service_id, wait=1.2)

    assert echo.exchange(b"UDP_TRANSPARENCY", bind=CLIENT_SOURCE) == b"UDP_TRANSPARENCY"
    assert echo.seen_peers, "the service recorded no datagram at all"
    assert echo.seen_peers[-1][0] == CLIENT_SOURCE, (
        f"the service saw the datagram come from {echo.seen_peers[-1][0]!r}, "
        f"not from {CLIENT_SOURCE!r}"
    )


def test_bulk_traffic_crosses_without_stalling_or_losing_any_of_it(api, protected,
                                                                   proxy_layer):
    """The return path — fwmark `0x1339`, `table 1339` — under something bigger than one
    packet. A proxy that works on a handshake and stalls on a transfer is a proxy that
    passes every short test and fails the round."""
    service_id, server, port = protected(proxy_layer, name="bulk")
    start_and_settle(api, service_id)

    chunk = b"A" * 8192
    total = 16
    server.connect_client(timeout=10)
    try:
        for _ in range(total):
            server.send_packet(chunk)
        received = 0
        while received < len(chunk) * total:
            got = server.recv_packet(16384)
            if not got:
                break
            received += len(got)
        assert received == len(chunk) * total, \
            f"expected {len(chunk) * total} bytes back, got {received}"
    finally:
        server.close_client()


def test_a_filter_cannot_be_stepped_around_by_dialling_the_service_directly(
        api, protected, inspecting_layer):
    """The rules intercept at the address the world dials, which is the address the
    service answers on. There is no second port to aim at instead."""
    from integration.conftest import add_regex_filter

    service_id, server, port = protected(inspecting_layer, name="noskip")
    add_regex_filter(api, service_id, "FORBIDDEN_FLAG")
    start_and_settle(api, service_id)

    channel = Channel(server, port, inspecting_layer.ipv6)
    assert channel.is_blocked(b"send FORBIDDEN_FLAG now")
