"""UDP, on whichever layer.

Both carry it and the same filters work on both, which is the whole point of the model.
They get there differently: the proxy relays datagrams with **one socket per protected
address** — `SO_ORIGINAL_DST` is TCP-only, so there is nothing to recover per datagram and
nothing to recover it from — while NFQUEUE inspects the real datagram in place.

What UDP keeps on both: per-flow filter state, released after a timeout because a datagram
has no close to observe, and the client's own address, which the proxy preserves with
`IP_TRANSPARENT` rather than giving up.
"""

import time

import pytest

from integration import filter_code
from integration.conftest import (Layer, add_python_filter, add_regex_filter,
                                  start_and_settle)

pytestmark = pytest.mark.instance

UDP_LAYERS = [
    pytest.param(Layer("proxy", ipv6=False), id="proxy-ipv4"),
    pytest.param(Layer("proxy", ipv6=True), id="proxy-ipv6", marks=pytest.mark.ipv6),
    pytest.param(Layer("nfqueue", ipv6=False), id="nfqueue-ipv4"),
    pytest.param(Layer("nfqueue", ipv6=True), id="nfqueue-ipv6", marks=pytest.mark.ipv6),
]


@pytest.fixture(params=UDP_LAYERS)
def udp_layer(request) -> Layer:
    return request.param


@pytest.fixture
def udp_service(api, service, udp_stand_in, udp_layer):
    """A running UDP service refusing anything carrying DENYME."""
    echo = udp_stand_in(udp_layer.ipv6)
    service_id = service(f"udp-{echo.port}", udp_layer.ip, echo.port,
                         udp_layer.transport, proto="udp")
    add_regex_filter(api, service_id, "DENYME")
    start_and_settle(api, service_id, wait=1.2)
    return service_id, echo


def test_a_benign_datagram_is_relayed_and_answered(udp_service):
    _, echo = udp_service
    assert echo.exchange(b"hello there") == b"hello there"


def test_a_matching_datagram_is_refused(udp_service):
    _, echo = udp_service
    assert echo.exchange(b"carrying DENYME") is None


def test_the_flow_survives_a_refused_datagram(udp_service):
    """`Verdict::Reject` drops the datagram rather than closing anything, because there
    is nothing to close."""
    _, echo = udp_service
    assert echo.exchange(b"carrying DENYME") is None
    assert echo.exchange(b"still here") == b"still here"


def test_the_block_is_counted_against_the_pattern(api, udp_service):
    service_id, echo = udp_service
    echo.exchange(b"carrying DENYME")
    time.sleep(0.6)
    filter_id = api.services_filters(service_id)[0]["filter_id"]
    rows = api.services_regexes(service_id, filter_id)
    assert any(r["blocked"] >= 1 for r in rows), str(rows)


def test_the_reply_appears_to_come_from_the_address_the_client_dialled(udp_service):
    """Replies leave through the *listener* socket so conntrack rewrites them.

    Sending from the upstream socket would reach a client not expecting that source, and
    the client would simply drop it.
    """
    _, echo = udp_service
    answered_from = echo.answered_from(b"who answered")
    assert answered_from is not None, "no answer came back at all"
    assert answered_from[1] == echo.port, \
        f"the answer came from {answered_from}, not the port the client dialled"


def test_a_second_udp_address_is_relayed_without_restarting(api, udp_service,
                                                            udp_stand_in, udp_layer):
    """New relays are bound on the fly over the control channel (`ADD_UDP`), so adding a
    UDP address drops nothing — the same promise TCP has always had here."""
    service_id, first = udp_service
    second = udp_stand_in(udp_layer.ipv6)

    why = api.services_add_address_error(service_id, udp_layer.ip, second.port)
    assert why is None, why
    time.sleep(1.2)

    assert second.exchange(b"hello second") == b"hello second"
    assert second.exchange(b"carrying DENYME") is None, \
        "the same chain is not filtering the new UDP address"
    assert first.exchange(b"still here") == b"still here", \
        "the original UDP address stopped answering"

    entries = api.services_logs(service_id)
    assert any("also protecting" in e["text"] for e in entries), str(entries[-4:])


def test_a_python_filter_works_on_datagrams(api, udp_service):
    """`cpproxy` gained `filter_action_udp` — no stream follower, no ack fixing, because
    a datagram is complete in itself."""
    service_id, echo = udp_service
    assert api.services_stop(service_id)
    add_python_filter(api, service_id, filter_code.UDP, name="datagrams")
    start_and_settle(api, service_id, wait=1.2)

    assert echo.exchange(b"carrying PYDENY") is None
    assert echo.exchange(b"perfectly fine") == b"perfectly fine"


def test_the_udp_block_is_counted_against_the_function_that_made_it(api, udp_service):
    service_id, echo = udp_service
    assert api.services_stop(service_id)
    filter_id = add_python_filter(api, service_id, filter_code.UDP, name="datagrams")
    start_and_settle(api, service_id, wait=1.2)

    echo.exchange(b"carrying PYDENY")
    time.sleep(0.8)
    functions = api.services_functions(service_id, filter_id)
    assert any(f["blocked"] >= 1 for f in functions), str(functions)


def test_a_filter_needing_a_tcp_stream_is_refused_on_a_udp_service(api, udp_service):
    """`RawPacket` is the only model that survives a datagram.

    Every other one declines to be built when the traffic is not TCP, so a filter asking
    for one would sit in the chain and never be called. The refusal names both the
    service's protocol and the model that cannot be built on it.
    """
    service_id, _ = udp_service
    assert api.services_stop(service_id)
    assert api.services_add_filter(service_id, "pyfilter", "wants-http")
    filter_id = [f["filter_id"] for f in api.services_filters(service_id)
                 if f["name"] == "wants-http"][0]

    why = api.services_set_code_error(service_id, filter_id, filter_code.HTTP)
    assert why is not None, "a filter needing a TCP stream was saved on a UDP service"
    assert "UDP" in why and "HttpRequest" in why, why


def test_a_tcp_service_and_a_udp_one_may_share_an_address(api, service, stand_in,
                                                          udp_stand_in):
    """Exactly as the kernel allows, which is what makes `(ip, port, proto)` the key.

    The protocol is denormalised onto each address for this reason; `tls` is stored as
    the TCP it is on the wire, or a TCP service and a TLS one could claim one `ip:port`
    between them.
    """
    tcp_server = stand_in()
    udp_echo = udp_stand_in(port=tcp_server.port)

    tcp_id = service(f"shared-tcp-{tcp_server.port}", "127.0.0.1", tcp_server.port,
                     "proxy")
    udp_id = service(f"shared-udp-{udp_echo.port}", "127.0.0.1", udp_echo.port,
                     "proxy", proto="udp")
    assert tcp_id and udp_id
    start_and_settle(api, tcp_id)
    start_and_settle(api, udp_id, wait=1.2)
    assert udp_echo.exchange(b"both at once") == b"both at once"


def test_udp_on_an_interface_needs_an_address_to_bind_a_relay_to(api, service,
                                                                 udp_stand_in):
    """A relay binds somewhere concrete, and an interface name is not somewhere.

    The interface's own address stands in — IPv4 first and link-local last, because an
    interface almost always carries an `fe80::` address it was never configured with, and
    binding there would put the service where nobody dials.
    """
    echo = udp_stand_in()
    service_id = service(f"udpif-{echo.port}", "lo", echo.port, "proxy", proto="udp")
    started = api.services_start(service_id)
    if not started:
        pytest.skip("this host has no `lo` to resolve, or would not start the service")
    time.sleep(1.2)
    assert echo.exchange(b"through the interface") == b"through the interface"
