"""QUIC, terminated by the engine — and the layer it has no choice about.

TLS over TCP can be carried past unopened: the bytes are framed by a transport the kernel
understands, so a layer that forwards still has packets to count and a rule to match them
with. QUIC leaves not even that. Past the Initial packet it encrypts the frames, the
stream boundaries and the packet number along with the payload, so a packet queued to
userspace is a datagram of noise. Terminating it is the only way a filter sees anything,
which is why it lives on the proxy layer and nowhere else.

What these tests check is the half the engine's own suite cannot reach: the rules that
steer a QUIC address, the relay bound for it, the certificate the API insists on, and a
filter attached the way an operator attaches one.
"""

import time

import pytest

from integration import filter_code
from integration.conftest import (SETTLE, add_python_filter, add_regex_filter,
                                  start_and_settle)
from helpers.net import free_port, supports_ipv6
from helpers.capture import needs_capture, watching
from helpers.quicserver import SECRET_PATH, h3_is_blocked, h3_request, needs_quic

pytestmark = [pytest.mark.instance, pytest.mark.quic]


def test_quic_is_refused_on_a_layer_that_cannot_carry_it(api, certificate):
    """And refused at creation, with an empty chain — a row that is created happily and
    then refuses to start every time is the trap this check exists to avoid."""
    cert, key = certificate()
    port = free_port()
    for transport in ("nfqueue", "external"):
        why = api.services_add_error(
            name=f"{transport}-quic-{port}", transport=transport, proto="quic",
            addresses=[{"ip_int": "127.0.0.1", "port": port}],
            tls_cert=cert, tls_key=key,
            **({"proxy_ip": "127.0.0.1", "proxy_port": free_port()}
               if transport == "external" else {}),
        )
        assert why is not None, f"a QUIC service was created on the {transport} layer"


def test_a_quic_service_needs_a_certificate(api):
    """The engine terminates the handshake, so it has to have something to answer with.

    Refused here rather than by the engine at startup: the operator is holding the form.
    """
    port = free_port()
    why = api.services_add_error(
        name=f"quic-bare-{port}", transport="proxy", proto="quic",
        addresses=[{"ip_int": "127.0.0.1", "port": port}],
    )
    assert why is not None, "a QUIC service was created with nothing to terminate with"


@needs_quic
def test_an_exchange_goes_through(api, service, quic_stand_in):
    """Also the interop test, and the reason the stand-in is somebody else's code.

    The engine sends no GREASE frame, on either edge, and this is what says so: with one
    the stand-in — `aioquic`, a third implementation that agrees with neither of ours —
    received the request and never completed it, because a trailing reserved frame left
    its end-of-stream unreported. If grease comes back, this test stops passing. Do not
    make the stand-in tolerant of it instead: what it is standing in for is whatever the
    operator is actually protecting.
    """
    server = quic_stand_in()
    cert, key = server.material
    service_id = service(f"quic-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    start_and_settle(api, service_id)

    answer = h3_request(server.host, server.port, "/hello")
    assert "/hello" in answer, f"the request did not reach the service: {answer!r}"


@needs_quic
def test_a_pattern_matches_a_request_that_arrived_compressed(api, service, quic_stand_in):
    """The reason for terminating it, in one assertion.

    On the wire that path was a QPACK-compressed header block inside an encrypted packet.
    The filters are shown the HTTP/1.1 the exchange would have been, so a pattern written
    for the TCP service beside it matches here without being rewritten.
    """
    server = quic_stand_in()
    cert, key = server.material
    service_id = service(f"quicflt-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    add_regex_filter(api, service_id, "GET /admin")
    start_and_settle(api, service_id)

    assert "/public" in h3_request(server.host, server.port, "/public")
    assert h3_is_blocked(server.host, server.port, "/admin"), \
        "the filters are not seeing the decrypted request"


@needs_quic
def test_the_answer_is_inspected_too(api, service, quic_stand_in):
    """Nothing in the request carries the pattern; everything that does is in the reply."""
    server = quic_stand_in()
    cert, key = server.material
    service_id = service(f"quicout-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    add_regex_filter(api, service_id, r"FLAG\{")
    start_and_settle(api, service_id)

    assert "/harmless" in h3_request(server.host, server.port, "/harmless")
    assert h3_is_blocked(server.host, server.port, SECRET_PATH), \
        "the answer reached the client with the flag in it"


@needs_quic
def test_the_service_still_sees_the_client(api, service, quic_stand_in):
    """Source transparency holds through a terminated QUIC connection as well.

    The engine opens its own connection to the service, and opens it from the client's
    address — so what the service sees is a client, not a proxy. It is the same
    `IP_TRANSPARENT` dial the datagram relay makes, with a QUIC endpoint on top of it.
    """
    server = quic_stand_in()
    cert, key = server.material
    service_id = service(f"quicsrc-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    start_and_settle(api, service_id)

    h3_request(server.host, server.port, "/whoami")
    assert server.seen_peers, "the service saw no connection at all"
    assert all(peer[0] == "127.0.0.1" for peer in server.seen_peers), \
        f"the service saw the proxy instead of the client: {server.seen_peers}"


@needs_quic
def test_an_address_can_be_added_without_dropping_anything(api, service, quic_stand_in):
    """One endpoint per address, bound on the engine that is already running.

    The same property the datagram relay has, and for the same reason: nothing about a
    QUIC address is recoverable per packet, so each one is bound its own endpoint — and
    binding one more is not a restart.
    """
    server = quic_stand_in()
    second = quic_stand_in(port=free_port())
    cert, key = server.material
    service_id = service(f"quicadd-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    start_and_settle(api, service_id)
    assert "/first" in h3_request(server.host, server.port, "/first")

    assert api.services_add_address(service_id, "127.0.0.1", second.port), \
        "the address was not accepted"
    time.sleep(SETTLE)
    assert "/second" in h3_request(second.host, second.port, "/second"), \
        "the new address is not being carried"
    assert "/again" in h3_request(server.host, server.port, "/again"), \
        "adding an address disturbed the one already running"


@needs_quic
def test_the_same_python_filter_runs_here(api, service, quic_stand_in):
    """`filter_code.HTTP` is the file the TCP tests use, attached unchanged.

    Which is the claim worth testing: a filter asking for an `HttpRequest` is an HTTP
    filter, and moving a service to QUIC must not quietly switch it off. It runs because
    the engine renders each HTTP/3 exchange as the HTTP/1.1 it would have been — and it
    is *detected* as an HTTP filter because that is read off the code, here as anywhere.
    """
    server = quic_stand_in()
    cert, key = server.material
    service_id = service(f"quicpy-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    filter_id = add_python_filter(api, service_id, filter_code.HTTP, name="http")
    detected = [f for f in api.services_filters(service_id)
                if f["filter_id"] == filter_id][0]
    assert detected["proto"] == "http", str(detected)
    start_and_settle(api, service_id)

    assert "/files/ok" in h3_request(server.host, server.port, "/files/ok")
    assert h3_is_blocked(server.host, server.port, "/files/../secret"), \
        "an HttpRequest filter never ran on a QUIC service"


@needs_quic
@needs_capture
def test_each_stream_is_its_own_conversation_on_the_capture(api, service, quic_stand_in):
    """The plaintext reaches `firegex0`, one TCP stream per exchange.

    Two properties, and the second is the one that took work. That the rendering arrives
    at all is what makes the interface mean the same thing on QUIC as on TLS: what is
    written there is what the filters saw, and for HTTP/3 that is the HTTP/1.1 view, since
    what crossed the wire was a QPACK block nobody can point a tool at.

    That the two exchanges arrive as *two* conversations is the reason a stream is given a
    synthetic client port. Every stream of one QUIC connection shares the connection's
    four-tuple, so without that they would interleave into one stream whose bytes decode
    as nothing — worse than an empty interface, because it looks like data.
    """
    server = quic_stand_in()
    cert, key = server.material
    service_id = service(f"quiccap-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    start_and_settle(api, service_id)

    with watching() as capture:
        assert "/alpha" in h3_request(server.host, server.port, "/alpha")
        assert "/beta" in h3_request(server.host, server.port, "/beta")

    # The rendering, not the wire: on the wire this was compressed and encrypted.
    alpha = capture.conversations(b"GET /alpha HTTP/1.1")
    beta = capture.conversations(b"GET /beta HTTP/1.1")
    assert alpha, "the decrypted request never reached the capture interface"
    assert beta, "the decrypted request never reached the capture interface"
    assert alpha.isdisjoint(beta), \
        f"two exchanges were written as one conversation: {alpha} and {beta}"
    for port in alpha | beta:
        assert capture.opened(port), \
            f"the stream on port {port} has no beginning, so nothing can reassemble it"

    # And the answer travels the other way on the same conversation, which is what makes
    # it an exchange rather than two halves that happen to share an interface.
    assert any(s.dst_port in alpha for s in capture.carrying(b"HTTP/1.1 200")), \
        "the reply was not written beside the request it answers"


@needs_quic
@pytest.mark.ipv6
@pytest.mark.skipif(not supports_ipv6(), reason="this host has no IPv6 loopback")
def test_it_works_over_ipv6_too(api, service, quic_stand_in):
    """The same exchange over `::1`, filters and all.

    Worth its own test rather than assumed from the TCP side: a QUIC address is relayed
    by an endpoint bound per address, the family is decided where that endpoint is bound
    and again where the engine dials the service from the client's address, and the rule
    that steers it is written by the same code that writes the UDP one. Four places to
    get a family wrong, and the symptom of getting it wrong is a service that answers on
    one family and silently not on the other.
    """
    server = quic_stand_in(ipv6=True)
    cert, key = server.material
    service_id = service(f"quic6-{server.port}", "::1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    add_regex_filter(api, service_id, "GET /admin")
    start_and_settle(api, service_id)

    assert "/public" in h3_request(server.host, server.port, "/public")
    assert h3_is_blocked(server.host, server.port, "/admin"), \
        "the filters are not seeing the decrypted request over IPv6"


@needs_quic
def test_what_the_service_speaks_can_be_changed_while_it_runs(api, service, quic_stand_in,
                                                              http_stand_in):
    """The relay is keyed by where it sends *and* what it speaks there.

    It used to be keyed by where alone, so the address came back to the relay it already
    had — still speaking HTTP/3 to a service now answering HTTP/1.1 — and the edit was
    saved, shown, and did nothing until the service was restarted.

    Two stand-ins on one port number, one on UDP and one on TCP, tell the two legs apart
    by their answers: the QUIC one echoes what it was sent after a colon, the HTTP/1.1
    one does not.
    """
    quic = quic_stand_in()
    http_stand_in(port=quic.port)
    cert, key = quic.material
    service_id = service(f"quic-onward-{quic.port}", "127.0.0.1", quic.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    start_and_settle(api, service_id)
    assert h3_request(quic.host, quic.port, "/which").endswith("bytes: "), \
        "the exchange did not reach the QUIC service to begin with"

    address = api.services_addresses(service_id)[0]
    assert api.services_edit_address(service_id, address["address_id"], "127.0.0.1",
                                     quic.port, upstream="tcp")
    time.sleep(SETTLE)
    answer = h3_request(quic.host, quic.port, "/which")
    assert answer.endswith("bytes"), \
        f"the edit was saved and the relay went on speaking HTTP/3: {answer!r}"


# --- what a QUIC service negotiates --------------------------------------------------


@needs_quic
def test_a_quic_service_that_is_not_http3_is_reached_with_nothing_to_configure(
        api, service, quic_stand_in):
    """QUIC carries whatever its two ends agree on, and the engine has to say it to both.

    It offered the service a list of its own — one environment variable for the whole
    instance, `h3` unless firegex was restarted with another — because the client's hello
    was taken to be unreadable. So a QUIC service speaking anything but HTTP/3 was not
    reachable through firegex until somebody found that. The hello is read off the
    client's first packet now and offered to the service as it is, the way the TLS path
    has always mirrored it; there is nothing to set.
    """
    from helpers.quicserver import quic_exchange

    server = quic_stand_in(alpn=["fgx-echo"])
    cert, key = server.material
    service_id = service(f"quic-alpn-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key)
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)

    assert quic_exchange(server.host, server.port, "fgx-echo", b"hello") == b"hello", \
        "a QUIC service that is not HTTP/3 was not reached"
    assert quic_exchange(server.host, server.port, "fgx-echo", b"x BLOCKME", timeout=3) \
        != b"x BLOCKME", "a stream carrying a blocked pattern reached the service"
    # And one speaking something the service does not is refused by the service, as it
    # would be with nothing in the way.
    assert quic_exchange(server.host, server.port, "fgx-other", b"hello", timeout=3) is None
