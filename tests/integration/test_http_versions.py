"""The test that says whether the objective was reached.

One filter file, unchanged, in front of an HTTP/1.1 service, an HTTP/2 service and an
HTTP/3 service, blocking the same request on all three.

It can only pass because each version is rendered to the chain as the HTTP/1.1 it would
have been. On the wire that path is plain text on HTTP/1.1, an HPACK-compressed header
block on HTTP/2 and a QPACK one on HTTP/3, so a filter asking for an `HttpRequest` used to
be called on the first alone — and on the other two it was handed a compression format,
never ran, and said nothing about it. A firewall whose rules quietly stop applying when a
client picks a newer protocol is worse than one that refuses the protocol outright.

The HTTP/2 leg is a gRPC service, because a gRPC service *is* an HTTP/2 service and the
suite already stands a real one up. What the filter is shown there is an HTTP/2 request
with a path, which is the thing under test; that it happens to be a gRPC method name
changes nothing about the question.
"""

import pytest

from integration import filter_code
from integration.conftest import add_python_filter, add_regex_filter, start_and_settle
from helpers.grpcserver import GrpcService, call, channel, needs_grpc
from helpers.net import free_port
from helpers.quicserver import h3_is_blocked, h3_request, needs_quic
from helpers.traffic import Channel

pytestmark = [pytest.mark.instance, pytest.mark.http2]

#: The same request, in the three shapes a client can send it.
BLOCKED_PATH = "/files/../secret"
ALLOWED_PATH = "/files/ok"

HTTP11_BLOCKED = f"GET {BLOCKED_PATH} HTTP/1.1\r\nHost: x\r\n\r\n".encode()
HTTP11_ALLOWED = f"GET {ALLOWED_PATH} HTTP/1.1\r\nHost: x\r\n\r\n".encode()


@pytest.fixture
def grpc_stand_in():
    started = []

    def _serve(cert: str | None = None, key: str | None = None) -> GrpcService:
        service = GrpcService(free_port(), cert, key)
        service.start()
        started.append(service)
        return service

    yield _serve

    for service in started:
        try:
            service.stop()
        except Exception:
            pass


def _grpc_blocked(port: int, path: str, cert: str | None) -> bool:
    """Whether the exchange was refused, as a client sees a refusal.

    A block closes the connection carrying the request rather than answering it, so from
    out here it is an error; getting an answer back is the request having gone through.
    """
    import grpc
    with channel(port, cert) as chan:
        try:
            call(chan, path, b"hello")
            return False
        except grpc.RpcError:
            return True


@needs_grpc
@needs_quic
def test_one_python_filter_covers_http1_http2_and_http3(api, service, stand_in,
                                                        grpc_stand_in, quic_stand_in,
                                                        certificate):
    """`filter_code.HTTP`, saved three times and edited never.

    Three services, three protocols, three real client libraries — and one file, which is
    the whole claim. If this passes and the three assertions below disagree with each
    other, the rendering has drifted between the protocols, which is the failure the
    shared `http1.rs` exists to make impossible.
    """
    cert, key = certificate()

    # HTTP/1.1, on a plain TCP service. The stand-in echoes, so the *reply* is not itself
    # valid HTTP — which is why the shared file turns the invalid-encoding refusal off.
    plain = stand_in()
    http11 = service(f"v11-{plain.port}", "127.0.0.1", plain.port, "proxy")
    add_python_filter(api, http11, filter_code.HTTP, name="http")
    start_and_settle(api, http11)

    # HTTP/2, on an `http` service: TLS on the wire, `h2` agreed by ALPN, and each
    # exchange terminated and rendered.
    grpc_server = grpc_stand_in(cert, key)
    http2 = service(f"v2-{grpc_server.port}", "127.0.0.1", grpc_server.port, "proxy",
                    proto="http", tls_cert=cert, tls_key=key)
    add_python_filter(api, http2, filter_code.HTTP, name="http")
    start_and_settle(api, http2)

    # HTTP/3, on a QUIC service.
    h3_server = quic_stand_in()
    h3_cert, h3_key = h3_server.material
    http3 = service(f"v3-{h3_server.port}", "127.0.0.1", h3_server.port, "proxy",
                    proto="quic", tls_cert=h3_cert, tls_key=h3_key)
    add_python_filter(api, http3, filter_code.HTTP, name="http")
    start_and_settle(api, http3)

    # The innocent request reaches all three.
    channel11 = Channel(plain, plain.port, False)
    assert channel11.gets_through(HTTP11_ALLOWED), "HTTP/1.1 refused an innocent request"
    assert not _grpc_blocked(grpc_server.port, ALLOWED_PATH, cert), \
        "HTTP/2 refused an innocent request"
    assert ALLOWED_PATH in h3_request(h3_server.host, h3_server.port, ALLOWED_PATH), \
        "HTTP/3 refused an innocent request"

    # And the same file blocks the same one on all three.
    assert channel11.is_blocked(HTTP11_BLOCKED), \
        "the filter did not run on HTTP/1.1, where it always did"
    assert _grpc_blocked(grpc_server.port, BLOCKED_PATH, cert), \
        ("the filter did not run on HTTP/2: the request reached the service, which means "
         "the exchange was not rendered and an HttpRequest filter was never called")
    assert h3_is_blocked(h3_server.host, h3_server.port, BLOCKED_PATH), \
        "the filter did not run on HTTP/3"


@needs_grpc
@needs_quic
def test_one_pattern_covers_http1_http2_and_http3(api, service, stand_in, grpc_stand_in,
                                                  quic_stand_in, certificate):
    """The same claim for a hyperscan pattern, which is the other half of a chain.

    A pattern is written against a request line, and a request line is what the rendering
    produces on every version. Before HTTP/2 was rendered, this pattern matched on two of
    the three and nothing said which.
    """
    cert, key = certificate()

    plain = stand_in()
    http11 = service(f"rx11-{plain.port}", "127.0.0.1", plain.port, "proxy")
    add_regex_filter(api, http11, f"GET {BLOCKED_PATH}")
    start_and_settle(api, http11)

    grpc_server = grpc_stand_in(cert, key)
    http2 = service(f"rx2-{grpc_server.port}", "127.0.0.1", grpc_server.port, "proxy",
                    proto="http", tls_cert=cert, tls_key=key)
    # The path is the part that was compressed; the method gRPC sends is a POST.
    add_regex_filter(api, http2, BLOCKED_PATH)
    start_and_settle(api, http2)

    h3_server = quic_stand_in()
    h3_cert, h3_key = h3_server.material
    http3 = service(f"rx3-{h3_server.port}", "127.0.0.1", h3_server.port, "proxy",
                    proto="quic", tls_cert=h3_cert, tls_key=h3_key)
    add_regex_filter(api, http3, f"GET {BLOCKED_PATH}")
    start_and_settle(api, http3)

    channel11 = Channel(plain, plain.port, False)
    # The innocent one first, on every leg. Without it a setup broken in some way that
    # has nothing to do with filtering — a handshake that fails, a service that is not
    # there — reads as a block and the whole test passes for the wrong reason.
    assert channel11.gets_through(HTTP11_ALLOWED)
    assert not _grpc_blocked(grpc_server.port, ALLOWED_PATH, cert)
    assert ALLOWED_PATH in h3_request(h3_server.host, h3_server.port, ALLOWED_PATH)

    assert channel11.is_blocked(HTTP11_BLOCKED)
    assert _grpc_blocked(grpc_server.port, BLOCKED_PATH, cert), \
        "a pattern did not match a path that arrived HPACK-compressed"
    assert h3_is_blocked(h3_server.host, h3_server.port, BLOCKED_PATH)


@needs_grpc
def test_an_http_service_carries_its_cleartext_and_its_tls_edge_at_once(
        api, service, grpc_stand_in, certificate):
    """One service, two addresses, one chain — which is what `http` is for.

    A daemon answering in the clear on one port and under TLS on another used to need two
    firegex services with the same filters copied between them by hand, and a chain kept
    in step by hand is one that stops protecting one of them silently. The edge is decided
    per connection, from what the client actually sent.
    """
    cert, key = certificate()
    encrypted = grpc_stand_in(cert, key)
    clear = grpc_stand_in()
    service_id = service(
        f"http-both-{encrypted.port}", "127.0.0.1", encrypted.port, "proxy",
        proto="http", tls_cert=cert, tls_key=key,
        addresses=[{"ip_int": "127.0.0.1", "port": encrypted.port, "edge": "tls"},
                   {"ip_int": "127.0.0.1", "port": clear.port, "edge": "tcp"}],
    )
    add_regex_filter(api, service_id, "/fgex.Echo/Forbidden")
    start_and_settle(api, service_id)

    # The innocent call works on both edges…
    with channel(encrypted.port, cert) as chan:
        assert call(chan, "/fgex.Echo/Unary", b"hello") == b"you sent hello"
    with channel(clear.port) as chan:
        assert call(chan, "/fgex.Echo/Unary", b"hello") == b"you sent hello"

    # …and the one chain refuses on both, which is the whole point of one service.
    assert _grpc_blocked(encrypted.port, "/fgex.Echo/Forbidden", cert), \
        "the TLS edge of an http service went unfiltered"
    assert _grpc_blocked(clear.port, "/fgex.Echo/Forbidden", None), \
        "the cleartext edge of an http service went unfiltered"


@needs_grpc
@needs_quic
def test_all_three_edges_of_one_http_service_share_one_chain(
        api, service, grpc_stand_in, quic_stand_in, certificate):
    """The shape an `http` service exists for: three ports, one chain, one certificate.

    A daemon reached in the clear on one port, under TLS on another and over HTTP/3 on a
    third. Before this it took three firegex services with the same filters pasted into
    each of them, and a chain kept in step by hand is one that stops protecting one of
    them silently — the same argument that put several addresses under one service.

    The certificate has to be the QUIC stand-in's, because that one is a real service
    with its own TLS and firegex opens a second QUIC handshake towards it; the TCP legs
    are happy with any.
    """
    quic_server = quic_stand_in()
    cert, key = quic_server.material
    encrypted = grpc_stand_in(cert, key)
    clear = grpc_stand_in()

    service_id = service(
        f"http-three-{quic_server.port}", "127.0.0.1", encrypted.port, "proxy",
        proto="http", tls_cert=cert, tls_key=key,
        addresses=[
            {"ip_int": "127.0.0.1", "port": encrypted.port, "edge": "tls"},
            {"ip_int": "127.0.0.1", "port": clear.port, "edge": "tcp"},
            {"ip_int": "127.0.0.1", "port": quic_server.port, "edge": "quic"},
        ],
    )
    add_regex_filter(api, service_id, BLOCKED_PATH)
    start_and_settle(api, service_id)

    # Every edge carries the innocent request…
    with channel(encrypted.port, cert) as chan:
        assert call(chan, ALLOWED_PATH, b"hello") == b"you sent hello", \
            "the TLS edge did not answer"
    with channel(clear.port) as chan:
        assert call(chan, ALLOWED_PATH, b"hello") == b"you sent hello", \
            "the cleartext edge did not answer"
    assert ALLOWED_PATH in h3_request("127.0.0.1", quic_server.port, ALLOWED_PATH), \
        "the HTTP/3 edge did not answer"

    # …and the one pattern refuses on all three, which is the whole point.
    assert _grpc_blocked(encrypted.port, BLOCKED_PATH, cert), \
        "the TLS edge went unfiltered"
    assert _grpc_blocked(clear.port, BLOCKED_PATH, None), \
        "the cleartext edge went unfiltered"
    assert h3_is_blocked("127.0.0.1", quic_server.port, BLOCKED_PATH), \
        "the HTTP/3 edge went unfiltered"


# --- and one service reached in a version it does not speak ---------------------------


@needs_quic
def test_an_http1_service_is_reached_by_an_http3_client(api, service, http_stand_in,
                                                        certificate):
    """The other half of one rendering: it can be *sent*, not only shown.

    Most of the web is a service that speaks HTTP/1.1 and never will speak QUIC. Because
    each exchange is already turned into the HTTP/1.1 the filters are shown, that same
    rendering can go on to the service — so firegex terminates HTTP/3 in front of an
    ordinary web service, which is what `upstream="tcp"` asks for. Nothing about the
    chain changes, which is what the block below is here to say.
    """
    cert, key = certificate("127.0.0.1")
    server = http_stand_in()
    service_id = service(f"h3toh1-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="quic", tls_cert=cert, tls_key=key, upstream="tcp")
    add_regex_filter(api, service_id, BLOCKED_PATH)
    start_and_settle(api, service_id)

    assert ALLOWED_PATH in h3_request("127.0.0.1", server.port, ALLOWED_PATH), \
        "an HTTP/3 client could not reach the HTTP/1.1 service behind it"
    assert h3_is_blocked("127.0.0.1", server.port, BLOCKED_PATH), \
        "the chain stopped seeing the exchange once the service spoke another version"


def _whole_answer(sock, timeout: float) -> bytes:
    """Read one HTTP/1.1 message, not the first segment that happens to arrive.

    The head and the body of a proxied response land separately often enough that reading
    once is a test failing for a reason belonging to TCP — which it did, on both legs of
    the one below, and in the same way.
    """
    got = b""
    while b"\r\n\r\n" not in got or not got.split(b"\r\n\r\n", 1)[1]:
        piece = sock.recv(65535)
        if not piece:
            break
        got += piece
    return got


def _http11(port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    """One HTTP/1.1 exchange in the clear, without the echo helper's assumptions.

    `Channel` compares what comes back with what went out, which is exactly right for the
    echo stand-in and exactly wrong for a service that answers. Here what matters is that
    an answer came back at all and that it is the service's.
    """
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(payload)
            return _whole_answer(sock, timeout)
    except OSError:
        return b""


def _https11(port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    """The same, through a real TLS handshake."""
    import socket
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as sock:
                sock.sendall(payload)
                return _whole_answer(sock, timeout)
    except OSError:
        return b""


@needs_quic
def test_one_service_is_published_in_the_clear_under_tls_and_over_http3(
        api, service, http_stand_in, certificate):
    """The shape an operator actually has: one daemon, three ways in.

    A service answering HTTP/1.1 in the clear on one port, and nothing else — no TLS of
    its own, no QUIC, no second port. It is *published* on two more: TLS on one, HTTP/3
    on another, both pointing back at the port it already listens on. Firegex terminates
    what each client speaks, renders every version as the same HTTP/1.1, runs one chain
    over all three, and sends the service what it has always understood.

    Three addresses and one filter. Before this the operator's options were to make the
    service speak TLS and QUIC itself, or to run three services with the chain copied
    between them by hand — which is the failure a list of addresses exists to prevent.
    """
    cert, key = certificate("127.0.0.1")
    server = http_stand_in()
    tls_port, h3_port = free_port(), free_port(udp=True)
    service_id = service(
        f"pub-{server.port}", "127.0.0.1", server.port, "proxy",
        proto="http", tls_cert=cert, tls_key=key,
        addresses=[
            # The service itself, in the clear, where it really is.
            {"ip_int": "127.0.0.1", "port": server.port, "edge": "tcp"},
            # And the two it is published on: each says where the service is *and* that
            # it answers in the clear, because both are facts about the way in.
            {"ip_int": "127.0.0.1", "port": tls_port, "edge": "tls",
             "target_port": server.port, "upstream": "tcp"},
            {"ip_int": "127.0.0.1", "port": h3_port, "edge": "quic",
             "target_port": server.port, "upstream": "tcp"},
        ],
    )
    add_regex_filter(api, service_id, BLOCKED_PATH)
    start_and_settle(api, service_id)

    # In the clear, on the service's own port.
    assert b"you asked for" in _http11(server.port, HTTP11_ALLOWED), \
        "the service stopped answering on its own port"

    # Under TLS, on a port it has never listened on.
    assert b"you asked for" in _https11(tls_port, HTTP11_ALLOWED), \
        "the TLS publication did not reach the cleartext service"

    # And over HTTP/3, on another one.
    assert ALLOWED_PATH in h3_request("127.0.0.1", h3_port, ALLOWED_PATH), \
        "the HTTP/3 publication did not reach the cleartext service"

    # One chain over all three, which is the point of them being one service.
    assert b"you asked for" not in _http11(server.port, HTTP11_BLOCKED), \
        "the chain did not run on the cleartext edge"
    assert b"you asked for" not in _https11(tls_port, HTTP11_BLOCKED), \
        "the chain did not run on the TLS publication"
    assert h3_is_blocked("127.0.0.1", h3_port, BLOCKED_PATH), \
        "the chain did not run on the HTTP/3 publication"


def test_an_https_edge_on_an_interface_is_reached_as_one(
        api, service, http_stand_in, certificate):
    """An interface is a way of spelling an address, not a lesser kind of one.

    The engine keys what it is told about an address on what `SO_ORIGINAL_DST` hands
    back, which is an address and never an interface name — so a row naming an interface
    had nothing to key on and was simply left out of the announcement. The rules were
    installed and the port was redirected, so the connection arrived; the engine then met
    it knowing nothing, terminated it as an ordinary one and dialled the port it came in
    on, where nothing listens.

    What that looked like to an operator: HTTPS declared on `lo:443` did not answer at
    all, while the very same address written `127.0.0.1:443` worked. Reported that way,
    and found by trying both.
    """
    cert, key = certificate("127.0.0.1")
    server = http_stand_in()
    tls_port = free_port()
    service_id = service(
        f"ifacetls-{server.port}", "lo", server.port, "proxy",
        proto="http", tls_cert=cert, tls_key=key,
        addresses=[
            # The service itself, in the clear, named by the interface it answers on.
            {"ip_int": "lo", "port": server.port, "edge": "tcp"},
            # And the encrypted way in, named the same way.
            {"ip_int": "lo", "port": tls_port, "edge": "tls",
             "target_port": server.port, "upstream": "tcp"},
        ],
    )
    add_regex_filter(api, service_id, BLOCKED_PATH)
    start_and_settle(api, service_id)

    assert b"you asked for" in _http11(server.port, HTTP11_ALLOWED), \
        "the cleartext edge did not reach the service"
    assert b"you asked for" in _https11(tls_port, HTTP11_ALLOWED), \
        "the HTTPS edge declared on an interface never reached the service"
    assert b"you asked for" not in _https11(tls_port, HTTP11_BLOCKED), \
        "the chain did not run on the HTTPS edge"
