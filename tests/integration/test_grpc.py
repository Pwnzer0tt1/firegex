"""gRPC, filtered — which is what rendering HTTP/2 was for.

gRPC is HTTP/2, and before the engine rendered it there was nothing to filter with: the
method name lives in `:path` and the status in a trailer section, both HPACK-compressed on
the wire. A pattern written against a method matched nothing, a filter asking for an
`HttpRequest` was handed the connection preface and then frames it could not read, and the
verdict was ACCEPT with nothing in the log to say why. Only a message body travelled in the
clear.

These tests put a real gRPC service behind firegex and a real gRPC client in front of it,
on all three edges an `http` service answers on, and check both halves: that the filters
see the exchange, and that firegex does not disturb the ones it lets through — including
the two shapes that are easy to break, a bidirectional stream and a trailers-only status.
"""

import pytest

from integration import filter_code
from integration.conftest import (add_python_filter, add_regex_filter,
                                  start_and_settle)
from helpers.grpcserver import (FORBIDDEN, SECRET, TRAILERS_ONLY, UNARY,
                                GrpcService, bidi, call, channel, needs_grpc,
                                server_stream)
from helpers.net import free_port

pytestmark = [pytest.mark.instance, pytest.mark.http2]


@pytest.fixture
def grpc_stand_in():
    """A gRPC service on a port nothing else is using, in the clear or behind TLS."""
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


def _grpc_error(fn, *args, **kwargs):
    """Run a call and give back the error it raised, or None."""
    import grpc
    try:
        fn(*args, **kwargs)
        return None
    except grpc.RpcError as e:
        return e


@needs_grpc
def test_a_unary_call_goes_through(api, service, grpc_stand_in, certificate):
    """The interop test, and the reason the stand-in is somebody else's code.

    Everything below asks whether firegex *sees* the exchange; this one asks first whether
    a real gRPC client and a real gRPC service still understand each other with the engine
    terminating HTTP/2 between them.
    """
    cert, key = certificate()
    server = grpc_stand_in(cert, key)
    service_id = service(f"grpc-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="http", tls_cert=cert, tls_key=key)
    start_and_settle(api, service_id)

    with channel(server.port, cert) as chan:
        assert call(chan, UNARY, b"hello") == b"you sent hello"


@needs_grpc
def test_a_pattern_matches_a_method_that_arrived_compressed(api, service, grpc_stand_in,
                                                            certificate):
    """The whole point, in one assertion.

    On the wire that method name was an HPACK-compressed header block inside TLS. The
    filters are shown the HTTP/1.1 the exchange would have been, so a pattern naming the
    method matches — which it could not do at all before HTTP/2 was rendered.
    """
    cert, key = certificate()
    server = grpc_stand_in(cert, key)
    service_id = service(f"grpcflt-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="http", tls_cert=cert, tls_key=key)
    add_regex_filter(api, service_id, FORBIDDEN)
    start_and_settle(api, service_id)

    with channel(server.port, cert) as chan:
        assert call(chan, UNARY, b"hello") == b"you sent hello", \
            "an unrelated method was affected"
    with channel(server.port, cert) as chan:
        assert _grpc_error(call, chan, FORBIDDEN, b"hello") is not None, \
            "the filters are not seeing the method name"


@needs_grpc
def test_the_answer_is_inspected_too(api, service, grpc_stand_in, certificate):
    """Nothing in the request carries the pattern; everything that does is in the reply."""
    cert, key = certificate()
    server = grpc_stand_in(cert, key)
    service_id = service(f"grpcout-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="http", tls_cert=cert, tls_key=key)
    add_regex_filter(api, service_id, r"FLAG\{")
    start_and_settle(api, service_id)

    with channel(server.port, cert) as chan:
        assert call(chan, UNARY, b"hello") == b"you sent hello"
    with channel(server.port, cert) as chan:
        assert _grpc_error(call, chan, UNARY, b"secret") is not None, \
            f"the answer reached the client with {SECRET!r} in it"


@needs_grpc
def test_server_streaming_is_carried(api, service, grpc_stand_in, certificate):
    """Three messages on one stream, each judged as it goes past and none held back."""
    cert, key = certificate()
    server = grpc_stand_in(cert, key)
    service_id = service(f"grpcss-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="http", tls_cert=cert, tls_key=key)
    add_regex_filter(api, service_id, FORBIDDEN)
    start_and_settle(api, service_id)

    with channel(server.port, cert) as chan:
        answers = server_stream(chan, b"x")
    assert [a for a in answers] == [b"chunk 0 for x", b"chunk 1 for x", b"chunk 2 for x"]


@needs_grpc
def test_bidirectional_streaming_is_not_deadlocked(api, service, grpc_stand_in,
                                                   certificate):
    """The exchange that a proxy holding the head deadlocks.

    Each side waits for the other: the client will not send its second message until the
    first is answered, and the service answers as each one arrives. A proxy that would not
    forward the head until it had seen a body would be waiting for something that was
    waiting for it — which is exactly the bug HTTP/3 had, and the reason the head is held
    only until the framing is known and never longer.
    """
    cert, key = certificate()
    server = grpc_stand_in(cert, key)
    service_id = service(f"grpcbd-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="http", tls_cert=cert, tls_key=key)
    add_regex_filter(api, service_id, FORBIDDEN)
    start_and_settle(api, service_id)

    with channel(server.port, cert) as chan:
        answers = bidi(chan, [b"one", b"two", b"three"])
    assert answers == [b"re: one", b"re: two", b"re: three"], \
        "a bidirectional stream did not complete through the proxy"


@needs_grpc
def test_a_trailers_only_status_arrives_as_one(api, service, grpc_stand_in, certificate):
    """HEADERS with the status and the end of the stream on them, and no DATA at all.

    The shape HTTP/2 can get wrong where HTTP/3 could not: the end of a message rides on
    its last frame, so a head that is the whole message has to be *sent* as the whole
    message. Forwarding it open and closing it with an empty DATA frame turns a
    trailers-only answer into one with a body, and a gRPC client refuses that — the status
    arrives as an unknown protocol error instead of the one the service sent.
    """
    import grpc
    cert, key = certificate()
    server = grpc_stand_in(cert, key)
    service_id = service(f"grpcto-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="http", tls_cert=cert, tls_key=key)
    add_regex_filter(api, service_id, FORBIDDEN)
    start_and_settle(api, service_id)

    with channel(server.port, cert) as chan:
        error = _grpc_error(call, chan, TRAILERS_ONLY, b"hello")
    assert error is not None, "a refusal from the service reached the client as a success"
    assert error.code() == grpc.StatusCode.PERMISSION_DENIED, \
        (f"the service's own status did not survive the proxy: got {error.code()} "
         f"({error.details()!r})")


@needs_grpc
def test_cleartext_grpc_is_filtered_too(api, service, grpc_stand_in):
    """gRPC without TLS, which is how most of it is actually deployed.

    A prior-knowledge HTTP/2 client opens with a fixed 24-byte preface and never
    negotiates, so there is no ALPN to read: the engine recognises the preface instead,
    on a plain `tcp` service with no certificate anywhere.
    """
    server = grpc_stand_in()
    service_id = service(f"grpch2c-{server.port}", "127.0.0.1", server.port, "proxy")
    add_regex_filter(api, service_id, FORBIDDEN)
    start_and_settle(api, service_id)

    with channel(server.port) as chan:
        assert call(chan, UNARY, b"hello") == b"you sent hello"
    with channel(server.port) as chan:
        assert _grpc_error(call, chan, FORBIDDEN, b"hello") is not None, \
            "cleartext HTTP/2 went past the filters unread"


@needs_grpc
def test_a_python_filter_sees_the_request(api, service, grpc_stand_in, certificate):
    """And the models are built, not only the patterns matched.

    A filter asking for an `HttpRequest` used to be handed the connection preface — parsed
    as one fictitious request — and then frames it could not read, so it was never called
    again and nothing said so. Here it is called, on every stream.
    """
    cert, key = certificate()
    server = grpc_stand_in(cert, key)
    service_id = service(f"grpcpy-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="http", tls_cert=cert, tls_key=key)
    add_python_filter(api, service_id, filter_code.HTTP)
    start_and_settle(api, service_id)

    with channel(server.port, cert) as chan:
        assert call(chan, UNARY, b"hello") == b"you sent hello"
    with channel(server.port, cert) as chan:
        assert _grpc_error(call, chan, "/files/../secret", b"hello") is not None, \
            "a Python filter asking for an HttpRequest was never called"


@needs_grpc
def test_a_filter_reads_the_messages_and_not_the_framing(api, service, grpc_stand_in,
                                                         certificate):
    """The gRPC body is length-prefixed, and a filter should not have to know that.

    Before `GrpcMessage`, a filter reading `request.body` read a five-byte header glued
    to a protobuf blob: a pattern written against the payload had to skip it, and one
    written against the whole body could match across the boundary between two messages
    — which is a false positive nobody would find.
    """
    cert, key = certificate()
    server = grpc_stand_in(cert, key)
    service_id = service(f"grpcmsg-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="http", tls_cert=cert, tls_key=key)
    add_python_filter(api, service_id, filter_code.GRPC, name="grpc")
    start_and_settle(api, service_id)

    with channel(server.port, cert) as chan:
        assert call(chan, UNARY, b"harmless") == b"you sent harmless"
    with channel(server.port, cert) as chan:
        assert _grpc_error(call, chan, UNARY, b"NOT-THIS-ONE") is not None, \
            "a gRPC message the filter refused reached the service"


@needs_grpc
def test_a_streaming_call_is_filtered_message_by_message(api, service, grpc_stand_in,
                                                         certificate):
    """And on a stream, where the body never ends until the call does.

    The needle is in the *third* message of a bidirectional exchange. A model that waited
    for the body to finish would see it after the call was over, which is a log entry and
    not a block; the first two messages have to go through and the third has to be
    refused while the stream is still open.
    """
    cert, key = certificate()
    server = grpc_stand_in(cert, key)
    service_id = service(f"grpcstr-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="http", tls_cert=cert, tls_key=key)
    add_python_filter(api, service_id, filter_code.GRPC, name="grpc")
    start_and_settle(api, service_id)

    with channel(server.port, cert) as chan:
        assert bidi(chan, [b"one", b"two"]) == [b"re: one", b"re: two"], \
            "an innocent bidirectional stream was disturbed"

    with channel(server.port, cert) as chan:
        import grpc
        try:
            answers = bidi(chan, [b"one", b"two", b"NOT-THIS-ONE"])
        except grpc.RpcError:
            answers = None
    assert answers != [b"re: one", b"re: two", b"re: NOT-THIS-ONE"], \
        "the needle in the third message of a stream was never refused"
