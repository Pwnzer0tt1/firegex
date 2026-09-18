"""A real gRPC service for firegex to protect, and a client that calls it through firegex.

gRPC is the reason HTTP/2 had to be rendered rather than carried. It puts the method name
in `:path` and its status in a trailer section, both of which are HPACK on the wire, so a
firegex that only forwarded HTTP/2 saw a compression format: no pattern matched a method
name, and a filter asking for an `HttpRequest` was handed the connection preface and then
frames it could not parse, so it was never called. Nothing said so.

Deliberately the real library rather than frames assembled by hand. What is being checked
is that firegex does not disturb gRPC while filtering it, and a hand-rolled client that
agreed with our own idea of the protocol would prove nothing about the one an operator
will actually put behind it.

No `.proto` and no codegen: the handlers use identity serializers, so a "message" is
whatever bytes the test sends. gRPC's own framing — the five-byte length prefix, the
trailer section, the status — is real, and that is the part under test.
"""

import threading
from concurrent import futures

import pytest

try:
    import grpc
    HAVE_GRPC = True
except ImportError:  # pragma: no cover - depends on what is installed
    HAVE_GRPC = False


needs_grpc = pytest.mark.skipif(
    not HAVE_GRPC,
    reason="grpcio is not installed, so nothing here can speak gRPC",
)

#: The method a rule is written against. A path on the wire, HPACK-compressed — which is
#: the whole point: a pattern matching it is a pattern matching something no unrendered
#: HTTP/2 proxy could show a filter.
FORBIDDEN = "/fgex.Echo/Forbidden"
UNARY = "/fgex.Echo/Unary"
SERVER_STREAM = "/fgex.Echo/ServerStream"
BIDI = "/fgex.Echo/Bidi"
TRAILERS_ONLY = "/fgex.Echo/TrailersOnly"

#: What the service answers on one method and nowhere else, so that a test of the
#: *answer* uses bytes appearing nowhere in the request.
SECRET = b"here is FLAG{only-in-the-answer}"


def _identity(x):
    return x


class _Handler(grpc.GenericRpcHandler):
    """Every method of the stand-in, dispatched by path.

    A generic handler rather than generated stubs: without a `.proto` there is nothing to
    generate, and gRPC's wire behaviour — which is what firegex touches — is the same
    either way.
    """

    def service(self, handler_call_details):
        method = handler_call_details.method

        if method == SERVER_STREAM or method == BIDI or method == TRAILERS_ONLY:
            pass
        else:
            # Anything else is echoed, including paths that are not gRPC method names at
            # all. That is what lets the *same* filter file the HTTP/1.1 and HTTP/3 tests
            # use be aimed at the same URL here: an unknown method would be answered
            # UNIMPLEMENTED by the service, which is a refusal from the wrong end and
            # indistinguishable from the one under test.
            method = UNARY

        if method in (UNARY, FORBIDDEN):
            def unary(request, context):
                return SECRET if b"secret" in request else b"you sent " + request
            return grpc.unary_unary_rpc_method_handler(
                unary, request_deserializer=_identity, response_serializer=_identity)

        if method == SERVER_STREAM:
            def stream(request, context):
                for n in range(3):
                    yield b"chunk %d for %s" % (n, request)
            return grpc.unary_stream_rpc_method_handler(
                stream, request_deserializer=_identity, response_serializer=_identity)

        if method == BIDI:
            def bidi(requests, context):
                # Answers each message as it arrives rather than after the last one,
                # which is what makes this a test of the head not being held: a proxy
                # waiting for the client to finish would deadlock against a client
                # waiting to be answered.
                for request in requests:
                    yield b"re: " + request
            return grpc.stream_stream_rpc_method_handler(
                bidi, request_deserializer=_identity, response_serializer=_identity)

        if method == TRAILERS_ONLY:
            def refuse(request, context):
                # Aborting before anything is sent produces HEADERS with the status and
                # END_STREAM, and no DATA at all — a *trailers-only* response. Carrying
                # it means sending the head with the end of the stream on it; closing it
                # with an empty DATA frame instead turns it into a message with a body,
                # which gRPC refuses.
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "not for you")
            return grpc.unary_unary_rpc_method_handler(
                refuse, request_deserializer=_identity, response_serializer=_identity)

        return None


class GrpcService:
    """The stand-in, listening in the clear or behind TLS."""

    def __init__(self, port: int, cert: str | None = None, key: str | None = None):
        self.port = port
        self.cert = cert
        self.key = key
        self._server = None

    def start(self):
        self._server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
        self._server.add_generic_rpc_handlers((_Handler(),))
        target = f"127.0.0.1:{self.port}"
        if self.cert:
            credentials = grpc.ssl_server_credentials(
                [(self.key.encode(), self.cert.encode())])
            self._server.add_secure_port(target, credentials)
        else:
            self._server.add_insecure_port(target)
        self._server.start()

    def stop(self):
        if self._server is not None:
            self._server.stop(0)
            self._server = None


def channel(port: int, cert: str | None = None):
    """A channel to a service reached *through* firegex, at the address the world dials."""
    target = f"127.0.0.1:{port}"
    if cert is None:
        return grpc.insecure_channel(target)
    credentials = grpc.ssl_channel_credentials(root_certificates=cert.encode())
    # No `ssl_target_name_override`. The suite's certificates name the address the test
    # actually dials — an IP SAN — so overriding the name to `localhost` made every TLS
    # call fail hostname verification before a byte of it reached firegex, which read
    # here as "the proxy broke gRPC". gRPC checks an IP SAN against an IP target happily;
    # there is nothing to override.
    return grpc.secure_channel(target, credentials)


def call(chan, method: str, payload: bytes, timeout: float = 10.0) -> bytes:
    """One unary call, returning the answer."""
    stub = chan.unary_unary(method, request_serializer=_identity,
                            response_deserializer=_identity)
    return stub(payload, timeout=timeout)


def server_stream(chan, payload: bytes, timeout: float = 10.0) -> list:
    stub = chan.unary_stream(SERVER_STREAM, request_serializer=_identity,
                             response_deserializer=_identity)
    return list(stub(payload, timeout=timeout))


def bidi(chan, payloads: list, timeout: float = 10.0) -> list:
    """A bidirectional stream, answered message by message.

    The generator hands over one message and then *waits*, which is what makes this the
    exchange a proxy holding the head deadlocks: the client will not send the second
    message until the first is answered.
    """
    stub = chan.stream_stream(BIDI, request_serializer=_identity,
                              response_deserializer=_identity)
    answers = []
    ready = threading.Event()

    def outgoing():
        for payload in payloads:
            yield payload
            # Wait to be answered before sending the next one.
            ready.wait(timeout)
            ready.clear()

    for answer in stub(outgoing(), timeout=timeout):
        answers.append(answer)
        ready.set()
        if len(answers) == len(payloads):
            break
    return answers
