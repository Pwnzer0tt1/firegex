"""What a gRPC filter sees, message by message.

gRPC is HTTP/2 and HTTP/2 is rendered to the chain as HTTP/1.1, so everything about the
exchange — the method in the path, the headers, the `grpc-status` in the trailer section
— already arrives through `HttpRequest` and `HttpResponse`. What did not arrive was the
*body*: a gRPC body is a sequence of length-prefixed messages, so a filter reading
`request.body` read a five-byte header glued to a protobuf blob and a pattern written
against the payload had to know to skip it.

These go through the public model, as the HTTP parsing tests do and for the same reason:
what is being pinned is what a filter written from the documentation is handed, not how
the parser arranges to hand it over.

The shape that matters most here is the **streaming** one. A server-streaming or
bidirectional RPC has a body that does not finish until the stream does, so a model shown
only finished bodies would be called once, at the end — too late to be a firewall. The
test for that is `test_each_message_arrives_as_it_completes`.
"""

from firegex.pyfilters.internals import compile, handle_packet

FILTER_CODE = """
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import GrpcMessage

seen = []

@pyfilter
def watch(message: GrpcMessage):
    seen.append({
        "payload": message.payload,
        "compressed": message.compressed,
        "is_request": message.is_request,
        "method": message.method,
        "grpc_status": message.grpc_status,
    })
    return ACCEPT
"""


def frame(payload: bytes, compressed: bool = False) -> bytes:
    """One gRPC message on the wire: a flag byte, a big-endian length, the bytes."""
    return bytes([1 if compressed else 0]) + len(payload).to_bytes(4, "big") + payload


def packet(payload: bytes, is_input: bool):
    return {
        "data": payload,
        "is_input": is_input,
        "is_ipv6": False,
        "is_tcp": True,
        "src_ip": "10.0.0.9" if is_input else "10.0.0.1",
        "src_port": 51000 if is_input else 443,
        "dst_ip": "10.0.0.1" if is_input else "10.0.0.9",
        "dst_port": 443 if is_input else 51000,
    }


def run(*chunks: tuple[bytes, bool]) -> list[dict]:
    glob = {"__firegex_pyfilter_enabled": ["watch"]}
    exec(FILTER_CODE, glob, glob)
    compile(glob)
    for payload, is_input in chunks:
        glob["__firegex_packet_info"] = packet(payload, is_input)
        handle_packet(glob)
    return glob["seen"]


def request_head(chunked: bool = True, length: int | None = None) -> bytes:
    """The head of a gRPC call, as the engine renders one out of HTTP/2."""
    framing = (b"transfer-encoding: chunked\r\n" if chunked
               else b"content-length: %d\r\n" % length)
    return (b"POST /fgex.Echo/Unary HTTP/1.1\r\nhost: x\r\n"
            b"content-type: application/grpc\r\nte: trailers\r\n" + framing + b"\r\n")


def chunk(data: bytes) -> bytes:
    return b"%x\r\n%s\r\n" % (len(data), data)


END = b"0\r\n\r\n"


def test_one_message_is_unwrapped():
    body = frame(b"hello")
    seen = run((request_head(chunked=False, length=len(body)) + body, True))
    assert [s["payload"] for s in seen] == [b"hello"]
    assert seen[0]["is_request"] is True
    assert seen[0]["method"] == "/fgex.Echo/Unary"
    assert seen[0]["compressed"] is False


def test_several_messages_in_one_body_are_several_calls():
    """A chunk carrying three messages is three calls, not one call holding a list."""
    body = frame(b"one") + frame(b"two") + frame(b"three")
    seen = run((request_head(chunked=False, length=len(body)) + body, True))
    assert [s["payload"] for s in seen] == [b"one", b"two", b"three"]


def test_each_message_arrives_as_it_completes():
    """The streaming case, and the reason the parser learned to release body chunks.

    The body of a bidirectional RPC does not finish until the stream does. A model shown
    only finished bodies would see these three messages once, at the end — which is not a
    firewall, it is a log. Each one has to arrive as it completes.
    """
    seen = run(
        (request_head() + chunk(frame(b"first")), True),
        (chunk(frame(b"second")), True),
        (chunk(frame(b"third")), True),
    )
    assert [s["payload"] for s in seen] == [b"first", b"second", b"third"], \
        "a streaming RPC was not shown to the filter until it ended"
    # And nothing is handed over twice, which is what the cursor on the message is for.
    assert len(seen) == 3


def test_a_message_split_across_packets_is_held_until_it_is_whole():
    """Half a message is not a message: a filter must never be shown a fragment.

    Deciding on half a payload is how a pattern is defeated by splitting it, which is the
    same reason the stream models exist at all.
    """
    body = frame(b"abcdefghij")
    seen = run(
        (request_head() + chunk(body[:7]), True),
        (chunk(body[7:]), True),
    )
    assert [s["payload"] for s in seen] == [b"abcdefghij"]


def test_a_length_that_has_not_arrived_yet_costs_nothing():
    """A header claiming far more than was sent waits, rather than being acted on."""
    claimed = bytes([0]) + (1 << 20).to_bytes(4, "big") + b"only a few bytes"
    seen = run((request_head() + chunk(claimed), True))
    assert seen == [], "a message was handed over before its bytes arrived"


def test_the_answer_is_unwrapped_too():
    body = frame(b"answering")
    seen = run(
        (request_head(chunked=False, length=5) + frame(b"ask"), True),
        (b"HTTP/1.1 200 OK\r\ncontent-type: application/grpc\r\n"
         b"content-length: %d\r\n\r\n" % len(body) + body, False),
    )
    answers = [s for s in seen if not s["is_request"]]
    assert [s["payload"] for s in answers] == [b"answering"]


def test_a_compressed_message_says_so_and_is_not_decoded():
    """The flag is reported; the bytes are left alone.

    What a message is compressed *with* is the peers' agreement (`grpc-encoding`), and
    guessing is how a filter comes to read something that is not there.
    """
    body = frame(b"\x1f\x8b-not-really-gzip", compressed=True)
    seen = run((request_head(chunked=False, length=len(body)) + body, True))
    assert seen[0]["compressed"] is True
    assert seen[0]["payload"] == b"\x1f\x8b-not-really-gzip"


def test_an_exchange_that_is_not_grpc_is_not_shown_at_all():
    """A filter asking for a gRPC message is not called on traffic that has none."""
    seen = run((b"POST /shop HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nhello", True))
    assert seen == []


def test_a_trailers_only_reply_carries_its_status():
    """HEADERS with `grpc-status` and no messages at all — a refusal from the service.

    There is no message to show, so the gRPC model is not called; the status is on the
    reply, which is `HttpResponse`'s to report. What this pins is that the absence is
    quiet rather than an error.
    """
    seen = run(
        (request_head(chunked=False, length=8) + frame(b"ask"), True),
        (b"HTTP/1.1 200 OK\r\ncontent-type: application/grpc\r\n"
         b"grpc-status: 7\r\ncontent-length: 0\r\n\r\n", False),
    )
    assert [s["payload"] for s in seen if not s["is_request"]] == []


# --- a stream that stays open --------------------------------------------------------
# A streaming RPC's body ends only when the stream does. Every frame in it had already
# been handed over, and the body went on holding all of them: under the default flush the
# buffer grew past every flush while the size it was counted by went negative.


def _parser_after(cap: int, *chunks: tuple[bytes, bool]):
    code = FILTER_CODE.replace(
        "seen = []",
        "from firegex.pyfilters import FullStreamAction\n"
        f"FGEX_STREAM_MAX_SIZE = {cap}\n"
        "FGEX_FULL_STREAM_ACTION = FullStreamAction.FLUSH\n"
        "seen = []",
    )
    glob = {"__firegex_pyfilter_enabled": ["watch"]}
    exec(code, glob, glob)
    compile(glob)
    for payload, is_input in chunks:
        glob["__firegex_packet_info"] = packet(payload, is_input)
        handle_packet(glob)
    from firegex.pyfilters.internals.data import DataStreamCtx
    return glob["seen"], DataStreamCtx(glob).data_handler_context["http_grpc_in"]


def test_a_long_stream_holds_only_what_it_has_not_framed():
    frames = [chunk(frame(b"x" * 295)) for _ in range(60)]
    seen, parser = _parser_after(1000, (request_head(), True),
                                 *[(f, True) for f in frames])
    assert len(seen) == 60
    assert len(parser.buffers._body_buffer) < 1000, "every frame handed over is still held"
    assert parser.msg.total_size >= 0


def test_a_frame_past_the_cap_is_skipped_and_the_next_one_still_found():
    big = frame(b"z" * 3000)
    pieces = [chunk(big[i:i + 400]) for i in range(0, len(big), 400)]
    seen, parser = _parser_after(1000, (request_head(), True),
                                 *[(p, True) for p in pieces],
                                 (chunk(frame(b"after")), True))
    assert [s["payload"] for s in seen] == [b"after"], \
        "the frame after the flushed one was read out of the middle of it"
    assert len(parser.buffers._body_buffer) < 1000
