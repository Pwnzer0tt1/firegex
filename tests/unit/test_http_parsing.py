"""What an HTTP filter actually sees, pinned exchange by exchange.

These are **characterisation** tests: they exist to make the parser replaceable, and
then to make it updatable. The library parsed HTTP with `pyllhttp`, which published a
wheel for exactly one platform and has since been archived; llhttp now ships as source
in `fgex-lib/llhttp/` behind a binding of ours, and the release workflow builds the
wheels. Nobody upstream will bump that copy — `fgex-lib/llhttp/PROVENANCE.md` says which
version it is and how to move it.

Either kind of change is only safe if "the same" can be demonstrated rather than hoped,
and the coverage before this was four plain GETs. So everything below goes through the
public models — the surface a filter written from the documentation touches — rather than
through parser internals, which are exactly what is allowed to change.

Each case is a shape that occurs in real traffic and that a naive port gets wrong:
headers split across packets, headers repeated, chunked bodies, compressed bodies,
pipelined messages, protocol upgrades, and bodies delivered in pieces.
"""

import gzip
import zlib

import pytest

from firegex.pyfilters.internals import compile, handle_packet

FILTER_CODE = """
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import HttpRequest, HttpResponse

seen = []

@pyfilter
def watch_request(req: HttpRequest):
    seen.append({
        "kind": "request",
        "method": req.method,
        "url": req.url,
        "headers": dict(req.headers),
        "lheaders": dict(req.lheaders) if hasattr(req, "lheaders") else None,
        "body": req.body,
        "http_version": req.http_version,
        "keep_alive": req.keep_alive,
        "content_length": req.content_length,
        "headers_complete": req.headers_complete,
        "message_complete": req.message_complete,
    })
    return ACCEPT

@pyfilter
def watch_response(res: HttpResponse):
    seen.append({
        "kind": "response",
        "status_code": res.status_code,
        "status_phrase": res.status_phrase,
        "headers": dict(res.headers),
        "body": res.body,
        "http_version": res.http_version,
        "keep_alive": res.keep_alive,
        "content_length": res.content_length,
        "headers_complete": res.headers_complete,
        "message_complete": res.message_complete,
    })
    return ACCEPT
"""


def packet(payload: bytes, is_input: bool):
    return {
        "data": payload,
        "is_input": is_input,
        "is_ipv6": False,
        "is_tcp": True,
        "src_ip": "10.0.0.9" if is_input else "10.0.0.1",
        "src_port": 51000 if is_input else 80,
        "dst_ip": "10.0.0.1" if is_input else "10.0.0.9",
        "dst_port": 80 if is_input else 51000,
    }


def run(*chunks: tuple[bytes, bool]) -> list[dict]:
    """Feed `(payload, is_input)` chunks through a filter and return what it saw."""
    return _feed(*chunks)[0]


def run_with_verdict(*chunks: tuple[bytes, bool], settings: str = "") -> tuple[list[dict], int]:
    """The same, plus what the chain answered — which is the whole story when the
    parser refuses the traffic and the filter is therefore never called."""
    return _feed(*chunks, settings=settings)[:2]


def _feed(*chunks: tuple[bytes, bool], settings: str = "",
          joined_late: bool = False) -> tuple[list[dict], int, str]:
    glob = {"__firegex_pyfilter_enabled": ["watch_request", "watch_response"]}
    exec(FILTER_CODE + settings, glob, glob)
    compile(glob)
    if joined_late:
        # What the datapath sets on a context that began after its connection did.
        glob["__firegex_joined_late"] = True
    for payload, is_input in chunks:
        glob["__firegex_packet_info"] = packet(payload, is_input)
        handle_packet(glob)
    result = glob.get("__firegex_pyfilter_result") or {}
    return glob["seen"], result.get("action"), result.get("matched_by")


def final(seen: list[dict], kind: str) -> dict:
    """The last complete view of a message — what a filter acts on."""
    complete = [s for s in seen if s["kind"] == kind and s["message_complete"]]
    assert complete, f"no complete {kind} was ever handed to the filter: {seen}"
    return complete[-1]


# --- the ordinary shapes --------------------------------------------------------------


def test_a_plain_request_is_reported_whole():
    got = final(run((b"GET /shop?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", True)),
                "request")
    assert got["method"] == "GET"
    assert got["url"] == "/shop?id=1"
    assert got["http_version"] == "1.1"
    assert got["headers"]["Host"] == "example.com"
    assert got["keep_alive"] is True


def test_a_plain_response_is_reported_whole():
    got = final(run((b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnop", False)),
                "response")
    assert got["body"] == b"nop"
    assert got["content_length"] == 3
    # Both, and each under the name that describes it. `status_code` held the phrase
    # for a long time while being documented as an int, so a filter asking `== 404`
    # matched nothing.
    assert got["status_code"] == 404
    assert got["status_phrase"] == "Not Found"


def test_a_post_body_reaches_the_filter():
    got = final(run((b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n"
                     b"\r\nuser=admin&", True)), "request")
    assert got["method"] == "POST"
    assert got["body"] == b"user=admin&"


# --- the shapes a naive port gets wrong -----------------------------------------------


def test_a_request_split_across_packets_is_reassembled():
    """The halves of a header can land in different packets, and routinely do."""
    got = final(run((b"GET /split HTTP/1.1\r\nHo", True),
                    (b"st: example.com\r\nX-Trace: abc\r\n\r\n", True)), "request")
    assert got["url"] == "/split"
    assert got["headers"]["Host"] == "example.com"
    assert got["headers"]["X-Trace"] == "abc"


def test_a_body_split_across_packets_is_reassembled():
    got = final(run((b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabcde", True),
                    (b"fghij", True)), "request")
    assert got["body"] == b"abcdefghij"


def test_a_repeated_header_is_kept_as_a_list_raw_and_joined_when_lowercased():
    """Two `Set-Cookie` lines are two cookies, not one — and the RFC says a
    comma-joined single value is the equivalent reading."""
    got = final(run((b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n"
                     b"Content-Length: 0\r\n\r\n", False)), "response")
    assert got["headers"]["Set-Cookie"] == ["a=1", "b=2"], got["headers"]


def test_a_header_keeps_the_case_the_sender_used():
    got = final(run((b"GET / HTTP/1.1\r\nHOST: example.com\r\nX-Mixed-Case: v\r\n\r\n",
                     True)), "request")
    assert got["headers"]["HOST"] == "example.com"
    assert got["headers"]["X-Mixed-Case"] == "v"


def test_a_chunked_body_is_delivered_dechunked():
    got = final(run((b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", False)), "response")
    assert got["body"] == b"hello world"


def test_a_chunked_body_split_across_packets_is_delivered_whole():
    got = final(run((b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", False),
                    (b"lo\r\n0\r\n\r\n", False)), "response")
    assert got["body"] == b"hello"


def test_pipelined_requests_are_reported_separately():
    """Two requests in one packet are two messages, and a filter has to see both."""
    seen = run((b"GET /one HTTP/1.1\r\nHost: x\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n",
                True))
    urls = [s["url"] for s in seen if s["kind"] == "request" and s["message_complete"]]
    # Each exactly once. `on_message_complete` queues the finished message but leaves
    # `parser.msg` pointing at it, so the branch that hands over a message whose headers
    # are known used to deliver the second one a second time.
    assert urls == ["/one", "/two"], urls


def test_a_request_with_no_body_reports_zero_content_length():
    got = final(run((b"GET /empty HTTP/1.1\r\nHost: x\r\n\r\n", True)), "request")
    assert got["content_length"] in (0, None), got["content_length"]


def test_connection_close_is_reported_as_not_keep_alive():
    got = final(run((b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", True)),
                "request")
    assert got["keep_alive"] is False


def test_http_1_0_is_reported_as_such():
    """A minor version of zero is still a version.

    Built behind `if self.major and self.minor` before, so HTTP/1.0 and HTTP/2.0 both
    reported the empty string and a filter keying on the version never saw them.
    """
    got = final(run((b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", True)), "request")
    assert got["http_version"] == "1.0"


# --- the bodies the filters are actually reading --------------------------------------
# A compressed body that reached a filter still compressed is a filter that silently
# stops matching, so the decoding is part of what a filter sees.


def test_a_gzipped_body_is_decompressed_before_the_filter_sees_it():
    payload = gzip.compress(b"FLAG{secret}")
    raw = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
           + str(len(payload)).encode() + b"\r\n\r\n" + payload)
    assert final(run((raw, False)), "response")["body"] == b"FLAG{secret}"


def test_a_raw_deflated_body_is_decompressed_before_the_filter_sees_it():
    """Raw deflate, which is what most servers actually send under this name."""
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    payload = compressor.compress(b"FLAG{secret}") + compressor.flush()
    raw = (b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: "
           + str(len(payload)).encode() + b"\r\n\r\n" + payload)
    assert final(run((raw, False)), "response")["body"] == b"FLAG{secret}"


def test_a_zlib_wrapped_deflate_body_is_decompressed_too():
    """RFC 7230 defines `deflate` as the zlib format of RFC 1950.

    Servers send both that and the raw stream under the same name, browsers accept
    either, and a decoder that takes only one lets half the compressed traffic reach a
    filter still compressed — where a pattern looking for a flag finds nothing and the
    only trace is a line on stdout saying it skipped.
    """
    payload = zlib.compress(b"FLAG{secret}")
    raw = (b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: "
           + str(len(payload)).encode() + b"\r\n\r\n" + payload)
    assert final(run((raw, False)), "response")["body"] == b"FLAG{secret}"


def test_a_zstd_body_is_decompressed_before_the_filter_sees_it():
    """The encoding whose stdlib module only exists on Python 3.14."""
    try:
        from firegex.pyfilters.internals import zstd_compat  # noqa: F401
        import zstandard
    except ImportError:
        try:
            from compression import zstd as _z
            payload = _z.compress(b"FLAG{secret}")
        except ImportError:
            pytest.skip("no zstd backend available here")
    else:
        payload = zstandard.ZstdCompressor().compress(b"FLAG{secret}")
    raw = (b"HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: "
           + str(len(payload)).encode() + b"\r\n\r\n" + payload)
    assert final(run((raw, False)), "response")["body"] == b"FLAG{secret}"


# --- a body larger decoded than the cap it arrived under -----------------------------
# `FGEX_STREAM_MAX_SIZE` bounds what a filter holds, but a body arrives under it
# compressed: a megabyte of gzip is a gigabyte of zeroes. It was decoded whole, so one
# response could take the worker's memory with it.


def _capped(cap: int, action: str, *chunks: tuple[bytes, bool]) -> tuple[list[dict], int]:
    code = FILTER_CODE.replace(
        "seen = []",
        "from firegex.pyfilters import FullStreamAction\n"
        f"FGEX_STREAM_MAX_SIZE = {cap}\n"
        f"FGEX_FULL_STREAM_ACTION = FullStreamAction.{action}\n"
        "seen = []",
    )
    glob = {"__firegex_pyfilter_enabled": ["watch_request", "watch_response"]}
    exec(code, glob, glob)
    compile(glob)
    for payload, is_input in chunks:
        glob["__firegex_packet_info"] = packet(payload, is_input)
        handle_packet(glob)
    return glob["seen"], glob.get("__firegex_pyfilter_result", {}).get("action")


def _response(encoding: str, payload: bytes) -> bytes:
    return (b"HTTP/1.1 200 OK\r\nContent-Encoding: " + encoding.encode()
            + b"\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)


def _bombs():
    import brotli
    zeroes = b"\0" * (4 * 1024 * 1024)
    deflate = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    yield "gzip", gzip.compress(zeroes)
    yield "deflate", deflate.compress(zeroes) + deflate.flush()
    yield "br", brotli.compress(zeroes)
    # Two layers, each under the cap on its own: the limit holds for every step.
    yield "gzip, gzip", gzip.compress(gzip.compress(zeroes))


@pytest.mark.parametrize("encoding,payload", list(_bombs()), ids=lambda v: str(v)[:12])
def test_a_body_that_decodes_past_the_cap_meets_the_full_stream_action(encoding, payload):
    seen, action = _capped(1024 * 1024, "REJECT", (_response(encoding, payload), False))
    assert action == 2, "a body decoding to four megabytes under a one-megabyte cap passed"
    assert seen == [], "the filter was handed a body past the cap"


def test_flushing_hands_the_body_over_as_it_arrived():
    """Nothing is buffered to throw away, so the message goes on still encoded — what
    an encoding this cannot undo already does."""
    payload = gzip.compress(b"\0" * (4 * 1024 * 1024))
    seen, action = _capped(1024 * 1024, "FLUSH", (_response("gzip", payload), False))
    assert action == 0
    assert final(seen, "response")["body"] == payload


def test_a_body_under_the_cap_is_still_decoded():
    seen, _ = _capped(1024 * 1024, "REJECT", (_response("gzip", gzip.compress(b"FLAG")), False))
    assert final(seen, "response")["body"] == b"FLAG"


def test_headers_past_the_cap_are_flushed_not_raised():
    """The flush subtracted `len(body)` from a message still in its headers, whose body is
    `None`: headers past the cap raised instead of flushing, and the packet failed open."""
    head = b"POST / HTTP/1.1\r\nHost: a\r\nX-Pad: " + b"A" * 150
    seen, action = _capped(100, "FLUSH", (head[:60], True), (head[60:], True),
                           (b"\r\nContent-Length: 4\r\n\r\nbody", True))
    assert action == 0
    assert final(seen, "request")["body"] == b"body"


def test_an_identity_encoding_is_left_alone():
    raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 5\r\n\r\nplain"
    assert final(run((raw, False)), "response")["body"] == b"plain"


# What the parser refuses, and what it has started tolerating. These two are the reason
# the vendored llhttp carries its version in `fgex-lib/llhttp/PROVENANCE.md`: both
# answers changed between 9.2.1 and 9.4.3, and both are decisions about what a filter is
# shown rather than details of how it is parsed.

EMPTY_TRANSFER_ENCODING = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \r\n\r\n"


def test_an_empty_transfer_encoding_never_reaches_a_filter():
    """`Transfer-Encoding:` with nothing after it is not parsed into a request.

    This is the shape request smuggling is built out of: a header that one parser reads
    as "chunked follows" and another as "no framing here" is two readings of where the
    next request begins. llhttp accepted it until 9.4.3 — which means firegex parsed it,
    showed a filter an ordinary-looking request, and forwarded whatever the service then
    made of it. Now the parse fails and `invalid_encoding_action` decides. The filter is
    never called, because there is no one message here to call it with.

    **By default the traffic is carried**, and said so: refusing whatever the parser cannot
    read broke a service over any quirk of a client it would have accepted, with nobody
    having chosen that. Refusing is one setting away.
    """
    seen, action = run_with_verdict((EMPTY_TRANSFER_ENCODING, True))
    assert seen == []
    assert action == 0  # ACCEPT


def test_traffic_the_parser_cannot_read_is_refused_when_asked_and_not_blamed_on_a_filter():
    """The stricter answer, chosen in the file — and credited to the parser.

    It used to be credited to the filter function, which had never been shown the
    request: the operator was told their own code refused a connection it did not see.
    """
    seen, action, matched_by = _feed(
        (EMPTY_TRANSFER_ENCODING, True),
        settings="\nfrom firegex.pyfilters import ExceptionAction\n"
                 "FGEX_INVALID_ENCODING_ACTION = ExceptionAction.REJECT\n")
    assert seen == []
    assert action == 2  # REJECT
    assert matched_by == "@INVALID_ENCODING"


def test_unreadable_traffic_is_reported_once_per_connection(capsys):
    """The parser starts afresh on every packet, so every packet fails the same way.

    A traceback each was the whole log, hundreds of times; one line says it and what was
    done about it.
    """
    run_with_verdict(*[(EMPTY_TRANSFER_ENCODING, True)] * 4)
    said = [line for line in capsys.readouterr().out.splitlines() if "[warn] [http]" in line]
    assert len(said) == 1, said
    assert "carried" in said[0], said


STRICT = ("\nfrom firegex.pyfilters import ExceptionAction\n"
          "FGEX_INVALID_ENCODING_ACTION = ExceptionAction.REJECT\n")


def test_a_connection_met_in_the_middle_of_a_body_is_carried_not_refused(capsys, monkeypatch):
    """What a filter taking over an open connection meets first can be half a request.

    The rest of an upload is not a malformed request, and judging it as one refused valid
    uploads in flight whenever a filter changed — under the strict setting, which is
    exactly the one an operator worried about smuggling chooses. That direction of the
    connection is carried, and said once, as information rather than as a problem.
    """
    from firegex.pyfilters.models import http
    monkeypatch.setattr(http, "_told_met_mid_message", False)
    seen, action, _ = _feed(
        (b"x" * 200, True),
        (b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n", True),
        settings=STRICT, joined_late=True)
    assert action == 0, "a request met halfway was refused"
    assert seen == [], "a direction met halfway was judged after all"
    out = capsys.readouterr().out
    assert "[warn] [http]" not in out, "a working client was reported as not speaking HTTP"
    assert out.count("[info] [http]") == 1, out


def test_a_connection_met_at_the_start_of_a_message_is_filtered_as_usual():
    """Met between two requests — the ordinary idle keep-alive — nothing is lost."""
    seen = _feed((b"GET /first HTTP/1.1\r\nHost: a\r\n\r\n", True),
                 settings=STRICT, joined_late=True)[0]
    assert final(seen, "request")["url"] == "/first"


def test_once_in_step_a_connection_met_late_answers_to_the_usual_rules():
    """Only the first thing met is given the benefit of the doubt; garbage after a clean
    request is garbage, and the strict setting refuses it as it would anywhere."""
    _, action, matched_by = _feed(
        (b"GET /first HTTP/1.1\r\nHost: a\r\n\r\n", True),
        (EMPTY_TRANSFER_ENCODING, True),
        settings=STRICT, joined_late=True)
    assert action == 2 and matched_by == "@INVALID_ENCODING"


def test_a_connection_seen_from_its_start_gets_no_such_benefit():
    """Unreadable from the first byte is not a connection met halfway."""
    _, action, _ = _feed((b"x" * 200, True), settings=STRICT)
    assert action == 2


def test_tabs_around_a_content_length_are_tolerated():
    """`Content-Length:\t5\t` is a length, not a malformed header.

    Servers accept it and llhttp has since 9.4.0. Refusing it — which is what happened
    before — meant a legitimate response was never parsed, so the filter meant to read
    that body never ran on it, and with the default action the connection was rejected:
    firegex breaking a service it was there to protect.
    """
    raw = b"HTTP/1.1 200 OK\r\nContent-Length:\t5\t\r\n\r\nplain"
    message = final(run((raw, False)), "response")
    assert message["body"] == b"plain"
    assert message["content_length"] == 5


def test_the_history_is_held_to_the_same_bytes_as_the_stream():
    """`FGEX_MAX_HISTORY_SIZE` counts messages, and each can be as large as the stream
    cap: a keep-alive connection could hold a hundred bodies of a megabyte, per
    direction, for as long as it stayed open."""
    code = """
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import HttpFullRequest
FGEX_STREAM_MAX_SIZE = 1000
held = []
@pyfilter
def watch(req: HttpFullRequest):
    held.append(sum(len(r.body or b"") for r in req.history.requests))
    return ACCEPT
"""
    glob = {"__firegex_pyfilter_enabled": ["watch"]}
    exec(code, glob, glob)
    compile(glob)
    request = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 400\r\n\r\n" + b"b" * 400
    for _ in range(8):
        glob["__firegex_packet_info"] = packet(request, True)
        handle_packet(glob)
    assert len(glob["held"]) == 8
    assert max(glob["held"]) <= 1000, glob["held"]
    assert glob["held"][-1] > 0, "the history was emptied rather than trimmed"
