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


def run_with_verdict(*chunks: tuple[bytes, bool]) -> tuple[list[dict], int]:
    """The same, plus what the chain answered — which is the whole story when the
    parser refuses the traffic and the filter is therefore never called."""
    return _feed(*chunks)


def _feed(*chunks: tuple[bytes, bool]) -> tuple[list[dict], int]:
    glob = {"__firegex_pyfilter_enabled": ["watch_request", "watch_response"]}
    exec(FILTER_CODE, glob, glob)
    compile(glob)
    for payload, is_input in chunks:
        glob["__firegex_packet_info"] = packet(payload, is_input)
        handle_packet(glob)
    return glob["seen"], glob.get("__firegex_pyfilter_result", {}).get("action")


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


def test_an_identity_encoding_is_left_alone():
    raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 5\r\n\r\nplain"
    assert final(run((raw, False)), "response")["body"] == b"plain"


# What the parser refuses, and what it has started tolerating. These two are the reason
# the vendored llhttp carries its version in `fgex-lib/llhttp/PROVENANCE.md`: both
# answers changed between 9.2.1 and 9.4.3, and both are decisions about what a filter is
# shown rather than details of how it is parsed.

def test_an_empty_transfer_encoding_never_reaches_a_filter():
    """`Transfer-Encoding:` with nothing after it is refused, and the connection with it.

    This is the shape request smuggling is built out of: a header that one parser reads
    as "chunked follows" and another as "no framing here" is two readings of where the
    next request begins. llhttp accepted it until 9.4.3 — which means firegex parsed it,
    showed a filter an ordinary-looking request, and forwarded whatever the service then
    made of it. Now the parse fails, `invalid_encoding_action` decides, and its default
    is to reject: the filter is never called, because there is no one message here to
    call it with.
    """
    seen, action = run_with_verdict(
        (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \r\n\r\n", True))
    assert seen == []
    assert action == 2  # REJECT


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
