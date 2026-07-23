# 🌐 Netfilter Proxy

Netfilter Proxy (`nfproxy`) is a filtering module that leverages [nfqueue](https://netfilter.org/projects/libnetfilter_queue/) to intercept network packets, then runs your own Python filter code against them inside the C++ core via an embedded interpreter. Unlike [Netfilter Regex](nfregex.md), which only matches raw byte patterns, nfproxy gives filters structured access to the traffic (parsed HTTP requests/responses, TCP streams, per-stream history, ...) and lets them make arbitrary decisions in Python.

## How to use it

1. Create a service: pick a protocol (`tcp` or `http`), the target `ip:port` (or attach it to a [TLS Decrypt](tls.md) stream, to see decrypted traffic), and a name.
2. Upload one or more Python filter files (see [writing a filter](#writing-a-filter) below). Each file can define multiple `@pyfilter` functions.
3. Start the service. From then on, every matching packet is routed through nfqueue to the embedded Python interpreter, which runs your filters and returns an action (accept/drop/reject/mangle) back to the C++ core.
4. The service page shows live counters (packets seen, blocked/mangled) and any Python exception raised by a filter, reported back over a unix socket — no restart needed to see them.

Filters can be edited and re-uploaded while the service is running: changes take effect on the next packet. `fail_open` (an advanced per-service option) controls what happens if the filter process itself crashes or can't be reached: enabled, traffic is allowed through unfiltered rather than blocked, trading protection for availability — useful if you'd rather risk letting an attack through than take the service down during a competition.

## Writing a filter

Install the library and CLI:

```bash
pip install -U firegex
```

`fgex` is an alias package for `firegex`: installing either one gives you the same `firegex` module and the `fgex`/`firegex` CLI commands.

### The `pyfilter` decorator

```python
from firegex.nfproxy import pyfilter
```

`pyfilter` marks a function as an active filter. A filter function:
- must be decorated with `@pyfilter`;
- must have every parameter type-annotated with one of the data structures listed below (parameters without a type annotation make the filter invalid, and default/keyword-argument values are ignored — the caller always builds the arguments itself from the live packet data);
- must `return` one of the [packet statements](#packet-statements) below (or `None`, which behaves like `ACCEPT`).

```python
from firegex.nfproxy import pyfilter, ACCEPT, REJECT

@pyfilter
def none_filter():  # A filter that does nothing
    return ACCEPT
```

Filter names (the function name) must be unique within a filter file.

Each TCP stream (i.e. each connection) gets its own isolated set of global variables: code at module level runs once per stream, and the same globals are reused across every packet of that stream. Don't store state in another module's globals — that memory is shared across every stream handled by the same thread and will cause data to leak/interfere between unrelated connections. Global variable names starting with `__firegex` are reserved for internal use.

```python
from firegex.nfproxy import pyfilter, ACCEPT, REJECT
from firegex.nfproxy.models import HttpRequest

@pyfilter
def filter_with_args(http_request: HttpRequest):
    if http_request.body and b"ILLEGAL" in http_request.body:
        return REJECT
```

Here the filter is only called once the data required to build an `HttpRequest` is available (i.e. once the HTTP headers have been parsed, and again once the body is complete). If a filter needs multiple parameters, it's only called once every parameter can be built from the data received so far.

### Packet statements

A filter must return one of these values (importable from `firegex.nfproxy`):

| Statement | Effect |
|---|---|
| `ACCEPT` | The packet is accepted and forwarded to the destination. This is also the default behavior if `None` is returned. |
| `REJECT` | The connection is closed and every packet in the stream is dropped. |
| `DROP` | This packet, and every subsequent packet in the stream, is silently dropped (unlike `REJECT`, this doesn't simulate a connection closure). |
| `UNSTABLE_MANGLE` | The packet is modified and forwarded. Only available when filtering `RawPacket` — see below. This is an unstable feature, use it carefully. |

### Data structures

These are the types you can use as filter parameter annotations. Some are only available when the service's protocol is `http` (marked **HTTP only**); the rest work for both `tcp` and `http` services.

#### `RawPacket`

```python
from firegex.nfproxy.models import RawPacket
```

The raw packet as received from nfqueue — the lowest level of abstraction, and the **only** data structure that can be mutated (for `UNSTABLE_MANGLE`).

- `data: bytes` — the packet's data, reassembled/reordered as a TCP stream (read-only).
- `is_input: bool` — `True` for an incoming packet, `False` for outgoing.
- `is_ipv6: bool` — `True` for IPv6, `False` for IPv4.
- `is_tcp: bool` — `True` for TCP, `False` for UDP.
- `l4_size: int` — size of the layer-4 payload (read-only).
- `raw_packet_header_len: int` — size of the original packet's header (read-only).
- `raw_packet: bytes` — the full packet, including the IP/TCP headers. Writable: assigning to it mangles the packet if the filter returns `UNSTABLE_MANGLE`, and updates `l4_size`/`l4_data` accordingly.
- `l4_data: bytes` — the layer-4 payload only, taken directly from the raw packet. Also writable for mangling; updates `l4_size`/`raw_packet` accordingly.

Be careful: `l4_data`/`raw_packet` reflect a single physical packet as seen by nfqueue, while `data` is the TCP stream already reassembled/reordered by the C++ core — they can legitimately differ (e.g. out-of-order packets are accepted by default without invoking Python at all).

#### `TCPInputStream` (alias `TCPClientStream`)

```python
from firegex.nfproxy.models import TCPInputStream
```

The assembled TCP stream in the input (client → server) direction. A filter using this type is only called for incoming packets.

- `data: bytes` — the entire input-direction stream assembled so far (read-only).
- `total_stream_size: int` — size of that stream (read-only).
- `is_ipv6: bool`

#### `TCPOutputStream` (alias `TCPServerStream`)

```python
from firegex.nfproxy.models import TCPOutputStream
```

Same as `TCPInputStream`, but for the output (server → client) direction; only called for outgoing packets.

#### `HttpRequest` — HTTP only

```python
from firegex.nfproxy.models import HttpRequest
```

The current HTTP request. This handler is called up to twice: once when the headers are complete, and again once the body is complete (if the whole request arrives in a single TCP packet, it's called only once).

- `method: bytes` — the request method.
- `url: str | None` — the request URL.
- `headers: dict[str, str]` — request headers, keys/values exactly as received (case-sensitive); a repeated header becomes a list of values.
- `get_header(header: str, default=None) -> str` — looks up a header case-insensitively; if the header was repeated, its values are joined with a comma (this method never returns a list).
- `user_agent: str`
- `content_encoding: str`
- `content_length: int | None`
- `body: bytes` — `None` until the body has arrived.
- `body_decoded` — the body decoded according to `content_encoding` (`gzip`, `br`, `deflate` and `zstd` are supported). `False` if decoding failed and `body` isn't `None`.
- `http_version: str`
- `keep_alive: bool`
- `should_upgrade: bool`
- `upgrading_to_h2: bool`
- `upgrading_to_ws: bool`
- `ws_stream: list[websockets.frames.Frame]` — decoded WebSocket frames (permessage-deflate supported); see the [websockets docs](https://websockets.readthedocs.io/en/stable/).
- `stream: bytes` — buffer of the raw WebSocket traffic in this direction; only meaningful once `should_upgrade` is `True`.
- `headers_complete: bool`
- `message_complete: bool`
- `total_size: int` — size of the whole request seen so far.
- `history: HttpHistory` — previously completed requests/responses on this same stream, see [`HttpHistory`](#httphistory-alias-httpstreamhistory--http-only) below.

#### `HttpRequestHeader` — HTTP only

```python
from firegex.nfproxy.models import HttpRequestHeader
```

Same fields as `HttpRequest`, but only called once, when the headers are complete — the body is never buffered and `body` is always `None`.

#### `HttpFullRequest` — HTTP only

```python
from firegex.nfproxy.models import HttpFullRequest
```

Same fields as `HttpRequest`, but only called once the whole request (headers + body) is complete. Completed instances of this type are also what gets stored in `HttpHistory.requests`.

#### `HttpResponse` — HTTP only

```python
from firegex.nfproxy.models import HttpResponse
```

The current HTTP response — same shape and calling convention as `HttpRequest` (up to twice: headers complete, then body complete), plus:

- `status_code: int`

All the other fields listed for `HttpRequest` (`headers`, `get_header`, `body`, `body_decoded`, `content_encoding`, `content_length`, `http_version`, `keep_alive`, `should_upgrade`, `upgrading_to_h2`, `upgrading_to_ws`, `ws_stream`, `stream`, `headers_complete`, `message_complete`, `total_size`, `history`, `user_agent`) apply here too.

#### `HttpResponseHeader` — HTTP only

```python
from firegex.nfproxy.models import HttpResponseHeader
```

Same as `HttpResponse`, but only called once the headers are complete; `body` is always `None`.

#### `HttpFullResponse` — HTTP only

```python
from firegex.nfproxy.models import HttpFullResponse
```

Same as `HttpResponse`, but only called once the whole response is complete. Completed instances of this type are what gets stored in `HttpHistory.responses`.

#### `HttpHistory` (alias `HttpStreamHistory`) — HTTP only

```python
from firegex.nfproxy.models import HttpHistory
```

Gives a filter access to previously *completed* requests/responses on the same TCP stream — useful for correlating a response with the request(s) that came before it on a keep-alive connection, or for stateful logic that spans more than one exchange.

- `requests: list[HttpFullRequest]` — a snapshot copy of the requests completed so far on this stream (does not include the request currently being processed).
- `responses: list[HttpFullResponse]` — a snapshot copy of the completed responses so far.

You can use it in two ways:

```python
from firegex.nfproxy import pyfilter, REJECT
from firegex.nfproxy.models import HttpHistory, HttpResponse

# 1. as its own filter parameter
@pyfilter
def check_history(hist: HttpHistory):
    if len(hist.requests) > 50:
        return REJECT

# 2. via the .history property available on any Http* instance
@pyfilter
def check_previous_requests(resp: HttpResponse):
    if any(b"admin" in req.url.encode() for req in resp.history.requests if req.url):
        return REJECT
```

The number of entries kept per stream is capped by the `FGEX_MAX_HISTORY_SIZE` global (default `100`) — see [Other global options](#other-global-options) below; once the cap is reached, the oldest entry is dropped as a new one is added.

## Stream limiter

What happens if a single TCP stream carries a lot of data? Past a configurable size, a "full stream" action kicks in. First import the enum:

```python
from firegex.nfproxy import FullStreamAction
```

Then set these in the filter file's globals:

- `FGEX_STREAM_MAX_SIZE: int` — maximum size (in bytes) of a stream before `FGEX_FULL_STREAM_ACTION` is triggered. This limit applies per data structure independently: e.g. if `TCPInputStream` has reached the limit but `HttpResponse` hasn't, the action only affects `TCPInputStream`. Default: 1MB.
- `FGEX_FULL_STREAM_ACTION: FullStreamAction` — the action taken once the limit is exceeded. Default: `FullStreamAction.FLUSH`.

`FullStreamAction` values:

| Value | Effect |
|---|---|
| `FLUSH` | Flush the stream and keep acquiring new packets (default). |
| `DROP` | Drop the next stream packets, like a `DROP` filter statement. |
| `REJECT` | Reject the stream and close the connection, like a `REJECT` filter statement. |
| `ACCEPT` | Stop calling pyfilters and accept the rest of the traffic as-is. |

## Other global options

```python
from firegex.nfproxy import ExceptionAction
```

- `FGEX_INVALID_ENCODING_ACTION: ExceptionAction` — action taken when parsing hits an invalid/unsupported encoding (a parser-level failure). Default: `ExceptionAction.REJECT`. Values: `ACCEPT` (accept the packet that caused the error), `DROP` (drop the connection), `REJECT` (reject the connection), `NOACTION` (do nothing — the error is signaled and the stream is accepted without calling any more pyfilters on it).
- `FGEX_MAX_HISTORY_SIZE: int` — max number of requests/responses kept per stream by [`HttpHistory`](#httphistory-alias-httpstreamhistory--http-only). Default: `100`.

## Testing a filter locally

You don't need a running Firegex instance to try out a filter: the `firegex` pip package ships a local proxy simulator.

```text
➤ fgex nfproxy -h

 Usage: fgex nfproxy [OPTIONS] FILTER_FILE ADDRESS PORT

 Run an nfproxy simulation

╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    filter_file      TEXT     The path to the filter file [default: None] [required]                                                               │
│ *    address          TEXT     The address of the target to proxy [default: None] [required]                                                        │
│ *    port             INTEGER  The port of the target to proxy [default: None] [required]                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --proto                 [tcp|http]  The protocol to proxy [default: tcp]                                                                            │
│ --from-address          TEXT        The address of the local server [default: None]                                                                 │
│ --from-port             INTEGER     The port of the local server [default: 7474]                                                                    │
│                 -6                  Use IPv6 for the connection                                                                                     │
│ --help          -h                  Show this message and exit.                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

This runs a local proxy in front of `ADDRESS:PORT`, applying `FILTER_FILE` to the traffic — no Docker, no nftables/root privileges required. The filter file is reloaded automatically whenever it changes on disk, so you don't need to restart the simulator while iterating.

```bash
fgex nfproxy test_http.py 127.0.0.1 8080 --proto http
```

## Full example

```python
# Example filter file for an http-protocol service

from firegex.nfproxy.models import RawPacket, HttpRequest, HttpHistory
from firegex.nfproxy import pyfilter, ACCEPT, REJECT, DROP, UNSTABLE_MANGLE, FullStreamAction

# Lowest level of abstraction: only RawPacket can be mangled.
@pyfilter
def mangle_example(packet: RawPacket):
    if b"TEST_MANGLING" in packet.l4_data:
        packet.l4_data = packet.l4_data.replace(b"TEST", b"UNSTABLE")
        return UNSTABLE_MANGLE
    if b"BAD DATA" in packet.data:
        return DROP
    return ACCEPT

# Higher level of abstraction: parsed HTTP requests.
@pyfilter
def http_filter(http: HttpRequest):
    if http.method == b"GET" and http.url and "test" in http.url:
        return REJECT

# Using history to see previous requests on the same keep-alive stream.
@pyfilter
def repeated_probe_filter(hist: HttpHistory):
    if len(hist.requests) > 20:
        return REJECT

# Stream size limits (applies per data structure, e.g. only to RawPacket streams above)
FGEX_STREAM_MAX_SIZE = 4096
FGEX_FULL_STREAM_ACTION = FullStreamAction.REJECT
```

## How it works

The proxy is built on a multi-threaded architecture that embeds Python for dynamic filtering:

- **Packet interception**: the [nfqueue](https://netfilter.org/projects/libnetfilter_queue/) kernel module (part of [netfilter](https://netfilter.org/)) intercepts network packets; the rules attaching nfqueue to traffic are generated with the nftables JSON API by the Python manager.
- **Packet reading**: a dedicated thread reads packets from nfqueue.
- **Multi-threaded analysis**: the C++ binary launches multiple threads, each with its own Python interpreter — Python 3.12's [per-interpreter GIL](https://peps.python.org/pep-0684/) makes this real multithreading. Traffic is distributed across threads by hashing IP/port, so all packets of the same flow are handled by the same thread.
- **Python filter integration**: uploaded filters run inside these interpreters.
- **HTTP parsing**: [a Python wrapper for llhttp](https://github.com/domysh/pyllhttp) (forked/adapted to work across multiple interpreters) parses HTTP traffic.
