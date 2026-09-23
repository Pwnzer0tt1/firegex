# 🐍 Python filters

A **pyfilter** is one of the two kinds of filter you can attach to a [service](services.md):
your own Python, given structured access to the traffic. Where a regex filter only matches
raw byte patterns, a pyfilter sees parsed HTTP requests and responses, TCP streams and
per-stream history, and decides in code.

## How to use it

1. Create a service and choose its network layer — see [Services](services.md). Both layers
   can run a pyfilter; only the proxy layer can run one alongside other filters.
2. Attach a **Python filter** to it and write or upload the code below. One file can define
   as many `@pyfilter` functions as you like.
3. From then on every matching packet reaches your filters, which return an action
   (accept / drop / reject).

Code can be edited while the service is running: it takes effect on the next packet, and no
connection is dropped. On the proxy layer the filter runs in a process of its own, so code
that hangs is killed and the traffic keeps moving; on NFQUEUE it runs inside the C++ process
through an embedded interpreter, and `fail_open` decides whether traffic keeps flowing if
that process dies.

## Writing a filter

Install the library and CLI:

```bash
pip install -U firegex
```

`fgex` is an alias package for `firegex`: installing either one gives you the same `firegex` module and the `fgex`/`firegex` CLI commands.

### The `pyfilter` decorator

```python
from firegex.pyfilters import pyfilter
```

`pyfilter` marks a function as an active filter. A filter function:
- must be decorated with `@pyfilter`;
- must have every parameter type-annotated with one of the data structures listed below (parameters without a type annotation make the filter invalid, and default/keyword-argument values are ignored — the caller always builds the arguments itself from the live packet data);
- must `return` one of the [packet statements](#packet-statements) below (or `None`, which behaves like `ACCEPT`).

```python
from firegex.pyfilters import pyfilter, ACCEPT, REJECT

@pyfilter
def none_filter():  # A filter that does nothing
    return ACCEPT
```

Filter names (the function name) must be unique within a filter file.

**They run in the order the file defines them**, top to bottom, and the first one to
return anything but `ACCEPT` ends the packet — so a filter placed above another decides
before it, and the interface lists them in that same order.

Each TCP stream (i.e. each connection) gets its own isolated set of global variables: code at module level runs once per stream, and the same globals are reused across every packet of that stream. Don't store state in another module's globals — that memory is shared across every stream handled by the same thread and will cause data to leak/interfere between unrelated connections. Global variable names starting with `__firegex` are reserved for internal use.

```python
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import HttpRequest

@pyfilter
def filter_with_args(http_request: HttpRequest):
    if http_request.body and b"ILLEGAL" in http_request.body:
        return REJECT
```

Here the filter is only called once the data required to build an `HttpRequest` is available (i.e. once the HTTP headers have been parsed, and again once the body is complete). If a filter needs multiple parameters, it's only called once every parameter can be built from the data received so far.

### Packet statements

A filter must return one of these values (importable from `firegex.pyfilters`):

| Statement | Effect |
|---|---|
| `ACCEPT` | The packet is accepted and forwarded to the destination. This is also the default behavior if `None` is returned. |
| `REJECT` | The connection is closed and every packet in the stream is dropped. |
| `DROP` | On NFQUEUE, this packet and every subsequent packet in the stream are silently dropped (unlike `REJECT`, this doesn't simulate a connection closure). On the proxy layer a stream cannot skip bytes, so `DROP` closes the connection exactly as `REJECT` does. |

There is no statement that rewrites the traffic. There used to be one, `UNSTABLE_MANGLE`,
and it was removed for the reason regex rewriting was: a filter only ever sees one chunk,
so a pattern split across two of them was never rewritten, and nothing said so. A filter
that should keep something from leaving refuses the connection carrying it.

### Data structures

These are the types you can use as filter parameter annotations. Some need a connection that speaks HTTP (marked **HTTP only**); the rest work whatever the traffic is.

## The editor knows the library

Firegex's code editor is not a plain text box:

- **Completion** offers the models, the verdicts and the module-level settings, and — once
  a parameter is annotated — the members of whatever it was annotated with. Everything a
  filter is shown is read-only: it answers with a verdict and changes nothing.
- **Hover** any model, member or verdict for what it is and what it does.
- **The file is checked as you type**, by the process that will actually run it. A file
  that will not load is marked **on the line it fails on**, with the reason and the
  source; one that loads says how many functions it defines and which protocol that
  makes it.

None of those hints are written down anywhere: they are introspected from the installed
library. A model that gains a property gains a hint, and one that is renamed stops being
offered under the old name — autocompletion that disagrees with the library would be
worse than none, for the same reason a regex tester that disagrees with the engine is.

The check is the same build, the same compile and the same library the datapath uses, so
a file the editor accepts is a file that loads. It runs in a process of its own, which is
also why a `while True:` at module level costs you a timeout and not the interface.

One file can define as many `@pyfilter` functions as you like, and firegex lists them
individually with a switch each. Switching one off does not touch your code — it is left
out of the list of names the library is given, which is what decides whether it is
called — so a noisy debugging filter can be silenced and brought back without the code
ever leaving the file. Saving a new version reconciles the list with what the file now
defines, keeping your choices for the functions that are still there.

**You never declare which protocol a filter file speaks — what it asks for decides.** Annotating a parameter with `HttpRequest` is what makes a file an HTTP filter; a file that asks only for a `RawPacket` or a TCP stream runs on anything. The two can live in the same file, so a service can carry one filter that parses HTTP and another that does not. What cannot: asking for two *different* application protocols in one file. A connection is only ever one of them, so saving such a file is refused, naming both functions, and you split them into two filters on the same service.

#### What a filter can see, and what it can change

Everything below the application layer is **metadata, and read-only**: the addresses, the ports, the address family, which way the chunk is going. There is no way to read an IP or TCP header as bytes and no way to write one. The payload is read-only too: a filter answers with a verdict, and nothing it assigns reaches either end.

That is deliberate. The two network layers cannot honestly offer the same thing down there: on NFQUEUE a real header exists and rewriting it desynchronises the connection in ways that surface minutes later somewhere else, while the proxy terminated the connection and reopened it, so the headers on the wire are firegex's own and a filter editing them would be editing nothing. An earlier version papered over that by handing the proxy a literal `FAKE:IP:TCP:HEADERS:` prefix — so the same filter did different things depending on which layer it happened to be attached to. Metadata in, a verdict out is the one contract both layers keep.

#### Which models work on UDP

`RawPacket` is the only model that does not need a stream underneath it. Everything
else — an assembled `TCPInputStream`, a parsed `HttpRequest` — reaches for something a
datagram does not have, and on one the library declines to build it, which means **the
filter is never called**.

So a Python filter runs on a UDP service, on either network layer, as long as it asks
for a `RawPacket`. Saving one that asks for anything else against a UDP service is
refused, naming the model: a filter sitting in the chain doing nothing, with nothing
saying so, is the failure this whole module is arranged to prevent.

**HTTP/2 is not a gap any more, and it used to be the one that mattered.** A filter asking
for an `HttpRequest` works on HTTP/1.x, on HTTP/2 and on HTTP/3 alike. It did not work on
a connection that negotiated `h2`: those headers are HPACK-compressed, so the parser was
handed a compression format and the filter was never called — no block, no log, no
counter. The engine terminates HTTP/2 now and shows the chain the HTTP/1.1 each exchange
would have been, from the same code that does it for HTTP/3, so the same file covers every
version. Since gRPC is HTTP/2, that is also what makes gRPC filterable.

**One thing about HTTP/2 to know if your filter keeps state.** Each HTTP/2 stream is its
own connection to a filter, with its own module globals — where an HTTP/1.1 keep-alive
connection carries many requests through one set of them. HTTP/2 interleaves its streams,
so sharing state between them would let one client's bytes decide another client's
verdict, and would let an attacker split a pattern across two streams to get past a
filter. One request, one state, is the honest mapping; it is the same rule an HTTP/3
request stream follows.

**QUIC is not that case, even though it is UDP on the wire.** A QUIC stream is ordered
and reliable, the engine terminates the connection to see inside it, and each stream
reaches the chain as its own connection — so every model works there exactly as it does
on TCP. On an HTTP/3 service the exchange is rendered as the HTTP/1.1 it would have been
before the chain sees it, so `HttpRequest` and the rest mean what they always meant; the
[services documentation](services.md#http3-is-shown-to-the-filters-as-http11) says what
that rendering does and does not promise. The question a model asks is therefore "is
there a stream", not "is this TCP", and `RawPacket` answers both separately.

`REJECT` means something narrower here. There is no connection to close, so the datagram
is simply not delivered and the next one from the same flow is judged afresh.

#### `RawPacket`

```python
from firegex.pyfilters.models import RawPacket
```

One chunk of the connection, and what is known about it.

- `data: bytes` — the application payload. Read-only.
- `data_size: int` — how many bytes of payload this chunk carries.
- `is_input: bool` — `True` for client → service, `False` for service → client. `is_output` is its inverse.
- `is_ipv6: bool` — `True` for IPv6, `False` for IPv4.
- `is_tcp: bool` — `True` for TCP. `False` for a datagram, and `False` for QUIC.
- `l4: str` — what carries this connection: `"tcp"`, `"udp"`, `"quic"` for a stream
  inside a QUIC connection, or `"quic-datagram"` for a DATAGRAM frame in one.
- `is_stream: bool` — whether these bytes arrive in order, once each, as part of a
  stream: true for TCP and for a QUIC stream, false for either kind of datagram. This is
  what every model above `RawPacket` actually needs, and the two came apart when QUIC
  arrived — it is a stream *and* it is UDP, so one flag answering both questions gets one
  of them wrong. A filter asking for a stream model is simply not called for a datagram,
  so one file can carry both.
- `src_ip: str`, `dst_ip: str`, `src_port: int`, `dst_port: int` — where this chunk came from and where it is going (read-only).
- `client_ip`, `client_port`, `server_ip`, `server_port` — the same two endpoints named by role instead of by direction, so a filter does not have to branch on `is_input` to find out who the client is (read-only).



#### `TCPInputStream` (alias `TCPClientStream`)

```python
from firegex.pyfilters.models import TCPInputStream
```

The assembled TCP stream in the input (client → server) direction. A filter using this type is only called for incoming packets.

- `data: bytes` — the entire input-direction stream assembled so far (read-only).
- `total_stream_size: int` — size of that stream (read-only).
- `is_ipv6: bool`

#### `TCPOutputStream` (alias `TCPServerStream`)

```python
from firegex.pyfilters.models import TCPOutputStream
```

Same as `TCPInputStream`, but for the output (server → client) direction; only called for outgoing packets.

#### `HttpRequest` — HTTP only

```python
from firegex.pyfilters.models import HttpRequest
```

The current HTTP request. This handler is called up to twice: once when the headers are complete, and again once the body is complete (if the whole request arrives in a single TCP packet, it's called only once).

- `method: str` — the request method, e.g. `"GET"`. Documented as `bytes` before, which no comparison in a filter ever satisfied.
- `url: str | None` — the request URL.
- `headers: dict[str, str]` — request headers, keys/values exactly as received (case-sensitive); a repeated header becomes a list of values.
- `get_header(header: str, default=None) -> str` — looks up a header case-insensitively; if the header was repeated, its values are joined with a comma (this method never returns a list).
- `user_agent: str`
- `content_encoding: str`
- `content_length: int | None` — what the `Content-Length` header declared, or `None` when there was none (a chunked body, or one delimited by the connection closing).
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
from firegex.pyfilters.models import HttpRequestHeader
```

Same fields as `HttpRequest`, but only called once, when the headers are complete — the body is never buffered and `body` is always `None`.

#### `HttpFullRequest` — HTTP only

```python
from firegex.pyfilters.models import HttpFullRequest
```

Same fields as `HttpRequest`, but only called once the whole request (headers + body) is complete. Completed instances of this type are also what gets stored in `HttpHistory.requests`.

#### `HttpResponse` — HTTP only

```python
from firegex.pyfilters.models import HttpResponse
```

The current HTTP response — same shape and calling convention as `HttpRequest` (up to twice: headers complete, then body complete), plus:

- `status_code: int | None` — the numeric status, e.g. `404`. `None` on a request, and before the response line has been read.
- `status_phrase: str | None` — the reason phrase beside it, e.g. `"Not Found"`. Free text: a server may write anything there, so decide on the code, a header or the body.

All the other fields listed for `HttpRequest` (`headers`, `get_header`, `body`, `body_decoded`, `content_encoding`, `content_length`, `http_version`, `keep_alive`, `should_upgrade`, `upgrading_to_h2`, `upgrading_to_ws`, `ws_stream`, `stream`, `headers_complete`, `message_complete`, `total_size`, `history`, `user_agent`) apply here too.

#### `HttpResponseHeader` — HTTP only

```python
from firegex.pyfilters.models import HttpResponseHeader
```

Same as `HttpResponse`, but only called once the headers are complete; `body` is always `None`.

#### `HttpFullResponse` — HTTP only

```python
from firegex.pyfilters.models import HttpFullResponse
```

Same as `HttpResponse`, but only called once the whole response is complete. Completed instances of this type are what gets stored in `HttpHistory.responses`.

#### `HttpHistory` (alias `HttpStreamHistory`) — HTTP only

```python
from firegex.pyfilters.models import HttpHistory
```

Gives a filter access to previously *completed* requests/responses on the same TCP stream — useful for correlating a response with the request(s) that came before it on a keep-alive connection, or for stateful logic that spans more than one exchange.

- `requests: list[HttpFullRequest]` — a snapshot copy of the requests completed so far on this stream (does not include the request currently being processed).
- `responses: list[HttpFullResponse]` — a snapshot copy of the completed responses so far.

You can use it in two ways:

```python
from firegex.pyfilters import pyfilter, REJECT
from firegex.pyfilters.models import HttpHistory, HttpResponse

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

### gRPC messages

**HTTP only.** `GrpcMessage`, `GrpcRequest` and `GrpcResponse` hand you **one gRPC message
at a time**, with its length prefix taken off.

gRPC is HTTP/2, and firegex renders every version of HTTP to the filters as HTTP/1.1 — so
everything *around* a call already arrives through the models above: the method is the
path on an `HttpRequest`, the metadata are its headers, the status is in the trailer
section. What did not arrive was the body. A gRPC body is a sequence of messages, each one
a flag byte, a four-byte length and then the protobuf; a filter reading `request.body` read
that framing glued to the payload, and a pattern could match across the boundary between
two messages — a false positive with nothing to point at.

```python
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import GrpcMessage

@pyfilter
def refuse_a_payload(message: GrpcMessage):
    if b"../" in message.payload:
        return REJECT
    return ACCEPT
```

| Member | What it is |
|---|---|
| `payload` | This message's bytes, without the length prefix |
| `compressed` | Whether this message's own flag byte says it is compressed |
| `is_request` | Whether it went from the client towards the service |
| `method` | The gRPC method, which is the HTTP path: `/package.Service/Method` |
| `grpc_status` | The status, where the message carrying it stated one |

`GrpcRequest` and `GrpcResponse` are the same thing narrowed to one direction, so you do
not have to check `is_request` yourself.

**It is called per message, not per body**, and that is the part that matters: a
server-streaming or bidirectional call has a body that does not finish until the stream
closes, so a model that waited for a finished body would call your filter once, at the
end — a log entry rather than a block. Each message is handed over as it completes, and a
message split across two packets is held until it is whole: deciding on half a payload is
how a pattern gets defeated by splitting it.

Two things it deliberately does **not** do. It does not decompress a message whose flag
byte says it is compressed — what it is compressed with is the two peers' agreement
(`grpc-encoding`), and guessing is how a filter comes to read something that is not there,
so you get `compressed` and the raw bytes. And it does not decode the protobuf: without
your `.proto` there is no schema, so `payload` is bytes and a pattern against them is what
a ruleset has.

A filter asking for one of these is simply **not called** on traffic that is not gRPC, the
way every other model declines when what it needs is not there.

## Stream limiter

What happens if a single TCP stream carries a lot of data? Past a configurable size, a "full stream" action kicks in. First import the enum:

```python
from firegex.pyfilters import FullStreamAction
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
from firegex.pyfilters import ExceptionAction
```

- `FGEX_INVALID_ENCODING_ACTION: ExceptionAction` — action taken when parsing hits an invalid/unsupported encoding (a parser-level failure). Default: `ExceptionAction.REJECT`. Values: `ACCEPT` (accept the packet that caused the error), `DROP` (drop the connection), `REJECT` (reject the connection), `NOACTION` (do nothing — the error is signaled and the stream is accepted without calling any more pyfilters on it).
- `FGEX_MAX_HISTORY_SIZE: int` — max number of requests/responses kept per stream by [`HttpHistory`](#httphistory-alias-httpstreamhistory--http-only). Default: `100`.

## Testing a filter locally

You don't need a running Firegex instance to try out a filter: the `firegex` pip package ships a local proxy simulator.

```text
➤ fgex pyfilters -h

 Usage: fgex pyfilters [OPTIONS] FILTER_FILE ADDRESS PORT

 Run your Python filters against a real service, locally

╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    filter_file      TEXT     The path to the filter file [default: None] [required]                                                               │
│ *    address          TEXT     The address of the target to proxy [default: None] [required]                                                        │
│ *    port             INTEGER  The port of the target to proxy [default: None] [required]                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --from-address          TEXT        The address of the local server [default: None]                                                                 │
│ --from-port             INTEGER     The port of the local server [default: 7474]                                                                    │
│                 -6                  Use IPv6 for the connection                                                                                     │
│ --help          -h                  Show this message and exit.                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

This runs a local proxy in front of `ADDRESS:PORT`, applying `FILTER_FILE` to the traffic — no Docker, no nftables/root privileges required. The filter file is reloaded automatically whenever it changes on disk, so you don't need to restart the simulator while iterating.

```bash
fgex pyfilters test_http.py 127.0.0.1 8080
```

There is no protocol to pass: the file says which one it speaks by what its filters ask for, exactly as it does in a running instance.

## Full example

```python
# One file, two filters: one that wants raw payloads and one that wants parsed HTTP.
# Nothing declares a protocol — asking for an HttpRequest is what makes this an HTTP
# filter file.

from firegex.pyfilters.models import RawPacket, HttpRequest, HttpHistory
from firegex.pyfilters import pyfilter, ACCEPT, REJECT, DROP, FullStreamAction

# Lowest level of abstraction: the raw payload of each chunk.
@pyfilter
def raw_example(packet: RawPacket):
    if not packet.is_input and b"FLAG{" in packet.data:
        return REJECT
    if b"BAD DATA" in packet.data:
        return DROP
    return ACCEPT

# Higher level of abstraction: parsed HTTP requests.
@pyfilter
def http_filter(http: HttpRequest):
    if http.method == "GET" and http.url and "test" in http.url:
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
