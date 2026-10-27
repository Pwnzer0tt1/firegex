# 🐍 Python filters

A **pyfilter** is your own Python attached to a [service](services.md) as a filter. Where a
regex only matches bytes, a pyfilter sees parsed HTTP, TCP streams and per-stream history,
and decides in code.

## How to use it

1. Create a service — see [Services](services.md). Both network layers run pyfilters.
2. Attach a **Python filter** and write or upload the code. One file can define any number
   of `@pyfilter` functions; each gets its own on/off switch and block counter.
3. Edits apply to live connections without dropping any.

The editor completes and documents every model and member (introspected from the
installed library) and **checks the file as you type** with the same process that will run
it: an error is marked on its line, with the reason.

On the proxy layer the filter runs in its own process, so code that hangs is killed and
traffic keeps moving. On NFQUEUE it runs in an embedded interpreter, and `fail_open`
decides whether traffic flows if that process dies.

## Writing a filter

```bash
pip install -U firegex     # `fgex` is the same package
```

```python
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import HttpRequest

@pyfilter
def no_illegal(http_request: HttpRequest):
    if http_request.body and b"ILLEGAL" in http_request.body:
        return REJECT
```

A filter function:

- is decorated with `@pyfilter` and has a unique name in the file;
- annotates **every** parameter with one of the [models](#models) below — it is called
  only once all of them can be built from the data seen so far;
- returns a [verdict](#verdicts) (`None` means `ACCEPT`).

Functions **run in the order the file defines them**; the first to return anything but
`ACCEPT` decides.

**Each connection gets its own module globals**: module-level code runs once per stream and
its globals persist across that stream's packets. Don't keep state in another module's
globals — that is shared between connections. Names starting with `__firegex` are reserved.

**The protocol is read from the annotations.** Asking for an `HttpRequest` makes the file
an HTTP filter; asking only for `RawPacket` or a TCP stream runs on anything. One file
can't ask for two different application protocols — split it into two filters.

### Verdicts

| Verdict | Effect |
|---|---|
| `ACCEPT` | Forward it (also what `None` means). |
| `REJECT` | Close the connection. |
| `DROP` | NFQUEUE: silently drop this and every later packet of the stream. Proxy: same as `REJECT`. |

Filters can't rewrite traffic: the payload is read-only, and so is everything below it.

### What runs where

- **UDP** (either layer): only `RawPacket`. Other models need a stream and would never be
  called, so saving one against a UDP service is refused. `REJECT` drops the datagram.
- **QUIC streams** are streams, so every model works. QUIC datagrams get `RawPacket` only.
- **HTTP/1.1, HTTP/2 and HTTP/3** are all shown to filters as HTTP/1.1 — one file covers
  all three ([details](services.md#http2-and-grpc)).
- **Each HTTP/2 or HTTP/3 stream is its own connection** to a filter, with its own
  globals, unlike an HTTP/1.1 keep-alive connection.

## Models

Annotate parameters with these. **HTTP only** ones need an HTTP connection.

### `RawPacket`

```python
from firegex.pyfilters.models import RawPacket
```

One chunk of the connection. Everything is read-only.

- `data: bytes`, `data_size: int` — the payload.
- `is_input: bool` — client → service (`is_output` is the inverse).
- `is_ipv6: bool`
- `is_tcp: bool` — `False` for UDP and for QUIC.
- `l4: str` — `"tcp"`, `"udp"`, `"quic"` (a QUIC stream) or `"quic-datagram"`.
- `is_stream: bool` — ordered, reliable bytes: TCP or a QUIC stream.
- `src_ip`, `dst_ip`, `src_port`, `dst_port` — by direction.
- `client_ip`, `client_port`, `server_ip`, `server_port` — by role.

### `TCPInputStream` (alias `TCPClientStream`) / `TCPOutputStream` (alias `TCPServerStream`)

```python
from firegex.pyfilters.models import TCPInputStream, TCPOutputStream
```

The stream assembled so far in one direction (client → service, or service → client); only
called for packets in that direction.

- `data: bytes`, `total_stream_size: int`, `is_ipv6: bool`

### `HttpRequest` — HTTP only

```python
from firegex.pyfilters.models import HttpRequest
```

The current request. Called up to twice: when the headers are complete, and again when the
body is (once if both arrive together).

- `method: str`, `url: str | None`, `http_version: str`
- `headers: dict[str, str]` — as received; a repeated header becomes a list.
- `get_header(name, default=None) -> str` — case-insensitive; repeats joined with commas.
- `user_agent: str`, `content_encoding: str`
- `content_length: int | None` — the declared `Content-Length`, if any.
- `body: bytes | None` — `None` until the body arrives.
- `body_decoded` — `body` decoded per `content_encoding` (`gzip`, `br`, `deflate`,
  `zstd`); `False` if decoding failed.
- `keep_alive`, `should_upgrade`, `upgrading_to_h2`, `upgrading_to_ws: bool`
- `ws_stream: list[websockets.frames.Frame]` — decoded WebSocket frames
  ([websockets docs](https://websockets.readthedocs.io/en/stable/)).
- `stream: bytes` — raw WebSocket traffic in this direction, once `should_upgrade`.
- `headers_complete`, `message_complete: bool`, `total_size: int`
- `history: HttpHistory` — see [below](#httphistory-alias-httpstreamhistory--http-only).

Variants, same fields:

- `HttpRequestHeader` — called once, at headers complete; `body` is always `None`.
- `HttpFullRequest` — called once, when the whole request is complete.

### `HttpResponse` — HTTP only

```python
from firegex.pyfilters.models import HttpResponse
```

Same shape and calling convention as `HttpRequest` (without `method`/`url`), plus:

- `status_code: int | None` — e.g. `404`.
- `status_phrase: str | None` — free text; decide on the code instead.

Variants: `HttpResponseHeader` (headers only) and `HttpFullResponse` (complete).

### `HttpHistory` (alias `HttpStreamHistory`) — HTTP only

```python
from firegex.pyfilters.models import HttpHistory
```

Earlier *completed* exchanges on the same connection.

- `requests: list[HttpFullRequest]`, `responses: list[HttpFullResponse]` — snapshots,
  excluding the one in progress.

Use it as a parameter or through `.history` on any `Http*` model:

```python
from firegex.pyfilters import pyfilter, REJECT
from firegex.pyfilters.models import HttpHistory, HttpResponse

@pyfilter
def check_history(hist: HttpHistory):
    if len(hist.requests) > 50:
        return REJECT

@pyfilter
def check_previous_requests(resp: HttpResponse):
    if any(req.url and "admin" in req.url for req in resp.history.requests):
        return REJECT
```

Capped at `FGEX_MAX_HISTORY_SIZE` entries (default `100`) and at `FGEX_STREAM_MAX_SIZE`
bytes per direction; the oldest go first, the newest is always kept.

### gRPC messages — HTTP only

`GrpcMessage`, `GrpcRequest` and `GrpcResponse` hand you **one gRPC message at a time**,
length prefix removed, as each completes — so a streaming call is filtered while still
open. The method, metadata and status are already available through the HTTP models
(path, headers, trailers).

```python
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import GrpcMessage

@pyfilter
def refuse_a_payload(message: GrpcMessage):
    if b"../" in message.payload:
        return REJECT
    return ACCEPT
```

| Member | |
|---|---|
| `payload` | This message's bytes |
| `compressed` | Whether its flag byte says compressed (not decompressed for you) |
| `is_request` | Client → service |
| `method` | `/package.Service/Method` |
| `grpc_status` | The status, where stated |

`GrpcRequest`/`GrpcResponse` are the same, narrowed to one direction. Protobuf isn't
decoded (no schema), and the filter isn't called on non-gRPC traffic.

## Settings

Set these as globals in the filter file.

```python
from firegex.pyfilters import FullStreamAction, ExceptionAction
```

- `FGEX_STREAM_MAX_SIZE: int` — max bytes per stream, per model independently.
  Default 1 MiB. Compressed bodies and WebSocket messages count **decoded**.
- `FGEX_FULL_STREAM_ACTION: FullStreamAction` — what happens past it:

  | Value | Effect |
  |---|---|
  | `FLUSH` (default) | Flush and keep going (a body too large to decode is handed over still encoded). |
  | `DROP` | Drop the rest, like `DROP`. |
  | `REJECT` | Close the connection. |
  | `ACCEPT` | Stop calling filters; accept the rest. |

- `FGEX_INVALID_ENCODING_ACTION: ExceptionAction` — what to do with traffic the HTTP
  parser can't read. Default `ACCEPT` (carried past the HTTP filters, logged once per
  connection); `REJECT` is the stricter choice against request smuggling. Also `DROP` and
  `NOACTION`. A connection a filter joins mid-message (after a filter change) is not
  treated as invalid.
- `FGEX_MAX_HISTORY_SIZE: int` — see [`HttpHistory`](#httphistory-alias-httpstreamhistory--http-only).

## Testing locally

No instance needed — the package ships a proxy simulator, with no Docker or root:

```bash
fgex pyfilters test_http.py 127.0.0.1 8080     # FILTER_FILE ADDRESS PORT
```

It listens on port 7474 (`--from-address`, `--from-port`, `-6` for IPv6) and reloads the
file whenever it changes.

## Full example

```python
from firegex.pyfilters.models import RawPacket, HttpRequest, HttpHistory
from firegex.pyfilters import pyfilter, ACCEPT, REJECT, DROP, FullStreamAction

@pyfilter
def raw_example(packet: RawPacket):
    if not packet.is_input and b"FLAG{" in packet.data:
        return REJECT
    if b"BAD DATA" in packet.data:
        return DROP
    return ACCEPT

@pyfilter
def http_filter(http: HttpRequest):
    if http.method == "GET" and http.url and "test" in http.url:
        return REJECT

@pyfilter
def repeated_probe_filter(hist: HttpHistory):
    if len(hist.requests) > 20:
        return REJECT

FGEX_STREAM_MAX_SIZE = 4096
FGEX_FULL_STREAM_ACTION = FullStreamAction.REJECT
```
