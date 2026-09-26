# The proxy datapath engine

`fgex-proxy`: one of the two network layers a service can be put on. Instead of lifting
packets to userspace and handing a verdict back to the kernel — which is what
`backend/binsrc/` does — it terminates the connection and owns both halves.

It is what a service selects as its **proxy** layer in `modules/services/transports.py`,
and it is what makes TLS, QUIC, HTTP/2 and HTTP/3 filterable at all.

> This file is the engine's own documentation: what it does, and why it is shaped this
> way. The product-level view — which layer to choose and what each one costs — is
> [`docs/services.md`](../../docs/services.md), and the rules a change here has to keep
> are in [`AGENTS.md`](../../AGENTS.md). Where any of the three disagree, `AGENTS.md`
> wins; this file has been wrong before by being left behind while the engine moved.

## What it has to prove first

The NFQUEUE engine fails open in the kernel: the nft rule carries `flags: ["bypass"]` and
the binary asks for `NFQA_CFG_F_FAIL_OPEN`. If firegex dies, stalls, or falls behind,
packets flow anyway. In attack/defense that is the difference between "the filter didn't
fire" and "I lost the SLA".

A userspace proxy has no such backstop: if the process dies, the socket dies with it. So
the property is rebuilt by hand, and it has to hold against user code that is assumed to
be broken:

| Failure | Handled by | Outcome |
| --- | --- | --- |
| Filter panics | `catch_unwind` around every call | Chunk forwarded, filter disabled at once |
| Filter never returns | Deadline on the blocking task | Chunk forwarded, filter disabled after 3 in a row |
| Every filter disabled | `degraded` flag | Chain skipped entirely — no copy, no thread hop |
| Connection handler panics | One task per connection | That connection only; the listener lives |
| Python worker hangs or dies | Killed and respawned on the next chunk | That chunk forwarded |
| Backend goes away | stdin closing is not a shutdown | The current ruleset keeps being enforced |

The degraded path is deliberately the cheapest one. Failing open must not cost more than
working normally, or the failure mode becomes a second failure. `panic = "unwind"` in
`Cargo.toml` is load-bearing rather than tuning: an aborting binary cannot catch anything.

`tests/fail_open.rs` asserts each row over real sockets.

## What the proxy buys

- **Every version of HTTP, filtered the same way.** HTTP/2 and HTTP/3 compress their
  method, path and headers (HPACK, QPACK), so a layer that only forwards shows a filter a
  compression format. This one terminates them and renders each exchange as the HTTP/1.1
  it would have been, so one pattern and one Python file cover all three.
- **TLS and QUIC.** The plaintext never leaves the process.
- **Reassembly from the kernel**, instead of a stream follower and the out-of-order caveat
  that comes with it.
- **An ordered chain inside one process**, rather than one process and one reassembly pass
  per filter.
- **Real connection metadata.** A filter is told the client's and the service's address
  and port once per connection (`ConnectionMeta`, a `KIND_OPEN` frame), and nothing below
  the application layer beyond that. That is more than a header could honestly say here:
  this engine terminated the connection, so the headers on the wire are its own.
- **Backpressure for free.** A slow filter slows the sender through TCP flow control
  rather than overflowing a fixed-size queue and dropping packets.
- **Clean closes.** A refused connection is shut down properly instead of leaving the peer
  to infer something from missing packets.

What it costs is the kernel backstop above, and being in the path at all: the connection
the service sees is one this process opened.

## The limitation that decided the design

A blocking filter thread **cannot be cancelled**. When one blows the deadline the engine
walks away, but the thread lives until its own code decides to stop — it holds a
blocking-pool slot until the process restarts. The damage is bounded (a filter that times
out repeatedly is disabled and never called again) but bounded is not zero.

That is why user Python runs **out of process**: a hung worker can be killed, a hung
thread cannot. It also keeps `libpython` out of the datapath binary, which is where a good
share of the C++ engine's complexity lives.

Compiled patterns cannot hang, so they declare `may_block() == false` and run **inline**
against the relay's own buffers — no thread hop, no copy. That is not a micro-optimisation:
it took ten rules from ~1260 to ~2950 MB/s in the benchmark that found it. The deadline
machinery is still there and still the default; it is simply no longer charged to filters
that cannot use it.

## Rules

One JSON line on stdin carries the whole ruleset, one `ACK OK` / `ACK FAIL <why>` line
comes back — the same shape `cppregex` uses for its filter codes. Blocks are reported as
`BLOCKED <id>` so the backend can attribute them.

```json
[{"kind":"regex","id":"r1","filter":"f1","pattern":"FLAG\\{[a-z]+\\}","direction":"s2c","case_sensitive":true},
 {"kind":"python","id":"f2","code_path":"/execute/db/service_filters/f2.py",
  "enabled":["block_traversal"],"command":["python3","/execute/modules/services/pyworker.py"],
  "timeout_ms":1000}]
```

Four decisions worth knowing:

- **A pattern blocks. There is no second action.** There used to be a `replace` rule, and
  it was withdrawn because it could not keep its promise: rewriting scanned one chunk at a
  time — bytes already forwarded cannot be taken back — so a match straddling two chunks
  was never rewritten. Measured: a pattern sent whole arrived redacted, the same pattern
  split across two TCP segments arrived intact, and blocking (which scans in hyperscan's
  stream mode) caught both. The miss was not the problem; its silence was.
- **The order the backend sent is the order that runs.** `filter` groups the patterns of
  one link so they share a compiled database, which is what makes fifty patterns cost
  about what one costs — and a group is exactly a filter, so grouping never crosses a
  boundary the operator can see. An earlier version grouped every regex and then every
  Python rule, which turned the chain into a set. `tests/rules.rs` pins both.
- **A rejected ruleset changes nothing.** One bad pattern refuses the whole update and the
  previous rules keep enforcing. Failing open covers a filter that breaks at runtime; it
  is not a licence to quietly drop rules the operator asked for. Each pattern is compiled
  alone first and thrown away, only so a failure can name *which* rule is wrong —
  hyperscan reports the first one and stops.
- **A block closes the connection, not the direction.** Half-closing would let a service
  that answers without waiting for the request still reach a client whose request was
  refused. On QUIC and HTTP/2 the refusal closes the *connection* rather than the stream,
  for the same reason: a block a client can simply retry on the next stream is not a block.

Matching is hyperscan (`src/hyperscan.rs`, a binding to `libhs`), the same library
`cppregex` uses on the other layer. There is no second regex engine in this tree, and
adding `regex` to `Cargo.toml` would undo that.

## Python filters

The API is the one a `firegex` user already knows, and it is the **same library** the
NFQUEUE binary embeds — `firegex.pyfilters`, with all of its models:

```python
from firegex.pyfilters import pyfilter, ACCEPT, REJECT, HttpRequest

@pyfilter
def block_path_traversal(req: HttpRequest):
    return REJECT if "../" in req.url else ACCEPT
```

`modules/services/pyworker.py` is the child process that runs it. A filter file's protocol
is read off the annotations, never declared; what a filter may read and write is the same
on both layers (`RawPacket` metadata in, payload out, nothing below the application
layer). See [`docs/pyfilter.md`](../../docs/pyfilter.md).

Frames are length-prefixed binary on the worker's stdin/stdout:
`[u32 len][u8 kind][u64 connection][payload]`, big-endian, `len` covering everything after
itself.

| kind | meaning |
| --- | --- |
| `0` / `1` | a chunk, client→server / server→client |
| `2` | the connection is over — so the worker can drop its module globals |
| `3` | the connection's metadata, one JSON object, once |

The reply is `[u32 len][verdict][name len][name][payload]`. The name is whichever
`@pyfilter` function decided, so a block is attributed as `<filter>/<function>` — the same
token the NFQUEUE binaries report, which is what lets the backend have one way to
attribute one.

Three things are load-bearing:

- **The worker announces itself** (`READY`) once it has executed the user's file. Waiting
  for it is what lets a ruleset carrying code that does not load be refused *when it is
  applied*, rather than discovered later as traffic that quietly stopped being filtered.
- **The connection id is in every frame**, because the documented promise is that each
  stream gets its own module globals. One client's state deciding another client's verdict
  is both a false positive and a way to smuggle a pattern past a filter.
- **`stdout` is the protocol channel**, so the worker reassigns `sys.stdout = sys.stderr`
  before running user code: a `print()` landing in the middle of a frame gets the worker
  killed on every packet with nothing to explain it. `tests/pyworker.rs` has a regression
  test for exactly that.

Tracebacks go to stderr, where the backend already reads them; the worker also marks them
so the backend can say *the traffic was forwarded unfiltered* alongside the traceback,
which is the sentence the NFQUEUE side produces from an `EXCEPTION`.

One worker per rule, one conversation at a time. Serialising is the honest simple thing
while a frame is a request and a response; a pool is the next step if Python filtering
ever becomes the bottleneck.

## TLS

The engine terminates it: it decrypts from the client, the chain sees plaintext that never
leaves the process, and it re-encrypts on the way out — `rustls` with the `ring` provider,
so there is no OpenSSL in the build and the Docker stage stays a plain `cargo build`.

What that replaced was **nginx**: one listener terminating the public connection and
forwarding plaintext to a second loopback port, which re-encrypted towards the real
service, with the filter engine attached to the leg in between. It cost a generated config,
**a pair of ports derived from hashing `ip:port`** — chosen rather than assigned, so they
could collide with something real — a `tls_streams` table, an nft chain of its own, and a
failure mode where one unloadable certificate stopped nginx and took every TLS service on
the instance down with it. A TLS service now occupies no port a plain one does not, and
the blast radius is structural: each service carries its certificate into its own process.

**ALPN is mirrored, and the ordering is the design.** The client's handshake is *started*
and held at the ClientHello (`tokio_rustls::LazyConfigAcceptor`), because that message
carries the protocols the client will speak; the upstream handshake goes next offering
exactly that list; and whatever the service picked is the single protocol the client is
then told. Answering something the service did not say is how a proxy breaks a protocol it
was only carrying — a client told `h2` against an HTTP/1.1 service sends frames nothing can
read. When the service picks nothing, the client is told nothing: no agreement is invented.
Before this, ALPN was dropped in both directions and every client silently fell back to
HTTP/1.1.

**The upstream certificate is not verified**, mirroring the `proxy_ssl_verify off` nginx
was configured with. That is the right call rather than laziness: the service on the other
side is the thing firegex is defending, it is behind loopback or a private link, and in a
competition it is invariably self-signed. Verifying it would only ever refuse to protect it.

Certificate and key reach the engine as **paths**, never as environment values: a private
key in an env dump is a private key in a log.

What cannot be carried, and is a limit rather than a missing setting: **TLS 1.0 and 1.1**,
which rustls does not implement; the cipher list, which is fixed and forward-secret only;
and **client certificates**, since the certificate a client would present is one only the
service can check. The key must be one `ring` will sign with — RSA ≥ 2048, ECDSA or
Ed25519; nginx could be told to take a 1024-bit key with `@SECLEVEL=1` and rustls has no
equivalent, so a smaller one is refused at startup with the reason on stderr.

## QUIC, and HTTP/3

**QUIC is terminated, and unlike TLS there was never a second option.** TLS over TCP can
be carried past unopened — the bytes are framed by a transport the kernel understands — so
filtering the ciphertext is a thing an operator could choose. Past its Initial packet QUIC
encrypts the frames, the stream boundaries and the packet number along with the payload,
so a packet queued to NFQUEUE is a datagram of noise.

To the kernel it is UDP, so the addresses, the rules and the relay map are the code that
was already there for datagrams; what changes is that the port is bound by something that
terminates (`quic::QuicManager`) instead of something that forwards (`udp::UdpManager`).
`relays::Relays` is the two-armed enum both the startup list and the control channel go
through.

- **The ALPN is mirrored, as on the TLS path.** quinn offers nothing to hold a ClientHello
  at, but an Initial packet's keys come from the connection ID it carries in the clear, so
  `quic_hello.rs` reads the client's list off the socket before the handshake is answered.
  The service is dialled first offering exactly that list, and the client is advertised
  the one protocol the service chose — nothing to configure, whatever the service speaks.
  A hello that cannot be read falls back to offering `h3`, and says so.
- **One stream is one connection to the chain**, with its own sessions and its own module
  globals, released when the stream ends. A filter's state follows a stream of bytes from
  start to end, which is what a QUIC stream is and what a QUIC connection is not.
- **A refusal closes the connection**, not the stream.
- **Datagrams are carried, and one connection's are one flow.** `L4::QuicDatagram` is its
  own value rather than `Quic` with a flag, because the two answer the stream question
  differently: a datagram gets `RawPacket` and nothing else, which is the same answer the
  plain UDP relay gives. The flow opens on the first datagram, not on the connection, so a
  connection that negotiates the extension and never uses it costs no filter state. A
  refused datagram is **dropped and the connection carries on** — a datagram is complete by
  the time it is judged. `DATAGRAM_BUFFER` bounds what one connection may have waiting.
- **They are not carried on HTTP/3, and the handshake says so** rather than the peer
  finding out: an HTTP/3 datagram names the stream it belongs to, and the request streams
  this proxy opens towards the service are not the ones the client opened. So the `h3`
  accept configuration is built with a transport that does not advertise the extension.
- **WebTransport is not carried**, and it is a bigger question than its datagrams: its
  streams are bound to a session by a varint every one of them carries, which breaks both
  "one stream is one connection to the chain" and the HTTP/1.1 rendering. It needs a
  session model, not a switch.
- **0-RTT is refused** (`max_early_data_size = 0`): early data is replayable and a refused
  request cannot be un-delivered. And **every unvalidated client gets a Retry**, so nothing
  is opened towards the service on the word of a source address nobody has checked.

**HTTP/3 is rendered to the chain as the HTTP/1.1 it would have been** (`src/h3.rs`, on
hyperium's `h3` — a binding, not a second implementation). That is the point of the whole
exercise: QPACK would otherwise be what a filter is shown, and every pattern written for
the TCP service beside it would silently stop matching.

## HTTP/2, and one rendering for every version

**`src/http1.rs` is the rendering, and `h2.rs`/`h3.rs` are what is left of each protocol
once it is taken out.** The HTTP/1.1 view a filter is shown — the framing decision, the
head hold, `render_request`/`render_response`, `judge` — lives in one place, and both
protocols are adapters to somebody else's parser. Two copies would be two things a filter
can be shown, and the day they drift the symptom is a pattern that matches over one
version and not another with nothing to say so.

An HTTP/2 client can be put in front of a service that speaks HTTP/1.1: `h2.rs` takes its
upstream as an `Outbound`, so it is either another HTTP/2 connection or `h1up::H1Upstream`
where the address said the service is cleartext — exactly as on the QUIC edge.

Three things differ from h3 and each is a way to get this wrong:

- **Flow control is ours to run.** `h2` hands received bytes over and waits for them to be
  released. Releasing on read means no backpressure and this process buying memory for
  whichever side is faster; never releasing stalls the stream after the first window. So
  capacity is released **after the piece has been forwarded**, and outbound writes reserve
  capacity before writing.
- **The end of a message rides on its last frame.** A head that *is* the whole message has
  to be sent with `end_of_stream` on the head; sending it open and closing with an empty
  DATA frame turns a **trailers-only** answer into one with a body — which is exactly a
  gRPC status-only reply, and gRPC clients refuse the mangled version. `head_is_the_message`
  asks the sender rather than inferring.
- **One stream is one connection to the chain**, unlike HTTP/1.1 where a keep-alive
  connection carries many requests through one set of filter state. HTTP/2 interleaves its
  streams, and sharing state between two of them is a way to smuggle a pattern past a
  filter by splitting it across them.

Also:

- **`h2c` — HTTP/2 in the clear — is recognised from the connection preface, not from a
  setting.** Most gRPC is deployed without TLS behind a load balancer, so leaving it out
  would have made "gRPC is filtered" half true. `sniff()` in `proxy.rs` **peeks** rather
  than reads, so a connection that turns out to be something else is handed to the byte
  pumps exactly as it arrived and there is no buffer to replay. It **races the service**,
  because a protocol where the server speaks first (SMTP, SSH, most game protocols) would
  otherwise be held waiting for a client that is correctly waiting for a banner — and it is
  bounded (`SNIFF_WAIT`), so two silent peers cannot hold two descriptors. The same peek
  answers the TLS question for an `http` service, which is why there is one `Opening` and
  not two sniffs.
- **Server push is refused in the handshake**, not by dropping what arrives, and
  **extended CONNECT is not advertised**; a plain `CONNECT` stream is reset with a log line
  rather than rendered, because a tunnel is opaque bytes with no HTTP/1.1 message in it.
- **A refusal closes the connection with `Reason::CANCEL`**, deliberately not
  `REFUSED_STREAM`, which tells a client the request was never acted on and may be retried.
- **A bypassed chain is not terminated.** Rendering for a chain with nothing to say is work
  paid for no answer, so a service with no filters, one whose filters have all been
  disabled, and a connection admitted past the limit with `over_limit_forwards` all take
  the byte pump. The cost is that such a connection stays a byte pump for its whole life
  even if a filter is pushed a moment later.
- **The HTTP/1.1 `Upgrade: h2c` handshake is not carried**, and that is a limit rather than
  an unconfigured setting: the upgrade request is filtered as the HTTP/1.1 request it is,
  but if the service answers `101` everything after it is HTTP/2 nobody rendered. RFC 9113
  deprecated the mechanism and nginx dropped it in 1.25.1.

## UDP

The TCP path recovers where a connection was headed with `SO_ORIGINAL_DST`, which the
kernel implements **for TCP and SCTP only**. So UDP is relayed with **one socket per
protected address**, each with its upstream fixed — nothing has to be recovered because
nothing was lost. The engine prints one `UDP <upstream> <port>` line per relay after
`PORT`, and the backend points each address's rule at its own port.

Per-flow filter state is keyed by client address and released after `IDLE`: UDP has no
close to observe, so a timeout is the only thing that ends a flow. Both directions are
inspected. `Verdict::Reject` drops the datagram rather than closing anything. Replies leave
through the **listener** socket so conntrack rewrites them to appear from the address the
client dialled; sending from the upstream socket would reach a client not expecting that
source. The relay's own dial carries the self-mark, or the redirect rule would catch it and
loop.

New relays can be added to a running engine over the control channel, so an address added
to a running service costs nobody their connection.

## Holding up under load

**A service carries at most `FGEX_PROXY_MAX_CONNECTIONS` at once**, and the operator says
what happens to the rest. It exists because the alternative was measured: silent
connections cost two descriptors each — one from the client, one to the service, since the
upstream is dialled on accept — and ~505 of them from one host exhausted the container's
1024 and took **every** service down. UDP was cheaper still: 600 datagrams from 600 forged
sources in 0.03 s took 400 descriptors and held them a minute after the sender left.

Say what it buys, and no more. **A cap does not save the service being attacked** — it
cannot tell a connection that is silent because it is an attack from one that is silent
because the client is slow. What it buys is that one service's attacker stops being
everyone's: measured, 400 silent connections against a limited service left the service
beside it answering.

- One number for both halves, because TCP connections and UDP flows spend the same
  descriptors. `0` is no limit, kept as a value rather than an absence.
- `Slot` is a guard with a `Drop`, not a decrement at the end of `handle_connection`: that
  function has a dozen ways out, and a counter that leaks on any one of them is a limit
  that tightens until it refuses everything.
- The accept loop **backs off** after a failed accept. Out of descriptors, the loop spun on
  `accept` → `EMFILE` → print → `accept`, measured at ~40% of a core with four clients
  knocking, writing a log line per attempt into the pipe the backend reads.
- On QUIC, `over_limit_forwards` is honoured but is not free: the connection is still
  terminated, decrypted and re-encrypted, because there is no such thing as forwarding a
  QUIC connection unopened.

**`FGEX_PROXY_FIRST_BYTE_TIMEOUT` is what the cap cannot be.** A cap contains a phantom
flood; a deadline ends it — measured, with the limit full and the attacker still holding
every socket, clients got back in once it passed. Two properties are load-bearing:

- **Either direction counts.** The flag is set by whichever pump moves a byte first, so a
  service that greets its client satisfies it with its banner. Requiring the *client* to
  speak would hang every server-speaks-first protocol.
- **Only until the first byte, never again.** A connection that has spoken and gone quiet
  is a session, and sessions think. This is not an idle timeout.

The flag is set *before* the chain runs, because a chunk a filter goes on to refuse is
still a connection that said something. The watchdog fires through the same stop signal a
refusal uses, so both directions shut down cleanly — a dropped peer reads a truncation, and
this connection has done nothing to deserve one.

## Preserving the client address

The service must keep seeing the real client, or everything that logs, rate-limits or bans
by address starts seeing one address for the whole internet. Source preservation is
**unconditional**: the engine always dials the service from the client's address
(`IP_TRANSPARENT`, with a kernel-chosen port). `CAP_NET_ADMIN` is probed at startup,
because a missing capability would otherwise surface only as every service quietly seeing
the proxy's address. If a transparent dial fails at runtime the engine falls back to its
own address — traffic beats identity — but counts it and says so once, loudly.

The work is in getting the reply back. With the service on this same host, two flows look
almost identical:

| Flow | src | dst | must |
| --- | --- | --- | --- |
| Engine answering the client | `service:port` | `client:client_port` | leave the box |
| Service answering the engine | `service:port` | `client:<ephemeral>` | stay local |

No address tells them apart — only an ephemeral port chosen at connect time, which nothing
can be written against. **Conntrack can**: the first belongs to the intercepted, DNATed
connection, the second is a separate entry the engine opened itself. So the output chain
reads `ct status dnat accept` for the first and marks everything else from a protected
service home, and the marked packets are delivered locally by an `fwmark` rule plus a
`local` default route. `modules/services/nftables.py` installs all of it.

**Only the redirect intercept exists.** A `tproxy` mode was implemented and removed: the
intercept it creates makes no NAT entry, so there is no marker to separate those two flows,
and a divert rule broad enough to catch the service's reply also reroutes the engine's own
SYN-ACK away from the client — the connection then hangs rather than fails. That was
measured. Since the topology firegex actually runs in has the service on the same host or
behind a private link, the mode that cannot serve it was not worth keeping.

The engine stamps `SO_MARK` (`SELF_MARK`, `0x133A`) on every connection it opens, and the
intercept rules skip it — otherwise, where both ends are local, an intercept in `nat output`
would catch the engine's own dial and loop it back into itself.

## Where the plaintext goes

Terminating in-process means the decrypted traffic is never a packet, so there is nothing
for a capture tool to read. `src/capture.rs` writes it out: each connection's plaintext
framed as the TCP stream it was, sent over `AF_PACKET` to a dummy interface (`firegex0`)
that carries every decrypted service's traffic and nothing else.

They are **reconstructed** packets. The bytes are real — what the filters saw and what was
forwarded — but the framing is built here, because the framing on the wire was encrypted:
sequence numbers from zero, no retransmissions, segmentation from this engine's read sizes.
A SYN and a FIN are emitted so a capture tool has a stream to follow rather than orphan
segments. **Say so wherever it is offered: a capture from here is not evidence of what was
on the wire.**

On QUIC each *stream* is written as its own TCP conversation, with a synthetic client port
from a cycling counter — every stream of one connection shares the connection's four-tuple,
and writing them out as they are would interleave a hundred of them into one conversation
whose bytes decode as nothing. On HTTP/3 and HTTP/2 what is written is the **rendering**,
which is the only way this interface can keep the promise it makes everywhere else: what is
on it is what the filters saw. It is not what left the process, and the two cannot disagree
because they are the same bytes.

Every failure is silent and local. No interface, no socket (it needs `CAP_NET_RAW`), a send
that fails — the traffic goes on exactly as it would have. A capture aid must never be able
to interrupt the service it is watching. The interface itself belongs to the instance and
is created by `modules/services/mirror.py` before any engine starts.

## Talking to it

Two channels, both line-oriented, and the datapath never waits on either.

**stdout — what the engine says.** The handshake first, then events:

| line | meaning |
| --- | --- |
| `PORT <n>` | the port it bound. Pass `:0` and read this back; nothing keeps a registry |
| `UDP <upstream> <port>` | one per relay, in the order they were asked for |
| `BLOCKED <id>` | a rule refused something; `<filter>/<function>` for Python |
| `ACK OK` / `ACK FAIL <why>` | the answer to one control line |
| `STATS seen=… refused=… live=… over_limit=… no_first_byte=…` | every 2 s, first one immediately |

Everything descriptive — `[info]`, `[warn]`, `[fatal]` — goes to **stderr**, which the
backend captures and turns into the service's log. `_died_because` keeps the last `[fatal]`
line, so a service that will not start reports the engine's own reason rather than "the
proxy engine did not report a listening port".

**stdin — what it is told.** One command per line:

| line | meaning |
| --- | --- |
| `[{…}, {…}]` | the whole ruleset, replacing the previous one |
| `ADD_UDP <addr> [same\|plain\|tls]` | bind one more relay; answers `UDP …` then `ACK` |
| `PUBLISH <dialled> <edge> <onward> [<service>\|-]` | what is spoken at one address and where the service behind it is |
| `WITHDRAW <dialled>` | forget one published address |

stdin closing is **not** a shutdown: the backend being gone is exactly when the datapath
outliving its control channel matters.

## Environment

| variable | meaning |
| --- | --- |
| `FGEX_PROXY_LISTEN` | **required.** `[::]:0` for dual-stack, which is what the backend passes |
| `FGEX_PROXY_UPSTREAM` | **required.** `original` (recover it per connection) or a literal address |
| `FGEX_PROXY_SPOOF_SOURCE` | dial the service as the client. The backend always sets it |
| `FGEX_PROXY_TARGETS` | `<addr>[\|<edge>[\|<onward>]][=<service>]`, comma-separated; the addresses that are not simply the service |
| `FGEX_PROXY_UDP` | `<addr>[\|<onward>]`, comma-separated; one relay each |
| `FGEX_PROXY_TLS` / `_TLS_OPTIONAL` | terminate TLS on the TCP listener; `_OPTIONAL` means only for the connections that start a handshake |
| `FGEX_PROXY_TLS_CERT` / `_TLS_KEY` | **paths**, never the material |
| `FGEX_PROXY_QUIC` | bind the relays with a QUIC endpoint instead of a datagram socket |
| `FGEX_PROXY_MAX_CONNECTIONS` | 0 is no limit |
| `FGEX_PROXY_OVER_LIMIT_FORWARD` | forward what does not fit, unfiltered, instead of refusing it |
| `FGEX_PROXY_FIRST_BYTE_TIMEOUT` | seconds; 0 is off |
| `FGEX_PROXY_FILTER_TIMEOUT_MS` | how long a blocking filter gets. Default 2000 |
| `FGEX_PROXY_CONNECT_TIMEOUT_MS` | upstream dial and handshakes. Default 5000 |
| `FGEX_PROXY_SELF_MARK` | hex; default `133A`. Must match `PROXY_SELF_MARK` in the backend |
| `FGEX_PROXY_PYWORKER` | fallback path to the worker, for a Python rule that carries no `command` |
| `FGEX_PROXY_FILTERS` | `panic`, `hang`, `block:<needle>` — **test scaffolding only** |
| `NTHREADS` | tokio worker threads. What `run.py --threads` sets, on both layers |

`FGEX_PROXY_BINARY` is read by the *backend*, not by this, and points at the binary — which
is what a dev build overrides.

There is one more mode: **`--debug-regex`** reads one JSON request on stdin, answers on
stdout and exits, starting no listener and touching no rules. It is what
`POST /api/services/debug-regex` shells out to, so the in-app pattern tester is answered by
the engine that would enforce the answer rather than by an approximation that would bless
patterns hyperscan rejects. It reports `unscannable` for patterns that are valid, will run,
and cannot be highlighted — validity is judged in **stream** mode, which is the mode a
pattern actually runs in, while highlighting needs a block-mode scan that does not accept
quite the same language.

## Layout

| file | what is in it |
| --- | --- |
| `src/main.rs` | environment, startup handshake, the runtime, the stats ticker, `--debug-regex` |
| `src/filter.rs` | verdicts, the `Filter` trait, the chain and its isolation policy. `ChainHandle` swaps the chain under live connections |
| `src/rules.rs` | the filters the backend configures, and the JSON they arrive in |
| `src/hyperscan.rs` | the `libhs` binding: stream and block scanning, compilation, validation |
| `src/proxy.rs` | accept loop, the opening peek, TLS and ALPN, the limit, the byte pumps |
| `src/http1.rs` | **the** HTTP/1.1 rendering, and the traits both HTTP protocols implement |
| `src/h2.rs` | HTTP/2, on hyperium's `h2` |
| `src/h3.rs` | HTTP/3, on hyperium's `h3` |
| `src/h1up.rs` | HTTP/1.1 *towards the service*, on hyper's client |
| `src/quic.rs` | QUIC termination, streams, datagrams, the relay manager |
| `src/udp.rs` | datagram relays and per-flow state |
| `src/relays.rs` | the two-armed enum both relay kinds go through |
| `src/tls.rs` | termination, re-encryption, ALPN mirroring, the deliberately permissive upstream verifier |
| `src/transparent.rs` | `IP_TRANSPARENT`, `SO_ORIGINAL_DST`, the self-mark, the startup capability probe |
| `src/capture.rs` | the reconstructed packets written to `firegex0` |
| `src/pyworker.rs` | the child process running the user's Python, and its deadline |
| `src/control.rs` | the stdin channel, running alongside the datapath |
| `src/debug.rs` | `--debug-regex` |
| `src/spec.rs` | filters built from a text spec. Test scaffolding only |

Tests: `tests/fail_open.rs` (the guarantees above, over real sockets), `tests/rules.rs`
(matching, direction, grouping, order), `tests/pyworker.rs` (a hung worker killed, a
crashed one recovering), `tests/tls.rs`, `tests/quic.rs`, `tests/h2.rs`, `tests/h3.rs`, and
`tests/throughput.rs` (the matcher benchmark, `--ignored`).

## Building and testing

Built in the Dockerfile's `compiler` stage rather than in a `rust` image on purpose: it
links the same `libhs` the C++ binaries do, and a binary built against one distro's
vectorscan and run against another's is a bad afternoon.

```bash
docker build --target compiler -t firegex-compiler .
docker run --rm -v "$PWD/backend:/execute" -w /execute/proxysrc firegex-compiler cargo test
cd backend/proxysrc && cargo test            # on a host with libhs + fgex installed
cargo test --release --test throughput -- --ignored --nocapture
```

Mount `backend/`, **not** `backend/proxysrc/`: `tests/pyworker.rs` launches
`../modules/services/pyworker.py`, which imports `firegex`, which imports `brotli`. Without
both on `PYTHONPATH` the pyworker tests fail with a `ModuleNotFoundError` buried in captured
output and read as real failures. The repo's own `fgex-lib` has to come *first* on the path,
or a stale image's `firegex` wins.

The product-level suite is `tests/`, driven by pytest against a running instance;
`tests/integration/test_http_versions.py` and `tests/integration/test_grpc.py` are the two
that say whether the rendering in here really works.

## Measured against NFQUEUE

**The proxy is not the slow one, and the docs used to say it was.** Moving bytes it is
about **2.2× NFQUEUE at one thread and 4.7× at eight**: NFQUEUE pays a userspace round trip
*per packet*, while this pays once per connection and then the kernel moves the bytes. On
short connections the two are indistinguishable.

The numbers, the method and the corrections that produced them live in
[`tests/bench/README.md`](../../tests/bench/README.md) and `tests/bench/results/`, and that
is deliberately the only place they are written down — a table copied into a second file is
a table that will still be quoting a figure nobody can reproduce a year from now.

The trade between the two layers is **fail-open and transparency, not speed**. Keep
`docs/services.md`, `LayerChoice.tsx` and `transportSummary()` saying that.

## Backend side

`backend/modules/services/` holds the other half:

- `transports.py` — `ProxyTransport` starts this binary, reads the handshake, keeps the
  relay map and pushes the ruleset. `NfqueueTransport` and `ExternalTransport` are the
  other two layers, behind the same interface.
- `nftables.py` — the redirect, the divert rule and the return path, all in `table inet
  fgex`. `NAT_PRIORITY` is `-120`, below `dstnat`, so a container runtime's published port
  cannot rewrite the destination before firegex's rule matches it.
- `firewall.py` — one `ServiceManager` per service: the engine is started first because it
  is what picks the listening port, and the rules are written afterwards. Stopping goes the
  other way round.
- `pyworker.py` — the child process this engine spawns for a Python rule, and
  `--check`, which is what decides whether a filter can be saved at all.
- `mirror.py` — the `firegex0` device, created before any engine starts.
