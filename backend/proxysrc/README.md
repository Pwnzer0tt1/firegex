# Proxy datapath engine

An alternative engine to the NFQUEUE one in `backend/binsrc/`. Instead of lifting
packets to userspace and handing a verdict back to the kernel, it terminates the
connection and owns both halves.

Status: **working, and not yet the default anywhere.** A service can select it from
the Proxy Engine page, with regex and rewrite rules that apply to live connections,
Python filters run in a process of their own, and it has been measured against
nfregex. What it does not have is the C++ engine's parsed HTTP models.

The two questions that could have killed the approach outright — does it still fail
open, and does the service still see the real client — are answered below, and by
tests rather than by argument.

## What it has to prove first

The NFQUEUE engine fails open in the kernel: the nft rule carries `flags: ["bypass"]`
and the binary asks for `NFQA_CFG_F_FAIL_OPEN`. If firegex dies, stalls, or falls
behind, packets flow anyway. In attack/defense that is the difference between "the
filter didn't fire" and "I lost the SLA".

A userspace proxy has no such backstop: if the process dies, the socket dies with it.
So the property has to be rebuilt by hand, and it has to hold against user code that
is assumed to be broken:

| Failure | Handled by | Outcome |
| --- | --- | --- |
| Filter panics | `catch_unwind` on a blocking task | Chunk forwarded, filter disabled at once |
| Filter never returns | Deadline on the blocking task | Chunk forwarded, filter disabled after N in a row |
| Every filter disabled | `degraded` flag | Chain skipped entirely — no copy, no thread hop |
| Connection handler panics | One task per connection | That connection only; the listener lives |

The degraded path is deliberately the cheapest one. Failing open must not cost more
than working normally, or the failure mode becomes a second failure.

## What the proxy buys

- **Exact rewriting.** `Verdict::Replace` changes the payload length and the stream
  stays correct, because there are two independent TCP connections. On NFQUEUE the
  same operation desynchronises sequence numbers, which is why its action is still
  called `UNSTABLE_MANGLE` there — see `docs/pyfilter.md`.
- **Real connection metadata.** A filter is told the client's and the service's
  address and port once per connection (`ConnectionMeta`, sent as a `KIND_OPEN`
  frame), and can read nothing else below the application layer. That is more than a
  header could honestly say here: this engine terminated the connection, so the
  headers on the wire are its own.
- **Reassembly from the kernel**, instead of `StreamFollower` and the out-of-order
  caveat that comes with it.
- **Backpressure for free.** A slow filter slows the sender through TCP flow control
  rather than overflowing a fixed-size queue and dropping packets.
- **Clean closes.** A rejected connection is shut down properly instead of leaving
  the peer to infer something from missing packets.

## The limitation that decided the design

A blocking filter thread **cannot be cancelled**. When one blows the deadline the
engine walks away, but the thread lives until its own code decides to stop — it holds
a blocking-pool slot until the process restarts. The damage is bounded (a filter that
times out repeatedly is disabled and never called again;
`hanging_filter_fails_open_then_loses_its_say` asserts the leak stops growing), but
bounded is not zero.

That is why user Python runs **out of process**: a hung worker can be killed, a hung
thread cannot. It also keeps `libpython` out of the datapath binary, which is where a
good share of the C++ engine's complexity lives. Nothing shipped now relies on the abandoned
thread path — regex rules run inline, the Python worker enforces its own deadline —
but the machinery stays, because it is what a future in-process filter would need.

## Rules

One JSON line on stdin carries the whole ruleset, one `ACK OK` / `ACK FAIL <why>`
line comes back — the same shape `cppregex` uses for its filter codes. Blocks are
reported as `BLOCKED <rule id>` so the backend can attribute them.

```json
[{"kind":"regex","id":"r1","pattern":"FLAG\\{[a-z]+\\}","direction":"s2c"},
 {"kind":"replace","id":"r2","pattern":"secret","with":"[redacted]"}]
```

Two decisions worth knowing:

- **A rejected ruleset changes nothing.** One bad pattern refuses the whole update
  and the previous rules keep enforcing. Failing open covers a filter that breaks at
  runtime; it is not a licence to quietly drop rules the operator asked for. The
  backend mirrors this: a rule the engine will not compile is removed again rather
  than left sitting in the list looking active.
- **`regex` matches the window, `replace` matches the chunk.** Matching the chunk
  alone would miss a pattern split across two reads, which is the evasion nfregex
  reassembles the stream to prevent. Rewriting the window instead of the chunk would
  resend bytes that already left. The per-direction window defaults to 1MB
  (`FGEX_PROXY_STREAM_WINDOW`) — that is the longest pattern that can still be caught
  across a boundary, and every byte of it is rescanned per chunk, so it is a
  throughput knob rather than a buffer. It belongs to one connection: one client's
  traffic can never complete another's pattern.

A block closes the **connection**, not the direction. Half-closing would let a
service that answers without waiting for the request still reach a client whose
request was refused — found by the suite, not by reading.

## Python filters

The thing the C++ engine has and this did not. It runs in a **child process**, and that is
the whole point rather than an implementation detail: the engine's own deadline can
only walk away from a blocking thread, which then holds a pool slot until the process
restarts. A child that misses its deadline is killed and respawned on the next chunk,
and the chunk it was holding is forwarded. `tests/pyworker.rs` asserts exactly that.

The API is the one a pyfilters user already knows:

```python
from firegex.pyfilters import pyfilter, ACCEPT, REJECT

@pyfilter
def block_path_traversal(data: bytes, direction: str):
    return REJECT if b"../" in data else ACCEPT
```

What a filter is handed is different, and deliberately so: a chunk of the stream and
a direction, not one of the C++ engine's parsed models. `HttpRequest` and friends are
the C++ engine's, and they are not here. The import is shimmed to resolve to the worker
rather than to an installed `fgex`, because the decorator has to register into this
worker and borrowing the names without the models would be the confusing option.

Frames are length-prefixed binary on the worker's stdin/stdout, tracebacks go to
stderr where the backend already reads them. The worker announces itself once it has
executed the user's file, which is what lets a ruleset carrying code that does not
load be **refused when it is applied** instead of discovered later as traffic that
quietly stopped being filtered — the backend then puts the previous file back.

One worker per rule, one conversation at a time. Serialising is the honest simple
thing while a frame is a request and a response; a pool is the next step if Python
filtering ever becomes the bottleneck.

## TLS

The engine terminates it. It decrypts from the client, the rules see plaintext that never
leaves the process, and it re-encrypts on the way out — `rustls`, so there is no OpenSSL
in the build either.

What that replaced was nginx: one listener terminating the public connection and
forwarding plaintext to a second loopback port, which re-encrypted towards the real
service, with the filter engine attached to the leg in between. It worked, and it cost a
config generated per stream, **a pair of ports derived from hashing `ip:port`**, and one
hop where the traffic was in the clear.

The ports are what settled it. They were chosen rather than assigned, so they could
collide with something the operator was actually running, and a service was protected on
them rather than on the address the world dialled. Terminating here means a TLS service
occupies no port that a plain one does not.

The argument that this removes the hop in the clear is *not* the argument, and was worth
retiring: reading loopback on the box means already having code on the box.

The upstream certificate is **not verified**, mirroring the `proxy_ssl_verify off` nginx
was configured with. That is the right call rather than laziness: the service on the
other side is the thing firegex is defending, it is behind loopback or a private link,
and in a competition it is invariably self-signed. Verifying it would only ever refuse to
protect it.

Certificate and key reach the engine as **paths**, never as environment values: a private
key in an env dump is a private key in a log. The API reports whether TLS is on and never
returns the material.

The key has to be one `ring` will sign with — RSA of at least 2048 bits, ECDSA, or
Ed25519. nginx could be told to accept a smaller RSA key with `@SECLEVEL=1`; rustls has
no equivalent, and a service carrying one is refused at startup with the reason.

One thing the NFQUEUE binaries never need, because they never open a second connection:
on a path where both ends are local, `nat prerouting` is never consulted, and an intercept
in `nat output` would catch the engine's own dial and loop it back into itself. So the
engine stamps `SO_MARK` on every connection it opens and the intercept rules skip it.

### Where the plaintext goes

Terminating in-process means the decrypted traffic is never a packet, so there is nothing
for a capture tool to read — which would have been a real loss along with the ports. So
`capture.rs` writes it out: each connection's plaintext framed as the TCP stream it was,
sent over `AF_PACKET` to a dummy interface (`firegex0`) that carries every TLS service's
plaintext and nothing else.

They are **reconstructed** packets. The bytes are real — what the rules saw, and what was
forwarded after any rewrite — but the framing is built here, because the framing on the
wire was encrypted: sequence numbers from zero, no retransmissions, segmentation from
this engine's read sizes. A SYN and a FIN are emitted so a capture tool has a stream to
follow rather than orphan segments.

Every failure is silent and local. No interface, no socket (it needs `CAP_NET_RAW`), a
send that fails — the traffic goes on exactly as it would have. A capture aid must never
be able to interrupt the service it is watching.

## Measured against nfregex

`tests/proxy_benchmark.py` runs both engines on the same host with the same iperf3
workload and the same patterns, adding rules one at a time — the method
`benchmark.py` already uses, with both binaries driven directly so it needs no
firegex instance. Figures below are MB/s on one machine; the interesting part is the
ratio, not the absolute number.

| Rules | Proxy engine | nfregex (NFQUEUE) | Proxy + a Python filter |
| --- | --- | --- | --- |
| none | ~7600 | ~2450 | ~1310 |
| 1 | ~4300 | ~2100–2700 | ~1200 |
| 5 | ~2900 | ~2300–2800 | ~1140 |
| 10 | ~2880 | ~2400–3300 | ~1200 |

A Python filter costs roughly another halving and then stops mattering: every chunk
is a round trip to a child process, and the regex rules that run alongside it are
free by comparison. It is the price of being able to kill a filter that hangs, and at
~1.2 GB/s it is far above what any service in a competition will offer.

TLS is measured apart, with its own client, because iperf3 does not speak it — only
the ratio between the two rows means anything:

| Through the engine | MB/s |
| --- | --- |
| plaintext | ~6900 |
| TLS terminated and re-encrypted | ~1450 |

Both handshakes and AES on both legs, for about a fifth of the plaintext figure. That
is the cost of the engine doing the crypto rather than nginx — worth knowing before
choosing which of the two TLS paths to take, though it is not what should decide it.

Moving bytes, the proxy is about **3x faster**: the kernel does the reassembly and
there is no per-packet round trip to userspace. With rules the two are **comparable** —
nfregex's readings swing widely enough that claiming a winner at 10 rules would be
reading noise.

Getting there took two corrections that the benchmark, not review, made obvious:

- The first version rescanned a 1MB rolling window with every rule on every chunk.
  Throughput fell with each rule added — 100 MB/s at ten rules, against nfregex's
  2400 — while hyperscan on the other side did not move. Fixed by scanning only the
  new bytes plus a bounded overlap, and by compiling all the patterns that share a
  direction and a case setting into **one** `RegexSet`.
- After that, one rule still cost 4x the throughput of none. The cost was not the
  matching: it was the thread hop and the copy that every filter paid so that user
  code which hangs cannot stall the datapath. A compiled regex cannot hang, so it now
  declares `may_block() == false` and runs inline against the relay's own buffers.
  That took ten rules from 1264 to ~2950 MB/s.

The deadline machinery is still there, and still the default: it is what Python
filters will need. It is simply no longer charged to filters that cannot use it.

## Layout

- `src/filter.rs` — verdicts, the `Filter` trait, the chain and its isolation policy.
  `ChainHandle` swaps the chain under live connections so reconfiguring costs nobody.
- `src/proxy.rs` — accept loop, upstream selection and the two relay pumps.
- `src/transparent.rs` — `IP_TRANSPARENT`, original-destination recovery, and the
  startup capability probe.
- `src/rules.rs` — the filters the backend configures, and the JSON they arrive in.
- `src/pyworker.rs` — the child process running the user's Python, and its deadline.
- `src/tls.rs` — termination and re-encryption, and the verifier that deliberately
  accepts what the protected service presents.
- `src/control.rs` — the stdin/ACK control channel, running alongside the datapath so
  a rule change never gates traffic.
- `src/spec.rs` — filters built from a text spec: `panic`, `hang` and friends. Test
  scaffolding only, so the Python suite can ask for a filter that misbehaves without
  linking against the crate.
- `tests/fail_open.rs` — the guarantees above, over real sockets.
- `tests/rules.rs` — matching, direction, rewriting, grouping, and the boundary cases.
- `tests/pyworker.rs` — a hung worker being killed, a crashed one recovering.
- `tests/tls.rs` — decrypt, inspect, re-encrypt, and rules seeing the plaintext.
- `../../tests/proxy_benchmark.py` — the comparison above.
- `../../tests/proxy_engine_test.py` — the same guarantees from outside the process.
- `../../tests/proxy_transparent_test.py` — transparency, in three network namespaces.

## Source-IP transparency

The service has to keep seeing the real client, or everything that logs, rate-limits
or bans by address starts seeing one address for the whole internet. `transparent.rs`
covers both halves:

- **Where was the client going?** Under `tproxy` the kernel leaves the original
  destination as the accepted socket's own local address. Under dnat/redirect — the
  shape `porthijack` already uses — it survives only in conntrack, so it is fetched
  with `SO_ORIGINAL_DST`. Both modes are implemented; `FGEX_PROXY_INTERCEPT` picks one.
- **Dial the service as the client.** `IP_TRANSPARENT` on the outbound socket, bound
  to the client's address with a kernel-chosen port.

`CAP_NET_ADMIN` is checked at startup, because a missing capability would otherwise
surface only as every service quietly seeing the proxy's address. If a transparent
dial fails at runtime the proxy falls back to its own address — traffic beats
identity — but counts it and says so once, loudly.

### The ruleset tproxy needs

Proven by `tests/proxy_transparent_test.py`, for a service outside this namespace.
Rule order is not cosmetic: replies addressed to a client we are impersonating belong
to an existing transparent socket and must be diverted **before** the forwarding
decision sends them back out. The next section covers the on-host case, which the
redirect intercept handles differently.

```
nft add rule ip <t> pre socket transparent 1 meta mark set 0x1 accept
nft add rule ip <t> pre iif <wan> tcp dport <svc> tproxy to :<proxy> meta mark set 0x1

ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

The `local` route is what makes marked packets be delivered here instead of routed by
destination. Without it a spoofed connection does not fail, it hangs — which is why
the test asserts a completed round trip and not just the address the service reports.
The same route serves the redirect intercept; only the divert rule differs.

## Preserving the client address

The service must keep seeing the real client, or everything that logs, rate-limits or
bans by address starts seeing one address for the whole internet. The proxy dials the
service from the client's address; the work is in getting the reply back.

With the service on this same host, two flows look almost identical:

| Flow | src | dst | must |
| --- | --- | --- | --- |
| Proxy answering the client | `service:port` | `client:client_port` | leave the box |
| Service answering the proxy | `service:port` | `client:<ephemeral>` | stay local |

No address tells them apart — only an ephemeral port chosen at connect time, which
nothing can be written against. **Conntrack can**: the first belongs to the
intercepted, DNATed connection, the second is a separate entry the proxy opened
itself. So the output chain reads

```
ct status dnat accept                     # the proxy answering a client: let it out
ip saddr <svc> tcp sport <port> mark set  # anything else from the service: bring it home
```

and the marked packets are delivered locally by the usual `fwmark` rule plus a
`local` default route. That is what makes source preservation work in the topology
firegex actually runs in, with no namespace of its own and no tproxy.

The tproxy intercept creates no NAT entry and so has no such marker: there, a divert
rule broad enough to catch the service's reply also reroutes the proxy's own SYN-ACK
away from the client, and the connection hangs rather than fails. That was measured.
`modules/proxyengine/routing.check_topology` refuses the combination up front, so it
is an error at start instead of a stall under load, and points at the mode that does
work.

| | intercept reaches proxy via | preserves client IP | needs `ip` | service on this host |
| --- | --- | --- | --- | --- |
| `redirect` | conntrack NAT + `SO_ORIGINAL_DST` | optional | only with preserve | yes |
| `tproxy` | `tproxy to :port` | optional | always | no |

## Running it

No Rust on the host? Build and test in a container:

```bash
docker run --rm -v "$PWD/backend/proxysrc":/w -w /w rust:1-slim cargo test
```

End-to-end against the built binary, reusing the existing test helpers:

```bash
docker run --rm -v "$PWD":/repo -w /repo/tests python:3-slim python3 proxy_engine_test.py
```

Transparency needs a real kernel, root and nftables, so it runs privileged:

```bash
docker run --rm --privileged -v "$PWD":/repo -w /repo/tests fedora:44 sh -c \
  "dnf install -y python3 nftables iproute >/dev/null && python3 proxy_transparent_test.py"
```

Neither test is in `run_tests.sh` yet: they need no running firegex instance, CI does
not build this binary, and the transparency one rewrites the host's routing rules —
the same reason `ipfilter_test.py` is run on its own. They join the suite when the
Dockerfile builds the engine and a service can select it.

## Backend side

`backend/modules/proxyengine/` follows the per-module shape the other modules use:

- `models.py` — `Service`, with `intercept` selecting the trade-off above.
- `nftables.py` — the ruleset, in the shared `firegex` inet table. One `filter`
  prerouting chain (divert + tproxy intercepts) and one `nat` prerouting chain
  (redirect intercepts). The divert rule is installed once by `init()`, never
  per service, and per-service rules append after it so it stays first.
- `routing.py` — the policy routing tproxy needs, plus the two guards: `check()` for
  a missing `ip` binary, `check_topology()` for the namespace constraint.

- `firewall.py` — the `ServiceManager`/`FirewallManager` pair. One engine process per
  service: it is started first because it is what picks the listening port (bind to 0,
  read `PORT <n>` back, the same handshake `cppregex` uses for `QUEUE <n>`), and the
  rules are written afterwards. Stopping goes the other way round.

`routers/proxyengine.py` mounts it at `/api/proxyengine` through the usual
auto-discovery, with its own `db/proxy-engine.db`. Its own module and its own DB
file on purpose: adding a field to an existing module's schema would wipe that
module's database, since `utils/sqlite.py` recreates rather than migrates.

The Dockerfile builds the engine in a `proxyengine` stage and ships it next to
`cppregex`/`cpproxy`, and the runtime image now installs `iproute` for the return-path
rules. `FGEX_PROXY_BINARY` overrides the path for a dev build.

## Next

1. The C++ engine's parsed models (`HttpRequest` and the rest), so a filter can work above
   raw bytes.
2. A worker pool, if Python filtering turns out to be a bottleneck.
3. Deciding whether the TLS module keeps its nginx. Everything it does is now possible
   here; retiring `modules/tls/nginx.py` would be the first change in this whole line
   of work that removes more code than it adds, and it is a product decision rather
   than a technical one.
