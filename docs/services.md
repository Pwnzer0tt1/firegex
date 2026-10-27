# 🛡️ Services

A **service** is one thing you are protecting, described in two independent parts:

```
  filters          regex (hyperscan)  ·  pyfilter (Python)              what to do with it
  network layer    NFQUEUE            ·  proxy  ·  your own proxy       how to get hold of it
```

You choose each separately. Filters run in the order you put them, and you can change
either part without recreating the other.

## Addresses

A service has a **list of addresses**, so a daemon answering on IPv4 and IPv6, or on a
public and an internal address, is protected by one chain instead of copies that drift
apart. Adding an address to a running service **drops no connections**.

An entry is an IP (`192.168.1.10:80`, `::1:80`), a CIDR (`10.0.0.0/24:8080`) or a
**network interface** (`eth0:80`, `wg0:8080`, `lo:80`). Use an interface when someone else
hands out the address — a VPN, a DHCP lease, a tunnel that comes up mid-round — and the
rules follow whatever address the link carries. The address doesn't have to exist on this
host yet.

How an interface is matched depends on the layer:

- **NFQUEUE** — `iifname` in prerouting and `oifname` in postrouting; anything crossing the
  link on that port is queued.
- **Proxy, TCP/TLS** — traffic arriving on the link is redirected. Traffic this host sends
  to the link's own addresses is redirected too, so protecting `lo` also covers a client on
  the box. **A link protects everything crossing it on that port**, including traffic only
  passing through: protecting `docker0:443` also catches every container's outbound HTTPS,
  which then fails certificate checks. To protect only what is addressed to this host, use
  the address instead of the link.
- **Proxy, UDP** — the relay binds to the interface's primary address; an interface with
  no address needs NFQUEUE.
- **Your own proxy** — IP addresses only.

On TCP, a new address the interface gains is matched for outside traffic right away.
For traffic the host sends itself, and for UDP relays, it's covered after the next restart.

### Per-address options

The **⚙ button on an address** opens the options that apply to that service:

| Option | Offered on | What it does |
|---|---|---|
| **What clients speak here** — clear · TLS · HTTP/3 | HTTPS services | What this address is |
| **The service is on another port** | proxy layer | Clients arrive here; firegex dials the service on that port |
| **Send to the service** — what arrived · plaintext · TLS | addresses firegex decrypts | What firegex speaks to the service (see [below](#what-the-service-behind-speaks)) |
| **Hand it to your proxy at** | your-own-proxy layer | Where your proxy listens for this address |

Whatever you set appears as a tag under the address; click the tag to change it. Every
option can be edited later from the pencil on the service page. Editing an address
reroutes only that address, and if the edit is refused, nothing changes.

**An address is a way in.** To reach a cleartext service on `:80` over TLS on `:443` too,
add a second address `:443` that points at `:80`. Don't add `443` as an option on the
`:80` address: that intercepts `:80` and publishes nothing new. A complete example:

| Address | Clients speak | Sent on to | Sent as |
|---|---|---|---|
| `10.0.0.1:80` | clear | — | what arrived |
| `10.0.0.1:443` | TLS | `:80` | plaintext |
| `10.0.0.1:4433` | HTTP/3 | `:80` | plaintext |

One chain covers all three. The service keeps speaking HTTP/1.1 on `:80` and needs no
certificate; only firegex holds one.

- On a published address the service sees a connection to `:80` (still from the client's
  own IP) rather than to the port the client dialled.
- **Declaring TLS is enforced**: a cleartext client on a TLS address is refused. *Clear* is
  permissive and still terminates a client that brings TLS.
- "Another port" is proxy-only. NFQUEUE doesn't open connections, and your own proxy
  decides where the service is, so on those layers the option is refused.

## Protocol

One choice per service, asked in the form as *Is the traffic encrypted?* and then
*which protocol?*:

| | Pick it for | Filters are shown | Needs |
|---|---|---|---|
| **TCP** | anything unencrypted on TCP, including plain web services | the bytes; HTTP/1.1 parsed, cleartext HTTP/2 (`h2c`) rendered as HTTP/1.1 | addresses |
| **UDP** | game servers, DNS, anything datagram-based | one datagram at a time, `RawPacket` only | addresses |
| **TLS** | a port where everything is encrypted | the decrypted stream | certificate + key, proxy layer |
| **QUIC** | a QUIC service, usually HTTP/3 | each stream as its own connection; HTTP/3 rendered as HTTP/1.1 | certificate + key, proxy layer |
| **HTTPS** (`http` in the API) | one web daemon reached several ways — `:80`, `:443`, `:443/udp` | every HTTP version as HTTP/1.1, gRPC included | certificate + key, proxy layer |

**A plain web service is TCP.** Decrypting means terminating the connection, so TLS, QUIC
and HTTPS are available on the proxy layer only.

## Network layers

The two inspecting layers differ in what happens when a filter dies, not in speed. The
proxy is actually faster.

|  | **Proxy** | **NFQUEUE** |
|---|---|---|
| Unit of work | a connection | a packet |
| Client address | kept: dials your service from the client's IP (not its source port) | kept: the real packets |
| Reassembly | the kernel's | userspace (libtins) |
| If a filter dies | the engine fails open (hand-built) | **the kernel keeps forwarding** |
| Cost | terminating each connection once | a userspace round trip per packet, per filter |
| Throughput ([how](../tests/bench/README.md#performance)) | **4035 MB/s** at 1 thread, **13 984** at 8 | 1820 at 1 thread, 2956 at 8 |
| Short connections | about the same | about the same |
| UDP | yes, transparent | yes, transparent |
| TLS / QUIC / HTTPS | yes | no |
| Connections open before the service started | not filtered (they keep going until they close) | filtered from their next packet |

Neither layer rewrites traffic: filters answer with a verdict.

### Proxy

The connection is terminated and reopened towards your service. You get kernel
reassembly, TCP backpressure (a slow filter slows the sender instead of dropping packets),
and a chain of any length for the cost of one interception.

Fail-open is enforced by the engine: each filter has a deadline, and one that misses it
repeatedly (usually a Python filter under a flood) is skipped for 30 seconds, then tried
again. A filter that crashes is skipped until you next save a change to the chain.

The service always sees the **client's IP**, on TCP and UDP. The source port is lost, and
a reset from either end arrives at the other as a normal close.

**Containers work as-is.** Protect the published port (`docker run -p 8080:80` → this
host, `8080`). Firegex's rules run before Docker's rewrite, on either layer, for clients
on other hosts and on this one.

### NFQUEUE

Packets are lifted to userspace and a verdict is handed back; nothing is terminated. If a
filter panics, hangs or crashes, **the kernel keeps forwarding**. The service sees the
original packets. Connections already open when a service starts or a filter is added are
inspected from their next packet.

The costs are a userspace round trip per packet, userspace reassembly, and one process per
filter in the chain.

### Your own proxy

Firegex rewrites the destination to a proxy you run yourself, and rewrites it back on the
way out, so your proxy sits invisibly in the path. Use it for protocols nothing built in
understands. No firegex process is involved, so filters can't be attached. Each address
takes an IP (not an interface) and its own proxy endpoint.

### UDP on the proxy layer

Each protected address gets its own relay socket.

- The service sees the client's real address and port.
- Each client address is a **flow** with its own filter state and its own Python globals.
  UDP has no close, so a flow is released after a minute of silence.
- Both directions are inspected. A slow verdict for one client doesn't hold up the others.
- Relays only answer redirected traffic. A datagram sent straight to a relay port is
  dropped.
- Flows that were open before a start, a restart or an engine crash are moved to the
  current rules on their next datagram. QUIC connections stay with the engine carrying
  them until they close.

`REJECT` here drops that datagram; the next one is judged afresh.

### Connection limits

Under **Advanced settings** (proxy layer) a service can be given:

- **A connection limit** — one number covering TCP connections, QUIC connections and UDP
  flows. Past it, **refuse** (default) or **forward unfiltered**. A limit doesn't save the
  service under attack, since an attacker can still fill it. What it does is keep one
  attacked service from exhausting file descriptors for every other service. Hitting the
  limit is logged as a warning and counted on the service page, with first and last times.
- **A first-byte deadline** — close a connection on which *neither side* has sent anything
  after N seconds. A server banner counts, so SMTP, SSH and similar protocols are safe. It
  only applies before the first byte, so it is not an idle timeout. `0` (the default) turns
  it off.

On NFQUEUE, for a UDP service only, the same limit caps how many flows keep their Python
state. Past it, the flow that has been quiet longest is reset.

## TLS

Give the service a certificate and key: paste them, pick files, or drop files onto the
fields. The engine decrypts, the filters see plaintext, and the traffic is re-encrypted
towards your service, all in the filtering process. **No extra port is used.** The key is
never sent back to the browser, so the fields are empty when you edit; leave them empty to
keep the stored ones.

- **ALPN is mirrored**: the service is offered exactly the client's list, and the client
  is told what the service picked, or nothing if the service picked nothing.
- **TLS 1.2 and 1.3 only**, on each leg independently. TLS 1.0/1.1, legacy ciphers and
  client certificates (mTLS) aren't supported. For those, keep firegex out of the path
  (your-own-proxy layer, or NFQUEUE filtering the ciphertext).
- The key must be RSA ≥ 2048, ECDSA or Ed25519. A smaller key is refused at start, with
  the reason in the log.
- The client's SNI is passed on to a TLS upstream.

### What the service behind speaks

Set per address, only where firegex decrypts:

| | |
|---|---|
| **What arrived** (default) | Speak to the service the way the client spoke to firegex |
| **Plaintext** | Send HTTP/1.1 in the clear. **Only firegex needs a certificate** |
| **TLS** | Send HTTP/1.1 over the service's own TLS, whatever the client used |

With *plaintext* or *TLS*, ALPN is no longer mirrored: over TLS the client settles on
HTTP/1.1, and over QUIC firegex itself answers `h3`. **Stopping firegex stops the
encryption**, since firegex was providing it.

HTTP/3 to a plaintext HTTP/1.1 service works: each QUIC stream is one request and gets its
own connection to the service, still from the client's address. Non-HTTP/3 QUIC can't be
sent to an HTTP/1.1 service.

### HTTP/2 and gRPC

HTTP/2 compresses headers (HPACK), so firegex terminates it and shows the chain each
exchange as HTTP/1.1, the same rendering HTTP/3 gets. **One pattern or Python file covers
HTTP/1.1, HTTP/2 and HTTP/3.** Cleartext HTTP/2 (`h2c`) is recognised on a plain TCP
service from its connection preface.

gRPC is HTTP/2. The method is the path, the metadata are headers, and the status is a
trailer. For message bodies, see [`GrpcMessage`](pyfilter.md#grpc-messages--http-only).

Not handled:

- the HTTP/1.1 `Upgrade: h2c` handshake (deprecated, and practically unused);
- server push (turned off in the handshake);
- `CONNECT` and extended CONNECT / WebTransport.

**Each HTTP/2 stream is its own connection to a filter**, with its own globals. This
differs from HTTP/1.1 keep-alive, where many requests share one connection's state.

### Watching the decrypted traffic

The decrypted traffic of every TLS and QUIC service is written to one interface:

```bash
sudo tcpdump -i firegex0 -w decrypted.pcap
```

Run this on the host. The bytes are exactly what the filters saw, but the TCP framing is
**reconstructed**: sequence numbers start at 0, there are no retransmissions, and on QUIC
the client port is made up per stream. Treat the capture as being as sensitive as the
private key. Writing it needs `CAP_NET_RAW`; without it firegex still runs and just has no
capture.

## QUIC

QUIC encrypts even its framing, so it can only be filtered by terminating it. That makes
it proxy-only. It needs a certificate and key, as TLS does.

- **Each stream is its own connection to the chain**, with its own state. On HTTP/3 that
  means one request per stream.
- **A refusal closes the whole connection**, not just the stream, and the client is told
  why.
- **ALPN is read from the client's Initial packet** and mirrored, so HTTP/3, DoQ or a
  custom protocol need no configuration. If a hello can't be read, firegex offers `h3`
  and logs it.
- **HTTP/3 is shown to filters as HTTP/1.1.** The request line says `HTTP/1.1`, `Host`
  comes from `:authority`, a declared length becomes `Content-Length`, and an undeclared
  one becomes chunked (decided within 100 ms). Trailers are always shown. On a message
  with a declared length, trailers are dropped with a log line, because they could not be
  shown. What goes on to the service is HTTP/3 again.
- **QUIC datagrams** reach filters as `RawPacket`, one flow per connection. A refused
  datagram is dropped and the connection continues. They aren't carried on HTTP/3, and
  WebTransport isn't supported.
- **No 0-RTT**: early data can be replayed. A new client address gets a **Retry** to
  prove it's real.
- Forwarding past the connection limit still terminates QUIC. It only skips the
  inspection.

## HTTPS: every version through one chain

`http` (labelled **HTTPS**) describes the service rather than the wire. Its TCP addresses
carry HTTP/1.1 and HTTP/2, in the clear or under TLS, decided per connection. Its UDP
addresses carry HTTP/3. One service, one chain, one certificate, instead of copies kept
in step by hand.

What leaves matches what arrived: cleartext is forwarded in the clear, TLS is
re-encrypted. A per-address [upstream choice](#what-the-service-behind-speaks) can turn
every edge into plain HTTP/1.1.

A certificate is required even for the cleartext addresses. A cleartext-only web service
should be a TCP service. Everything above about TLS and QUIC limits applies here too.

## Filters

### Regex

Patterns matched by [hyperscan](https://github.com/VectorCamp/vectorscan), the same
engine on both layers. All patterns in one filter compile into a single database, so fifty
patterns cost about the same as one. Matching is **stateful per connection**: a pattern
split across packets is still caught.

Each pattern has a direction, and a match **blocks** the connection:

```
FLAG\{[a-z0-9]+\}   service → client   block
X-Debug: [^\r\n]*    client → service   block
../                  both ways          block
```

Patterns can be edited in place. Changing the pattern text resets its counter, and its
past blocks stay in the filter's history. Other changes keep the counter. Each pattern is
checked by the engine before it is saved.

Patterns can't rewrite traffic. Rewriting one chunk at a time silently missed matches
split across chunks.

### Python (pyfilter)

Your own code, written against the [`firegex`](https://pypi.org/project/firegex/) library.
See [pyfilter.md](pyfilter.md). On the proxy layer it runs in its own process, so a hang
is killed instead of stalling traffic. On NFQUEUE it runs in an embedded interpreter.

- Each `@pyfilter` function in a file gets **its own switch** and block counter. Switching
  one off doesn't touch the code. Saving a new version keeps your switches for the
  functions that are still there.
- **The protocol comes from the code.** Asking for an `HttpRequest` makes it an HTTP
  filter, and asking only for `RawPacket` lets it run on anything. A file asking for two
  different application protocols is refused.
- On UDP, only `RawPacket` filters are accepted.
- Filters read addresses, ports and direction as read-only metadata. They return a
  verdict and change nothing.

## Testing a pattern

The **try** button on a regex filter opens a tester that runs **the same engine that will
enforce the rule**. If it accepts a pattern, you can save it; if it rejects one, it gives
hyperscan's reason. Patterns are validated in streaming mode, the mode they run in.
Occasionally a valid pattern can't be highlighted, and the tester says so.

### Without an instance

```bash
pip install -U firegex
fgex regex check rules.json                    # does it compile?
fgex regex test  rules.json --sample req.txt   # what would it do to this?
fgex regex proxy rules.json 10.60.3.1 8080     # a local proxy applying it
```

```json
[
  {"id": "traversal", "pattern": "\\.\\./", "direction": "c2s"},
  {"id": "flag-leak", "pattern": "FLAG\\{[a-z0-9]+\\}", "direction": "s2c",
   "case_sensitive": false}
]
```

It uses the same hyperscan, and stops if `libhs` is missing. `fgex regex proxy` matches
**per chunk**, while a live service matches across the stream, so it can miss a split
match that production would catch, but never the reverse.

## Statistics

The service page shows **which rule is doing the work** (each filter, pattern and
function, with its share of all blocks), **when** it happened (a timeline), and **how much
traffic** there was.

- **Window**: 15 min, 1 h, 6 h, 24 h, everything kept (48 h), or two exact instants.
  Everything on the page uses the same window. The lifetime total is shown beside it.
- **Step**: *Auto* widens the bars with the range. A fixed step makes two windows easy to
  compare.
- **Shape**: bars, lines, stacked area, or share. Hover to read a step's exact numbers.
- A window never starts before the service began filtering. A service that was stopped
  for a while shows a real gap.
- **Traffic**: NFQUEUE and the your-own-proxy layer report packets and bytes, counted by
  the kernel. The proxy reports connections seen and refused, so its refused share is
  exact. Each layer shows only what it can measure.

## The live log

Each service page has a live log showing:

- what blocked each connection, by name (`refused by patterns: /BLOCKME/`,
  `refused by http: refuse_traversal()`);
- whatever your Python `print()`s;
- engine health: a filter skipped after missing its deadline, a refused ruleset, a
  restart.

Warnings and errors also pop up as a notification anywhere in the interface (one per
service every 20 s), and the service row shows a badge for an hour. Clearing the log
dismisses it. The log is bounded, so a flood of blocks can't take anything down.

## Editing while it runs

- Adding, removing, reordering or toggling filters, patterns and functions **drops no
  connections**. An edit only resets state for the filter that was edited.
- On NFQUEUE, adding, removing or reordering a *whole filter* rebuilds the process chain.
  Traffic passes unfiltered for that moment, and open connections are picked up again.
- A filter that joins a connection mid-message (for example, a half-finished upload)
  leaves that direction's HTTP filters out until the connection closes, rather than
  refusing a valid request.
- Adding an address drops nothing. Removing or changing one affects only that address.
- Changing the protocol, layer, TLS or limits restarts the service. **Stopping or
  restarting doesn't cut open connections**: on the proxy the old engine keeps carrying
  them (unfiltered after a stop, under the old filters after a restart) for up to 10
  minutes. Only shutting firegex down cuts them immediately.

## See also

- [Python filters](pyfilter.md)
- [Firewall rules](firewall.md)
