# 🛡️ Services

A **service** is one thing you are protecting, described in two independent parts:

```
  filters          regex (hyperscan)  ·  pyfilter (Python)              what to do with it
  network layer    NFQUEUE            ·  proxy  ·  your own proxy       how to get hold of it
```

You choose each one separately. Any filter runs on any network layer that can host it,
in whatever order you put them, and you can change either without recreating the other.

## Where a service is

A service has a **list of addresses**, not one. The same daemon routinely answers on more
than one — a v4 and a v6 address, a public and an internal one, two ports of the same
process — and all of them deserve the same chain. Add them when you create the service or
afterwards, mixing address families — and interface names — freely.

Adding an address to a running service **drops nothing**: the datapath is already up and
already enforcing the chain, so all that happens is that one more address is pointed at
it. On TCP and TLS the listener is dual-stack from the start, so adding IPv4 or IPv6
addresses requires no restart. On UDP, a dedicated relay is created dynamically on the fly
without interrupting existing traffic.

The alternative — one service per address, with the chains copied between them — is how
one of them silently stops being protected the first time a pattern is added to the other.

### What one address can say

An address is normally **where the service is**: firegex intercepts what the client
dialled and dials it back as the client, so the service sees the connection it would have
seen. That is what transparent means here, and it is what every address does unless you
say otherwise.

Everything else lives behind the **⚙ button on the address**, and only what applies to
the service being configured is offered:

| | When it is offered | What it does |
|---|---|---|
| **What clients speak here** — clear · TLS · HTTP/3 | HTTPS services, on the row itself | Not an extra: it is what the address *is* |
| **The service is on another port** | the Proxy layer | Clients arrive at this address; firegex dials the service on that port instead |
| **Send to the service** — what arrived · plaintext · TLS | any service firegex decrypts | What firegex speaks to the service, which need not be what the client spoke. *Plaintext* is what puts an ordinary cleartext site behind HTTPS, HTTP/2 and HTTP/3 with only firegex holding a certificate |
| **Hand it to your proxy at** | the hand-off layer | Where your own proxy is listening for this address |

What is set is repeated back under the address as a **tag**, and clicking a tag opens the
panel it came from. Folded is not hidden: an option you cannot see you set is one that
will surprise you at the worst moment. The same tags are shown beside the address on the
service's page, in the same words, and open the same settings.

**An address is a way in, and one more way in is one more address.** The option above is
not "also expose it on :443" — it says the opposite thing: *clients arrive here, and the
service is over there*. So a cleartext service on `:80` reached over TLS on `:443` is two
addresses, `:443` carrying the option that points at `:80`, and not one address on `:80`
with `443` typed into it. Written that way round it is intercepted where it already
listens and published nowhere, which is the one mistake this option makes easy.

*The service is on another port* is the Proxy layer's rather than any protocol's: that layer
terminates the connection and opens the one to the service, so it is free to open it
somewhere else. NFQUEUE passes judgement on packets already on their way and opens
nothing; the hand-off layer gives the traffic to the proxy you run yourself, which decides
for itself where the service is. On both it is refused rather than stored, because a port
nothing reads would tell you your service is published while it is merely intercepted.

So a service answering HTTP/1.1 in the clear on `:80`, and nothing else, is three rows:

| Address | Clients speak | Sent on to | Sent as |
|---|---|---|---|
| `10.0.0.1:80` | clear | — | what arrived |
| `10.0.0.1:443` | TLS | `:80` | plaintext |
| `10.0.0.1:4433` | HTTP/3 | `:80` | plaintext |

Firegex terminates what each client speaks, shows the filters the same HTTP/1.1 whichever
it was, runs **one chain** over all three, and hands the service the HTTP/1.1 it has always
understood. The service is not moved, reconfigured, or told about any of it — and only
firegex holds a certificate.

Three things to know:

- **On a published address firegex is not transparent**, which is the point of it. The
  service sees a connection to `:80` — from the client's own address, as always — rather
  than to the port the client dialled.
- **Declaring TLS is a promise**, and the engine keeps it: a client that opens that port
  in the clear is refused rather than carried to a service expecting HTTPS. *In the clear*
  is the permissive default and terminates a client that brings TLS anyway, decided per
  connection, because refusing one at a port nobody promised would be a rule with nothing
  behind it.
- **All of it can be changed afterwards**, from the pencil beside the address on the
  service's page. Editing an address takes its rules back and reinstalls them, which is
  what makes the whole row rewritable and not only the address; only that one address
  stops being steered while it happens, and a refusal puts the row back untouched.

### An address, or the interface it arrives on

An address entry is a concrete IP (`192.168.1.10:80`, `::1:80`, CIDR `10.0.0.0/24:8080`) or
a **network interface name** (`eth0:80`, `wg0:8080`, `tun0:53`, `lo:80`). The picker lists
both, each interface shown with the addresses it is carrying at that moment, and takes
anything you type that is neither — the address a service will answer on does not have to
exist on this host yet.

Which of the two to use is a question about who decides the address. An IP protects that
one place. An interface protects *whatever address that link is carrying*, matched on the
name, which is what you want when somebody else hands the address out — a VPN the
organisers dial you on, a DHCP lease, a tunnel that comes up mid-round. Nothing has to be
edited when the address changes, and nothing silently stops being protected when it does.

The rules are built differently for each, so the layer matters:

- **On NFQUEUE**: interface matching operates natively in nftables using `meta iifname <iface>` (in prerouting) and `meta oifname <iface>` (in postrouting). Packets arriving at or routed through that interface on the configured port are queued to userspace, regardless of the destination IP.
- **On Proxy (TCP & TLS)**: traffic entering through the interface (`meta iifname <iface>`) is redirected to the proxy listener. The engine connects upstream preserving the destination (`SO_ORIGINAL_DST`) and spoofing the client source IP (`IP_TRANSPARENT`), while policy routing diverts return packets (`meta oifname <iface>`). **Protecting a link protects everything that crosses it on that port** — including traffic that is only passing through. On a bridge like `docker0` that means the containers' own outgoing connections: a service protecting `docker0:443` takes every container's outbound HTTPS into firegex, which terminates it with that service's certificate, and the containers see a certificate that does not match the site they asked for. That is the interface doing what it says; it is not narrowed for you, because a link is also how you protect a service on **another machine** that this host routes for, which is the case the address is not yours to know. If you want only what is addressed to this host, name the address instead of the link. An interface stands for whatever addresses it carries, and firegex resolves them wherever it needs an address rather than a match — so an HTTPS edge, a published port and a client on this host all work the same whether you write `eth0` or the address itself. Traffic this host generates towards those addresses is redirected too, matched by address rather than by interface name — a connection from the host to one of its own addresses is routed through loopback, so there is no interface on it to match. That is what makes protecting `lo` also protect a client running beside the service.
- **On Proxy (UDP)**: because UDP relays need a concrete destination to bind upstream forwarding, Firegex automatically resolves the interface's primary assigned IP. If the interface has no IP assigned, use NFQUEUE instead.
- **External proxies**: the `external` transport takes an IP only. Its return rule recognises your proxy by one address and port to put the original port back, and an interface is not one address — so the interface half of the picker is not offered there at all.

## What the service speaks

One choice per service: **TCP**, **UDP**, **TLS**, **QUIC** or **HTTP**. It tells firegex
what is on the wire, which is what decides what the filters can be shown.

| | Pick it for | The filters are shown | It needs |
|---|---|---|---|
| **TCP** | anything unencrypted on TCP — a web service on `:80`, a game protocol, a shell | the bytes as they travel; HTTP/1.1 parsed, and HTTP/2 in the clear recognised from its preface and rendered as HTTP/1.1 | nothing but the addresses |
| **UDP** | anything unencrypted on UDP — a game server, DNS, something homemade | one datagram at a time, both directions, `RawPacket` only | nothing but the addresses |
| **TLS** | a port where *everything* arrives encrypted | the decrypted stream, the same models a cleartext service gives | a certificate and key; the proxy layer. [What the service behind speaks](#what-the-service-behind-speaks) is its own question |
| **QUIC** | a QUIC service, in practice HTTP/3 | one stream at a time with its own state; HTTP/3 rendered as HTTP/1.1 | a certificate and key; the proxy layer |
| **HTTP** | one daemon reached **more than one way at once** — `:80`, `:443` and `:443` over UDP | every version as the same HTTP/1.1, gRPC included | a certificate and key, including for the cleartext addresses; the proxy layer |

**The interface asks this as two questions**, because the list of five looks like five
alternatives on one axis and is not:

> **Is the traffic encrypted?** in the clear · encrypted 🔒
> **Encrypted with what?** TLS · QUIC · HTTPS — or, in the clear: **TCP** · **UDP**

The first answer is the one the certificate hangs off, which is why it wears the lock; the
second only ever offers protocols of that kind. `HTTP` is shown as **HTTPS** there, because
beside TLS and QUIC an option labelled "HTTP" reads as the cleartext web protocol — which
is the confusion this picker was rebuilt around. It is `http` in the API and in a backup.

**A plain web service is `TCP`.** Filtering HTTP needs nothing special: HTTP/1.1 is parsed
as it goes past, HTTP/2 in the clear is recognised from its connection preface, and
patterns match the plaintext because the plaintext is what is on the wire.

Every layer carries TCP and UDP; the three that have to be decrypted are on the proxy
layer alone, because decrypting means terminating the connection — see [TLS](#tls),
[QUIC](#quic) and [HTTP](#http-every-version-through-one-chain).

**UDP on the proxy layer preserves the client's address** transparently using `IP_TRANSPARENT`
source spoofing and policy routing, matching the behavior of TCP. See
[UDP on the proxy layer](#udp-on-the-proxy-layer).

This used to be four modules — `nfregex` was NFQUEUE welded to regexes, `nfproxy` was
NFQUEUE welded to Python, `tls` was a separate object you had to keep in step with the
service that used it. Choosing regexes therefore also chose NFQUEUE, and switching meant
starting over. Nothing about the two decisions actually requires them to be one.

## Network layers

The two that inspect traffic are built on opposite trades. **The trade is not speed** —
the proxy layer measures faster on both bulk throughput and connection rate, for the
reason in the table below — it is what happens when a filter dies, and what you are
allowed to do to the traffic. Pick by those.

|  | **Proxy** | **NFQUEUE** |
|---|---|---|
| Unit of work | a connection | a packet |
| Transparency | full — dials your service **from the client's own address** | full — the real packets, on their way to your service |
| Reassembly | the kernel's, on two real sockets | rebuilt in userspace with libtins |
| Rewriting | patterns: no. Python: exact, any length | patterns: no. Python: unstable on TCP, exact on UDP |
| If a filter dies | the engine rebuilds fail-open by hand | **the kernel keeps forwarding**, by itself |
| Cost | terminating a connection, once | **a userspace round trip per packet**, per filter |
| Measured ([how](../tests/bench/README.md#performance)) | **4035 MB/s** at 1 thread, **13 984** at 8 | 1820 at 1 thread, 2956 at 8 |
| Short connections | the two are indistinguishable — see below | |
| UDP | yes, fully transparent (source IP preserved, one relay per address) | yes, fully transparent |
| TLS and QUIC | yes, terminated here | no — decrypting means terminating |

### Proxy

The connection is terminated and reopened towards your service, so firegex owns both
halves.

**What that buys**

- **Exact rewriting, for a Python filter.** Two independent connections means a
  replacement can be any length: there are no sequence numbers shared with the client to
  desynchronise. Patterns do not rewrite on any layer — see **Regex** under *Filters* below
  for why that was withdrawn. This is
- **Reassembly is the kernel's problem.** Both sides are ordinary sockets, so
  out-of-order and retransmitted segments are sorted out before a filter ever sees them
   — rather than being rebuilt in userspace with the caveats that come with it.
- **Backpressure for free.** A slow filter slows the sender through TCP flow control
  instead of overflowing a queue and dropping packets.
- **An ordered chain inside one process.** Filters are a list walked in order, so a long
  chain costs one interception, not one per filter.

- **It carries bulk traffic several times faster**, which reads backwards and is not:
  NFQUEUE copies every packet out to the kernel's queue and takes a verdict back, once
  per packet, while the proxy pays to terminate a connection once and then the kernel
  moves the bytes. Measured on the same host, same filter, same traffic: **2.2×** at one
  thread and **4.7× at eight**, with the ranges nowhere near touching. It also scales
  better with `--threads` — 3.5× from one thread to eight, against about 1.5× for
  NFQUEUE, whose work is largely a trip through the kernel that a second core cannot
  take.

  **On short connections there is no measurable difference.** That is the axis where a
  terminating proxy is supposed to lose, and it does not obviously — but neither does it
  win: measured with the layers interleaved, they overlap, and the medians land within
  3% of each other. Anyone quoting a number for this axis is quoting noise, this page
  included until it was measured properly. Both are in
  [tests/bench/README.md](../tests/bench/README.md#performance), with the scripts that produce them.

**What it costs**

- **The kernel's fail-open backstop is gone**, and the engine has to rebuild it by hand:
  `catch_unwind`, a deadline per filter, a filter that misbehaves losing its say rather
  than the traffic being held. It works — and it is code, where the other layer has a
  kernel guarantee.

It stays invisible: it always dials your service **from the client's own address** on both
TCP and UDP, so anything that logs, rate-limits or bans by IP keeps working. That is not
a setting, because a service that suddenly saw one address for the whole internet would be
a regression nobody would attribute to us.

### NFQUEUE

Packets are lifted to userspace, inspected, and a verdict is handed back to the kernel.
Nothing is terminated.

**What that buys**

- **The kernel's fail-open backstop is real.** If a filter panics, hangs or crashes, the
  kernel keeps forwarding untouched packets.
- **Full transparency.** The service sees the original packets, with original headers and
  timestamps intact.
- **No connection termination.** Suitable for protocols that cannot be proxied or where
  terminating the transport is prohibited.

**What it costs**

- **A userspace round trip per packet.** Every packet is copied across the netlink boundary,
  which caps bulk throughput.
- **Reassembly in userspace.** Done via libtins, with memory caps and timeout heuristics.
- **One process per filter.** Chaining requires multiple processes and netfilter queues.
- **A Python filter's rewriting is unstable on TCP here.** Changing a payload's length
  desynchronises the stream, which is what `UNSTABLE_MANGLE` is named after. On **UDP**
  it is exact, because a datagram carries no sequence numbers to desynchronise.
  Patterns do not rewrite on either layer.

### UDP on the proxy layer

On TCP a single listener fronts every protected address and recovers where each
connection was headed with `SO_ORIGINAL_DST`, reading the conntrack entry the redirect
left behind. **The kernel implements that option for TCP and SCTP only**; ask it about a
UDP socket and it answers `ENOPROTOOPT`. So UDP is relayed with **one dedicated socket
per protected address**, each with its upstream already known, and nothing has to be
recovered per datagram.

What UDP on the proxy layer provides:

- **Full source IP transparency.** Outbound datagrams towards your service are sent with
  `IP_TRANSPARENT` using the client's own address and port, with mark-based policy routing
  diverting return packets to the local engine. Your service sees the real client IP.
- **Zero-downtime dynamic address addition.** Adding new addresses to a running UDP service
  dynamically binds new relay sockets through the control channel without restarting the
  engine or dropping existing connections.
- **Exact rewriting, at any length, for a Python filter.** A datagram is
  self-contained, so there are no sequence numbers for a longer or shorter payload to
  desynchronise. The caveat that makes rewriting unstable on the NFQUEUE layer simply
  does not apply.
- **Per-flow filter state.** Each client address is a flow with its own filter state and
  its own Python module globals, released after a minute of silence — UDP has no close
  to observe, so a timeout is the only thing that can end one.
- **Both directions inspected**, and replies leave through the listener socket so
  conntrack rewrites them to appear from the address the client dialled.

`REJECT` means something narrower here: there is no connection to close, so the datagram
is simply not forwarded, and the next one from that client is judged afresh.

### Holding up under load

A service can be given a **limit on how many connections it carries at once**, and told
what to do with what does not fit. Both are on the proxy layer, which is the one that
accepts a connection and dials the service; NFQUEUE hands the kernel a verdict on packets
already in flight, and what it can run out of is queue — that is what fail-open is for.

Without a limit, connections that are opened and then say **nothing** are the cheapest
attack there is. Each costs two descriptors — one from the client, one to the service,
because the upstream is dialled as soon as the connection is accepted — and about five
hundred of them from a single host were enough to exhaust firegex entirely. No data has
to be sent, and every other service on the instance went down with the one being
attacked.

A limit does **not** save the service under attack. A cap cannot tell a connection that
is silent because it is an attack from one that is silent because the client is slow, so
an attacker who fills the limit still fills it. What it does is contain the damage to that
one service: measured with four hundred silent connections against a limited service, the
service beside it kept answering, which is what used to be lost.

What happens past the limit is yours to choose:

- **Refuse** (the default). Nothing reaches the service that was not inspected, and
  clients are turned away while the limit holds.
- **Forward unfiltered.** The service stays reachable past the limit, and that traffic
  gets there with nothing having looked at it. This is the same trade as fail-open, made
  at a different moment, and it is off by default for the same reason: a filter that
  quietly stops filtering is the worse surprise.

**Hitting the limit leaves a mark in two places, because they answer different
questions.** The service log says it now, at warning level, so an operator watching
clients fail sees the reason rather than guessing — rate-limited, since being at the limit
means connections are arriving faster than they leave and a line each would be the flood
arriving twice. And a count is kept in the database with the first and last time it
happened, which is what survives a restart and outlives the live log's bounded ring: *did
we ever hit the wall* is a question asked the next morning. The service page shows it
above everything else.

#### A deadline on the first byte

The limit contains the damage; it cannot undo it, because a cap cannot tell a connection
that is silent because it is an attack from one that is silent because the client is slow.
An attacker who fills the limit keeps it filled.

So a service can also be told to **close a connection that has said nothing** after a
number of seconds. That is the thing the limit cannot do: measured with the limit full and
the attacker still holding every socket, clients got back in once the deadline passed.

Two properties make it safe to turn on:

- It counts **either direction**. A service that greets its client — SMTP, SSH, most game
  protocols — satisfies the deadline with its banner, exactly as a request would. A
  deadline that required the *client* to speak first would have hung every one of them.
- It applies only until the **first** byte, and never again. A connection that has said
  something and then goes quiet is a session, and sessions are allowed to think. This is
  not an idle timeout, and it will not close a long-lived connection that is waiting.

Zero means never, which is what every service did before. There is no default worth
picking for you: how long a legitimate client may reasonably stay silent is a fact about
your service, not about firegex.

UDP flows are counted against the same number. They are the cheaper half of the same
attack — a flow is created per source address, a datagram's source is not verified by any
handshake, and six hundred datagrams from six hundred forged sources took four hundred
descriptors in three hundredths of a second and held them for a minute after the sender
had gone.

### TLS

TLS is one of the **transport protocols** a service can speak, beside TCP and UDP —
not a switch on top of TCP. That is the shape of the thing: asked what is on the wire,
the answer is TLS or it is not.

It is offered on the **proxy** layer only, because decrypting means terminating the
connection and terminating is what that layer does. NFQUEUE inspects packets on their way
past, which is the whole reason it can fail open, and a hand-off to your own proxy has
nothing of firegex in the path at all — so on those layers the TLS option is there but
cannot be chosen, and the form says why. The same holds the other way round: choose TLS
and the two layers that cannot carry it grey out.

Choose it and give the service a certificate and a private key; both fields take a paste,
a file picked from disk, or a file dropped onto them. The engine decrypts the connection,
the filters see the plaintext, and it is re-encrypted towards your service — all inside
the process that is already filtering, so **a TLS service occupies no port that a plain
one does not**, and clients keep dialling the address they always did.

There used to be two ports, and a boolean. nginx terminated on one loopback port and
re-encrypted from a second, with the filters attached to the leg in between, so
protecting one address cost a pair of ports derived by hashing `ip:port` — ports that
were chosen rather than assigned, and could collide with something real. And because TLS
was a flag rather than a protocol, three combinations were expressible that are not real:
TLS on a UDP service, on NFQUEUE, and on a hand-off. Two of those cannot be said any
more; the third is refused when the service is created rather than when it first fails to
start.

The private key is stored and never sent back to the browser; neither is the certificate,
so the fields are empty when you come back to edit and leaving them that way keeps what
is already there. Switching a service *to* TLS when it has never been given either is
refused there and then.

#### What the service behind speaks

**It is asked of each address**, under its ⚙ button, and not of the service: what leaves
towards the service is a property of the way in. One daemon reached over TLS on one port
and in the clear on another is re-encrypted for the first and handed the plaintext for the
second.

| | What firegex does |
|---|---|
| **As it arrives** | It speaks what arrived. The default, and what every address did before there was a choice: a connection terminated here goes back out encrypted. Firegex is *carrying* its encryption. |
| **In the clear** | It is an ordinary HTTP/1.1 service. Firegex terminates what the client used and forwards the plaintext, so **only firegex needs a certificate**. |
| **TLS** | It speaks HTTP/1.1 under its own TLS, whatever the client used to get here. |

The second one is why this exists. A service that speaks HTTP and nothing else can be put
behind an encrypted edge with firegex providing the encryption: clients reach it over TLS
— or over **HTTP/3**, see below — on the port it already listens on in the clear.

Two things follow from choosing anything but *as it arrives*, and both are worth knowing
before a round:

- **ALPN is no longer mirrored** on that address. The protocol a client is told is
  normally the one the service picked, and a service reached over HTTP/1.1 picks nothing.
  On TLS the client is told nothing and settles on HTTP/1.1; on QUIC, firegex answers `h3`
  — for itself, not for the service, because it is firegex that is speaking HTTP/3.
- **Stopping firegex stops the encryption**, because the encryption was firegex's. A
  client dialling that port with TLS then reaches a service answering in the clear.

##### HTTP/3 in front of a service that has never heard of it

This is the one place in the engine where what leaves is **not** the version that
arrived, and it is only ever an explicit choice. An HTTP/3 exchange is already rendered as
the HTTP/1.1 it would have been, because that is what the filters have to be shown — so
that same rendering can be sent on to a service that speaks HTTP/1.1. Nothing is invented:
what the service receives is byte for byte what the chain inspected.

One QUIC stream is one request, and HTTP/1.1 has no multiplexing, so each exchange opens
its own connection to the service — dialled from the client's own address like every other
dial firegex makes.

What cannot be done, and is a limit rather than a missing setting: a QUIC edge carrying
anything **other than HTTP/3**. Opaque bytes on a QUIC stream have no HTTP/1.1 form, so
there is nothing to send a service that speaks one. In practice that means an instance
whose `FGEX_PROXY_QUIC_ALPN` is not `h3`: the choice is refused there, on `QUIC` and
`HTTPS` services alike, with the ALPN named.

#### What is carried through, and what cannot be

**ALPN is the service's answer, carried.** Terminating a connection means answering for
your service, and answering something it did not say is how a proxy breaks a protocol it
was only meant to carry — a client told `h2` while the service speaks HTTP/1.1 sends
frames to something that cannot read them. So the client's hello is held open, the
service is asked with exactly the list the client offered, and the client is told exactly
what came back. If the service picks nothing, the client is told nothing: firegex does not
invent an agreement between two ends that did not reach one.

That means HTTP/2 works if your service speaks it, and does not appear if it does not.
Before this, ALPN was dropped in both directions — every client fell back to HTTP/1.1
whatever it asked for, and a client that insists on `h2` failed.

> **HTTP/2 is terminated and rendered, exactly as HTTP/3 is.** HTTP/2 puts the method,
> the path and the headers in an **HPACK-compressed** HEADERS frame, so a firegex that
> only forwarded it showed a filter a compression format: a pattern written against a
> request line matched nothing, and a filter asking for an `HttpRequest` was handed the
> `PRI * HTTP/2.0` preface and then frames it could not read, so it was never called and
> nothing said so. Only a body travelled in the clear. Since gRPC *is* HTTP/2, gRPC could
> not be filtered at all.
>
> On a connection that negotiates `h2`, the engine now terminates it and shows the chain
> each exchange as the HTTP/1.1 it would have been — the same rendering HTTP/3 gets (see
> [below](#http3-is-shown-to-the-filters-as-http11)), from the same code. One pattern and
> one Python filter cover HTTP/1.1, HTTP/2 and HTTP/3. There is nothing to turn off on
> your service any more.
>
> Since gRPC is HTTP/2, that is also what makes gRPC filterable: the method name is the
> path, the metadata are headers and the status is a trailer section, all of them visible
> to a pattern and to a Python filter. For the message bodies themselves there is a
> `GrpcMessage` model that takes the length prefix off — see
> [the pyfilter documentation](pyfilter.md#grpc-messages).
>
> **HTTP/2 in the clear** (`h2c`, prior knowledge) is recognised too, on a plain `tcp`
> service with no certificate anywhere: such a client opens with a fixed 24-byte preface
> that no other protocol begins with. What is *not* handled is the old HTTP/1.1
> `Upgrade: h2c` handshake — the upgrade request is filtered as the HTTP/1.1 request it
> is, but if your service answers `101` everything after that is HTTP/2 nobody rendered.
> RFC 9113 deprecated that mechanism and nginx dropped it in 1.25.1, so in practice no
> service accepts it.
>
> Two shapes are **refused rather than rendered**, because a tunnel has no HTTP exchange
> in it to show and inventing one would be worse than saying no: **server push**, which
> is turned off in the handshake with your service so it knows rather than watching its
> pushes disappear, and **CONNECT** streams, including the extended CONNECT that
> WebTransport uses.
>
> One difference to know about if you write stateful Python filters: **each HTTP/2 stream
> is its own connection to a filter**, with its own module globals, where an HTTP/1.1
> keep-alive connection carries many requests through one. HTTP/2 interleaves its
> streams, so sharing state between them would let one client's bytes decide another's
> verdict — and would let an attacker split a pattern across two streams to get past a
> filter.

**TLS versions are negotiated per leg**, which is what terminating means: a client on
TLS 1.2 can reach a service on TLS 1.3. Both legs do **TLS 1.2 and 1.3 only**. TLS 1.0 and
1.1 are not supported and cannot be turned on — the engine's TLS library does not
implement them at all, so this is a limit of what firegex can be rather than a setting
that is off. A service that must be reached over TLS 1.0 has to keep firegex out of its
path, on the `external` layer or the NFQUEUE one with the ciphertext filtered as it goes
by.

The same goes for the cipher list: it is a modern fixed set, not something to configure,
and key exchange is always forward-secret. There is no option for RC4, 3DES, or
RSA key transport, and there is no switch that would bring them back.

Client certificates are not requested. A service that authenticates its clients with mTLS
cannot be terminated here, because the certificate the client would present is one only
your service can check.

**The key has to be one the engine can sign with**: RSA of at least 2048 bits, or an
ECDSA or Ed25519 key. A smaller RSA key is refused when the service starts, with the
engine's own reason. nginx could be told to accept one; the engine's TLS library has no
equivalent switch.

#### Watching the decrypted traffic

The plaintext never becomes a packet — that is exactly what removed the two ports — so
the engine writes it out itself. **`firegex0` carries the decrypted traffic of every TLS
and QUIC service and nothing else:**

```bash
sudo tcpdump -i firegex0 -w decrypted.pcap
```

No filter expression, no port to look up, and one capture covering the whole instance
rather than one per service. Wireshark takes the same interface live, or opens the file
afterwards. Run it on the **host** running firegex: the container shares the host's
network namespace, so the interface is there.

What arrives there is a **reconstruction**. The bytes are real — exactly what the filters
saw and exactly what was forwarded, after any rewriting — but the framing around them is
built by the engine, because the framing that crossed the wire was encrypted. Sequence
numbers start at zero, there are no retransmissions, and the segmentation is the engine's
read sizes rather than the peer's. What that buys is a stream Wireshark can follow; what
it costs is that a capture from here is not evidence of what was on the wire.

Opening the socket it writes to needs `CAP_NET_RAW`. Firegex asks for it and starts
without it: a host that will not grant it loses the capture, not the firewall, and says
so once at startup.

What comes out is decrypted traffic, which makes the file exactly as sensitive as the
private key that would have produced it.

### QUIC

QUIC is the fourth thing a service can speak, and the one with the least room for
argument about where it lives.

TLS over TCP can at least be carried past unopened: the bytes are framed by a transport
the kernel understands, so a layer that forwards still has a packet to match and a rule
to match it with, and filtering the ciphertext is a thing you can choose to do. QUIC
leaves not even that. Past the Initial packet it encrypts the **frames, the stream
boundaries and the packet number** along with the payload, so a packet queued to
userspace is a datagram of noise. Terminating it is not the better option, it is the only
one — which is why the QUIC option greys out on the other two layers, exactly as TLS
does, and says so.

On the wire QUIC is **UDP**, and that is what the rules match: a QUIC service's addresses
are steered the same way a datagram service's are, one endpoint bound per protected
address. What changes is what is behind the port — something that terminates rather than
something that forwards.

Give it a certificate and a private key, as for TLS. QUIC carries TLS 1.3 inside itself,
so there is no unencrypted QUIC to fall back to and no version to negotiate.

**A stream is what the filters see.** A QUIC connection carries many streams at once, and
each one is handed to the chain as its own connection: its own filter state, its own set
of module globals for a Python filter, released when that stream ends. That is the honest
mapping — a filter's state follows a stream of bytes from its start to its end, which is
what a QUIC stream is and what a QUIC connection is not — and on HTTP/3 it lands where
you would expect, one request to a stream.

**A refusal ends the connection, not the stream.** Blocking one stream would leave the
client free to ask again on the next one, which is not what blocking means anywhere else
in firegex; it is the same thing that happens on HTTP/1.1 with keep-alive, where a
refused request takes the connection with it. The client is told why, in the close
reason, rather than being left to time out.

#### HTTP/3 is shown to the filters as HTTP/1.1

A filter is supposed to be written once. `HttpRequest` on a QUIC service has to mean what
it means on the TCP service beside it, and a hyperscan pattern written for one has to
match on the other — otherwise moving a service to QUIC silently switches its filters
off.

But HTTP/3 puts the method, the path and the headers in a **QPACK-compressed HEADERS
frame**. A filter shown the bytes of the stream would be shown a compression format, and
every pattern would stop matching. So firegex terminates HTTP/3 too, and renders each
exchange as the HTTP/1.1 message it would have been. That is what the chain is shown, and
what goes on towards your service is HTTP/3 again, re-encoded.

The same bargain the [decrypted capture](#watching-the-decrypted-traffic) makes: **the
bytes are real and the framing is reconstructed.** Concretely —

- the request line says `HTTP/1.1`, because that is the only version an HTTP/1 parser
  will read, and what was on the wire was HTTP/3;
- `Host` is rendered from the `:authority` pseudo-header, which is where HTTP/3 puts it;
- a body whose length the message declared is shown under its own `Content-Length`;
- a body whose length it did not declare is shown **chunked**, which is what that message
  is in HTTP/1.1 — and the head is held back until it is known whether a body is coming
  at all, so that a request without one is never shown a `Transfer-Encoding` it did not
  carry. A filter looking for that header is usually looking for smuggling, and one
  invented by the proxy in front of it would be the worst possible answer. Held *briefly*:
  a declared length settles the question outright, a message with no body has already
  ended its stream, and the only thing left waiting is a sender holding the stream open —
  which after 100 ms is rendered chunked rather than held, because a bidirectional
  exchange the service speaks first in (gRPC's among them) would otherwise deadlock, each
  end waiting for the other;
- a **trailer section is always shown to the filters**, and that is what decides the
  framing of a message that has one and no body — in HTTP/1.1 a trailer section belongs to
  a chunked message and nowhere else, which is exactly a gRPC trailers-only answer. The
  one message whose rendering cannot carry a trailer section is one that declared its
  length, since its HTTP/1.1 body ends where the header said it would; there the trailers
  are **dropped rather than forwarded**, because a piece of a message no filter was shown
  is a piece that travelled unfiltered. The engine logs it when it happens;
- hop-by-hop headers do not appear, because HTTP/3 forbids sending them.

#### What is carried through, and what cannot be

**ALPN is the service's answer, carried — asked in the other order.** On TLS over TCP the
client's hello is held open, the service is asked with exactly the list the client
offered, and the client is told what came back. In QUIC the hello arrives inside an
encrypted Initial packet whose processing *is* the handshake, so there is nothing to hold
it at. The order is therefore reversed: firegex opens its connection to the service
first, offering the protocols it was told to offer, and tells the client the one thing
the service agreed to. The invariant that matters is unchanged — the client is never told
a protocol the service did not choose — and what is lost is knowing in advance whether
the client would have accepted it. When it would not, its handshake fails and the log
says which protocol the service picked.

That list is `h3`, which is what a QUIC service speaks nine times in ten. An instance in
front of something else sets `FGEX_PROXY_QUIC_ALPN` as a comma-separated list in
preference order:

```bash
python3 run.py restart --env FGEX_PROXY_QUIC_ALPN=h3,doq
```

`run.py` stores it and puts it back on every later start — editing the generated compose
file by hand does not survive one, because `run.py` rewrites that file each time. The
list is **per instance, not per service**, and it is a superset rather than a choice:
every QUIC service is offered all of it and each one picks what it actually speaks, so
listing every protocol the instance carries is the way to run more than one kind of QUIC
service at once.

**0-RTT is not offered.** Early data is replayable by anyone who watched it go past, and
a filter that refused a request has no way to un-deliver the copy your service already
acted on. A round trip is the price of that not being true.

**QUIC datagrams are carried, except on HTTP/3.** A datagram is unreliable and unordered,
which is to say it is not a stream — so a filter is handed a `RawPacket` for it and
nothing else, exactly as on a UDP service, and the stream and HTTP models stay out of the
way rather than being built on something that cannot support them. One connection's
datagrams are **one flow**: a filter keeping state sees them in order of arrival and can
still catch a pattern split across two of them, which is what the flow is for. A refused
datagram is **dropped and the connection carries on** — there is no conversation to end,
and taking the connection down would cost every stream on it for one message that was
already complete when it was judged.

Over HTTP/3 they are not carried, and the handshake says so rather than letting a peer
find out by watching them disappear. An HTTP/3 datagram names the stream it belongs to,
and the request streams firegex opens towards your service are not the ones your client
opened, so the name would point at the wrong stream on the far side. **WebTransport is not
carried** for a further reason: its streams are bound to a session by a marker each of
them carries, which is a different shape from "one stream, one filter" and would need a
session model rather than a setting.

**A new client is asked to prove its address.** The first Initial packet from an address
is answered with a Retry, so that nothing is opened towards your service on the word of a
source address nobody has checked — otherwise a forged source turns the relay into an
amplifier, which is the datagram flood the connection cap exists for with a handshake in
front of it. It costs an honest client one round trip.

**The decrypted traffic is mirrored to `firegex0`, one TCP stream per QUIC stream** — and
over HTTP/3 that is one per request. What you read there is the same HTTP/1.1 the filters
were shown, which is the only honest thing it could be: what crossed the wire was a
compressed header block inside an encrypted packet, and there is no tool that would read
it back as an exchange.

One thing to know before reading a port out of that capture: **the client port is
invented**. Every stream of one QUIC connection shares the client's real port, so each is
given one of its own — otherwise a hundred streams arrive as one conversation whose bytes
decode as nothing. The addresses are real and the service's port is real; the client's
names a stream, not a socket.

**The connection limit is honoured; forwarding the excess unfiltered is not free here.**
On TCP a connection past the limit is relayed with no chain at all, costing nothing. A
QUIC connection past the limit is still terminated, decrypted and re-encrypted, because
there is no such thing as forwarding a QUIC connection unopened — what "unfiltered"
saves is the inspection, not the termination.

### HTTP: every version through one chain

`HTTP` is the one protocol on that list that does not say what is on the wire. It says
what the *service* is, and each of its addresses says how it is reached:

| Address | What reaches it |
|---|---|
| **TCP** | HTTP/1.1 and HTTP/2 — in the clear or under TLS, whichever each client opens with |
| **UDP** | HTTP/3, over QUIC |

One service, one filter chain, one certificate. Add `10.0.0.1:80` as TCP, `10.0.0.1:443`
as TCP and `10.0.0.1:443` as UDP, and every client that can reach your web service goes
through the same filters.

**Why it exists.** HTTP/1.1 and HTTP/2 live on TCP and HTTP/3 lives on UDP, so covering
all three used to take two or three separate firegex services with the same patterns and
the same Python pasted into each of them. Keeping those in step by hand is exactly how one
of them quietly stops being protected — which is the same reason a service takes a *list*
of addresses rather than making you create one service per address.

**Whether a connection is TLS is decided per connection**, from what the client actually
sent, not from a setting. So one `http` service in front of a daemon that answers in the
clear on `:80` and under TLS on `:443` carries both, and what leaves towards your service
matches what arrived: a cleartext connection is forwarded in the clear, an encrypted one
is re-encrypted. It is the same rule ALPN mirroring follows — firegex carries what the two
ends are doing rather than deciding it for them.

**The service behind may answer in the clear too**, including on the HTTP/3 edge — see
[what the service behind speaks](#what-the-service-behind-speaks). Every edge is then
forwarded as HTTP/1.1, which is what an ordinary web service reached on `:80`, `:443` and
`:443/udp` at once looks like: three protocols in front, one behind, one chain over all
of them.

**A certificate is required**, including for the cleartext addresses beside it. A service
that only ever answers in the clear should be a `TCP` one: HTTP/1.1 is filtered there as
it always was, and HTTP/2 in the clear is recognised from its connection preface. The TLS
and HTTP/3 edges are the whole of what `HTTP` adds, and neither exists without a
certificate.

**Proxy layer only.** An `HTTP` service is reached over TLS on one port and QUIC on
another, and the NFQUEUE and hand-off layers can read neither — nor, in fact, the
cleartext edge, because HTTP/2 in the clear is HPACK-compressed and rendering it means
terminating the connection.

Everything the [TLS](#tls) and [QUIC](#quic) sections say about what is and is not
supported applies here unchanged: the same TLS versions and ciphers, no client
certificates, no 0-RTT, no HTTP/3 datagrams and no WebTransport, and the same
`firegex0` capture of the decrypted traffic.

## Filters

### Regex

Patterns matched by [hyperscan](https://github.com/VectorCamp/vectorscan) — the same
library on both network layers, so a pattern means the same thing wherever it runs.

Every pattern in one filter is compiled into a single database, so matching fifty
patterns costs about what matching one costs. That is why patterns live inside a filter
rather than each being one, and why adding a pattern rebuilds rather than chains.

Matching is **stateful per connection**: a pattern split across two packets is still
found, however far apart the halves land, and one client's bytes can never decide another
client's verdict.

Each pattern has a direction — client to service, service to client, or both. A leaked
flag shows up on the way out; an exploit on the way in.

A pattern **blocks** the connection. That is the only thing it does:

```
FLAG\{[a-z0-9]+\}   service → client   block
X-Debug: [^\r\n]*    client → service   block
../                  both ways          block
```

A pattern can be **edited in place**. A typo is usually found while the service is
running, and retyping the rule as a new one loses its place in the chain and drops the
connections the filter is holding — editing keeps both. What it does not keep is the
**counters**, when the pattern text itself changes: those numbers were about the text
that used to be there, and carrying them over would credit blocks to a matcher that
never made them. Changing anything else — the direction, the case sensitivity, whether
it is active — leaves the counters alone. The new pattern is checked by the engine
before it is stored, and a rule that would collide with another in the same filter is
refused rather than silently duplicated.

**A pattern cannot rewrite, on any layer.** It used to be able to, and the reason it no
longer can is worth stating rather than leaving as a missing feature. Rewriting scanned
one chunk at a time, because bytes already forwarded cannot be taken back — so a match
straddling two chunks was never rewritten. Measured: a pattern sent whole reached the
service redacted, and the *same* pattern split across two TCP segments reached it intact.
Blocking, which scans in hyperscan's stream mode, caught the split version.

What made that unacceptable was not the miss but its silence: no block, no log line, no
counter — just a rule the operator believed was applying. A filter that works on the
sender's segmentation is worse than no filter, because it is trusted. Blocking is the
verdict a pattern can honestly reach on a stream, so it is the only one offered. To
change bytes rather than refuse them, use a Python filter, which sees the reassembled
stream and can say so.

### Python (pyfilter)

Your own code, written against the [`firegex`](https://pypi.org/project/firegex/) library
and documented in [pyfilter.md](pyfilter.md). On the proxy layer it runs in a process of its
own, so code that hangs is killed rather than stalling traffic; on NFQUEUE it runs inside
the C++ process through an embedded interpreter.

A file normally holds **several `@pyfilter` functions**, and each one is listed on the
filter's card with its own switch and its own count of what it has refused. Switching
one off leaves the code exactly where it is: only the list of names handed to the
library changes, and that list is what decides whether a function is ever called. The
alternative — deleting a function to stop consulting it, and pasting it back to resume —
is what these switches exist to replace, and it is the one that loses code mid-round.

The code itself is visible on the card too, without opening the editor: expand it to
read what is running.

The code decides which functions exist; you decide which of them run. So saving a new
version drops the functions that have gone from the file, adds the new ones switched on,
and leaves whatever you had set for the ones still there — an edit elsewhere in the file
must not quietly switch a function back on.

**You do not tell firegex which protocol a filter speaks — the code does.** The library
already decides when to call a filter from what its parameters are annotated with, so
asking for an `HttpRequest` is what makes a file an HTTP filter, and asking only for a
`RawPacket` is what makes one run on anything. Firegex reads it back off the file when you
save it and shows it on the card. A file whose filters want two *different* application
protocols is refused when saved, naming both — a connection is only ever one of them, so
split them into two filters on the same service.

A Python filter runs on UDP too, on either layer, as long as it asks for a `RawPacket`:
the stream and HTTP models need a connection underneath them and would never be built on
a datagram. Saving one that asks for them against a UDP service is refused rather than
accepted and never called.

A filter reads metadata about the layers below it — addresses, ports, address family,
direction — and can change **only the payload**. That boundary is described in
[pyfilter.md](pyfilter.md), and it is what lets the same filter mean the same thing on
either network layer.

## Testing a pattern

Every regex filter card has a **try** button — and only a regex filter card, because
trying a pattern is a thing you do to a set of patterns, not to a service. It is a regex
tester inside firegex: patterns on the left, a sample below, matches highlighted.

It runs **the same engine that will enforce the answer**. That is the entire point. A
tester built on Python's `re` or JavaScript's `RegExp` would accept backreferences and
lookarounds hyperscan rejects, and would disagree about what matches — so you would tune a
pattern against it and find out mid-round that it was never valid. Here, a pattern the
tester accepts is one you can save, and a pattern it rejects tells you why in hyperscan's
own words.

One detail follows from being honest rather than approximate. A pattern is judged against
the mode it will actually run in — stream matching, which is how a pattern follows a
connection across chunk boundaries, and hyperscan does not accept quite the same patterns
in every mode — so the tester's verdict is the one the datapath will reach. And
occasionally a pattern is valid, will run, and still
cannot be highlighted here, because showing *where* a match starts needs the scan mode
that accepts slightly less. The tester says so instead of silently showing no matches.

## What has been refused

The service page answers three questions, because a single number answers none of them.

**Which rule is doing the work.** Every filter, every pattern and every `@pyfilter`
function is listed with what it refused and **what share of the total is its doing**. A
chain where one pattern accounts for 96% of the blocking and the other nineteen for the
rest is a chain you would drop; you cannot see that from raw counts.

**When it started.** A timeline, which a cumulative counter cannot give you: a filter
that blocked a thousand connections an hour ago looks exactly like one blocking them now.

**How much of the traffic it is** — see below, where each layer reports what it can
honestly measure.

### Choosing a window

The last 15 minutes, hour, 6 hours, 24 hours, everything kept — or **two exact
instants**, for looking at something that has already happened: a round that ended, an
attack somebody described afterwards.

**Everything on the page obeys the window.** The chart, the per-filter, per-pattern and
per-function totals, and the shares are all computed over the same range. A page where
the chart honours a fifteen-minute window and the table beside it quietly reports all of
time is a page that contradicts itself. The lifetime figure is reported once, beside the
range total, so a narrow window showing nothing is not mistaken for a service that has
never blocked anything.

Widening the window widens the **bars**, not their number: twelve hours at one-minute
resolution is seven hundred bars in a few hundred pixels, which is a texture rather than
a chart. Blocks are stored once a minute and everything else is a sum of those, so no
range costs more than another.

That is the **Auto** step, and you can override it. Pick a fixed one — a minute, five,
an hour — and it stays that whatever range you look at, which is what makes two windows
comparable by eye: five minutes of a quiet hour against five minutes of a busy one. A
step too fine for the range is widened rather than refused, and the header always names
the step actually drawn.

History is kept for **48 hours**. Asking for more is clamped, and the panel says how far
back it actually goes.

**No range starts before the service did.** A window is also floored at the first moment
the service could have refused anything — running, with a filter attached — so asking for
24 hours of a service that has been up for ten minutes gives you ten minutes, not
twenty-three hours of blank followed by a smudge. Those hours are not quiet hours; they
are hours in which the question was not being asked, and drawing them flat says the
opposite of what is true. The header states the range it actually drew, and why.

The mark is set once and never moved. A service stopped for an hour and started again
has a real gap in the middle of its chart, which is worth seeing. A window that ended
*before* the service began is left exactly as you asked for it, and comes back empty —
which is the true answer, and a more useful one than being quietly moved to now.

### Choosing a shape

The same numbers, four ways, because they answer different questions:

| | Good for |
|---|---|
| **Bars** | how much was refused in each step, stacked by filter |
| **Lines** | comparing filters against each other over time |
| **Area** | seeing where a burst begins and ends as a shape |
| **Share** | what proportion each filter contributed, step by step |

Hovering anywhere over the plot marks the step under the cursor and reads it out: the
time it covers, what each filter refused in it, and the total. Reading a stacked bar by
eye tells you something was refused; it does not tell you which of two similar colours
was the larger, and it never tells you a number.

### How much of the traffic

Reported in the unit each layer can honestly produce, and never as a ratio between two
different units:

- **Packets and bytes** that reached the service, counted by the **kernel** on the rules
  that intercept it. Free, and nothing in userspace can skew it — the count comes from
  netfilter, not from a filter reporting on itself. Reported on the layers whose rules
  the kernel walks for every packet: NFQUEUE and the hand-off.
- **Connections seen and refused**, from the proxy engine. That layer works in
  connections, which is the same unit a block is in, so the share of refused traffic
  there is exact.

Each layer reports what it can actually measure. NFQUEUE has no connection to count — it
works per packet, which is the whole reason it is cheap — so it leaves the connection
share empty rather than dividing refused connections by a packet count and calling the
result a percentage. The proxy layer has no honest packet count: its rule lives in a
`nat` chain, and conntrack translates a connection once, so every packet after the first
is handled without the rule being walked again. That counter is new connections wearing
a packet label, so it is not shown at all.

The asymmetry is not a gap in the reporting; it is the difference between the two layers
showing through in what each of them can honestly say.

Blocks are written out at most every few seconds and the history is pruned as it is
written. Both are deliberate: a service refusing thousands of connections a minute must
not be able to take the backend down through its own bookkeeping, which is exactly what
one row per block would do.

## The live log

Every service page carries a rolling log of what that service is actually doing, pushed
as it happens rather than polled:

- **blocks**, naming what refused the connection — `connection refused by patterns:
  /BLOCKME/`, or `refused by http: refuse_traversal()` for a Python filter, down to the
  function rather than the file; not an opaque id you would have to go and look up
  mid-round;
- **whatever your Python prints**, so `print()` while debugging a filter works the way
  you expect;
- **what the datapath says about its own health** — a filter that lost its say after
  missing its deadline, a fallback, a ruleset that was refused. These used to go to the
  backend's stderr, where nobody looks during a competition.

It is bounded at both ends. A service under attack refuses thousands of connections a
minute; the tail keeps the last few hundred lines and the rest fall off, and lines are
coalesced before being sent so a burst arrives as one message instead of thousands.
Nothing about logging can turn into an outage.

## Trying a ruleset without an instance

The tester above needs a running firegex. The `firegex` pip package carries the same
matching, so a ruleset can be tried anywhere — on the laptop you are writing it on,
before the competition starts:

```bash
pip install -U firegex

fgex regex check rules.json                    # does it compile? what is in it?
fgex regex test  rules.json --sample req.txt   # what would it do to this?
fgex regex proxy rules.json 10.60.3.1 8080     # a local proxy applying it
```

The ruleset file is **the same shape firegex uses**, so one file works in both places:

```json
[
  {"id": "traversal", "pattern": "\\.\\./", "direction": "c2s"},
  {"id": "flag-leak", "pattern": "FLAG\\{[a-z0-9]+\\}", "direction": "s2c",
   "case_sensitive": false}
]
```

It binds the same hyperscan rather than approximating it with Python's `re`, so a
pattern it accepts is one firegex accepts, and one it rejects reports hyperscan's own
message. Where hyperscan is not installed it says so and stops, rather than quietly
answering with a different engine.

One honest limit. `fgex regex proxy` matches **per chunk**, while a rule on a real
service matches across the whole stream — so a pattern split over two reads is caught in
production and not in the simulator, never the other way round. A ruleset that looks
clean here may still block something on a live service; one that blocks here always
would.

## Editing while it runs

Adding, removing, reordering, enabling and disabling filters, patterns and individual
`@pyfilter` functions all take effect on live connections **without dropping any of
them**. Both layers swap their configuration
underneath the traffic.

Adding an address does not drop anything either, and removing or moving one costs only
the connections on that address.

Changing the service's own definition — its protocol, network layer, or TLS — is
different: that changes what the datapath *is*, so the service is stopped and started
around it, and the connections it was carrying are dropped. The UI says so before you do it.

## See also

- [Firewall rules](firewall.md) — plain nftables rules, unrelated to services.
- [Writing a Python filter](pyfilter.md) — the `@pyfilter` API and its models.
