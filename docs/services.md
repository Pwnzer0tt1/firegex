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
afterwards, mixing address families freely.

Adding an address to a running service **drops nothing**: the datapath is already up and
already enforcing the chain, so all that happens is that one more address is pointed at
it. (The single exception is a proxy service gaining its first IPv6 address, because the
listener has to be reopened in a family that can accept one. The log says so.)

The alternative — one service per address, with the chains copied between them — is how
one of them silently stops being protected the first time a pattern is added to the other.

## Transport protocol

TCP, UDP or TLS, chosen on the service. Every layer carries TCP and UDP; TLS is on the
proxy layer alone, because decrypting means terminating the connection — see
[TLS](#tls).

**UDP on the proxy layer does not preserve the client's address**, which is the one place
that layer stops being invisible. See
[UDP on the proxy layer](#udp-on-the-proxy-layer-and-what-it-gives-up); the interface
says the same thing where you choose, and marks any service in that combination.

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
| Rewriting | **exact**, any length | patterns: no. Python: yes, unstable on TCP, exact on UDP |
| If a filter dies | the engine rebuilds fail-open by hand | **the kernel keeps forwarding**, by itself |
| Cost | terminating a connection, once | **a userspace round trip per packet**, per filter |
| Measured ([how](../tests/README.md#performance)) | **4035 MB/s** at 1 thread, **13 984** at 8 | 1820 at 1 thread, 2956 at 8 |
| Short connections | the two are indistinguishable — see below | |
| UDP | yes, **without the client's address** (see below) | yes, fully transparent |
| TLS termination | yes | no — decrypting means terminating |

### Proxy

The connection is terminated and reopened towards your service, so firegex owns both
halves.

**What that buys**

- **Exact rewriting.** Two independent connections means a replacement can be any
  length: there are no sequence numbers shared with the client to desynchronise. This is
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
  [tests/README.md](../tests/README.md#performance), with the scripts that produce them.

**What it costs**

- **The kernel's fail-open backstop is gone**, and the engine has to rebuild it by hand:
  `catch_unwind`, a deadline per filter, a filter that misbehaves losing its say rather
  than the traffic being held. It works — and it is code, where the other layer has a
  kernel guarantee.
- **On UDP it stops being invisible**: the client's address is not preserved. See
  [below](#udp-on-the-proxy-layer-and-what-it-gives-up).

It stays invisible: it always dials your service **from the client's own address**, so
anything that logs, rate-limits or bans by IP keeps working. That is not a setting,
because a service that suddenly saw one address for the whole internet would be a
regression nobody would attribute to us.

### NFQUEUE

Packets are lifted to userspace, inspected, and a verdict is handed back to the kernel.
Nothing is terminated.

**What that buys**

- **Nothing is in the path.** Your service receives the original packets, from the
  original client, on the original connection. There is no proxy to be visible.
- **A real kernel backstop.** With `fail_open`, `NFQA_CFG_F_FAIL_OPEN` plus `bypass` on
  the rule mean that if the filter process dies outright — crash, kill, anything — **the
  traffic keeps flowing**. Nothing in userspace has to be correct for that to hold.
- **UDP**, with the real datagrams and the real client address.

**What it costs**

- **A userspace round trip per packet.** This is the one that surprises people, because
  "no second connection, no relay" sounds cheap. Every packet — payload, handshake,
  ACK — is copied to userspace and a verdict copied back, which is why bulk traffic
  measures a fraction of the proxy's, and why adding threads helps it less. It is cheap
  per *connection* and expensive per *packet*, and a stream of bytes is made of packets.
  On short connections, where the packet count per connection is small, the two layers
  measure the same.
- **Reassembly is yours.** TCP is rebuilt in userspace with libtins, which is where the
  out-of-order caveat lives: a packet that arrives out of sequence is accepted without
  the filter being called at all.
- **A filter costs a process.** The two binaries fuse transport and filter (`cppregex`
  is NFQUEUE plus hyperscan, `cpproxy` is NFQUEUE plus an embedded interpreter), so a
  chain is a chain of *processes*: each filter has its own queue and its own place in
  the kernel's rule order, and a packet one filter accepts carries on to the next. Eight
  is the ceiling, and a long chain costs a reassembly pass each.
- **Reordering rebuilds the chain**, because the order *is* the arrangement of processes
  and rules. That is a visible interruption, and the log says so. On the proxy layer the
  same edit costs nothing.
- **Patterns cannot rewrite here.** The matcher reports where a pattern matched; it has
  no replacement path. A *Python* filter can mangle on this layer — unstably on TCP,
  where changing a payload's length desynchronises the stream (hence `UNSTABLE_MANGLE`),
  and **exactly on UDP**, where a datagram carries no sequence numbers to desynchronise.

### UDP on the proxy layer, and what it gives up

It works — and it is the one place where this layer stops being invisible, so it is
worth knowing exactly what changes.

On TCP a single listener fronts every protected address and recovers where each
connection was headed with `SO_ORIGINAL_DST`, reading the conntrack entry the redirect
left behind. **The kernel implements that option for TCP and SCTP only**; ask it about a
UDP socket and it answers `ENOPROTOOPT`. So UDP is relayed differently: firegex binds
**one socket per protected address**, each with its upstream already known, and nothing
has to be recovered per datagram.

The consequence is the part to weigh:

- **Your service sees firegex's address, not the client's.** On TCP this layer dials
  your service *from the client's own address*, so anything that logs, rate-limits or
  bans by IP keeps working. On UDP it cannot, and it says so rather than pretending —
  the service page carries a **NO CLIENT IP** badge on any service in this combination.
- **Your filters still see the real client.** `RawPacket.client_ip` and `client_port`
  are the actual peer: firegex knows who is talking even though it does not pass that
  identity on. Only the protected service loses it.

What you keep:

- **Exact rewriting, at any length.** A datagram is self-contained, so there are no
  sequence numbers for a longer or shorter payload to desynchronise. The caveat that
  makes rewriting unstable on the NFQUEUE layer simply does not apply.
- **Per-flow filter state.** Each client address is a flow with its own filter state and
  its own Python module globals, released after a minute of silence — UDP has no close
  to observe, so a timeout is the only thing that can end one.
- **Both directions inspected**, and replies leave through the listener socket so

`REJECT` means something narrower here: there is no connection to close, so the datagram
is simply not forwarded, and the next one from that client is judged afresh.

**If the client's identity matters more than any of that, use NFQUEUE.** It filters UDP
with the real datagrams, from the real client, and a Python filter can rewrite them
exactly — with the kernel still holding the traffic up if the filter dies. That is the
transparent way to filter UDP, and this one is the way to get the proxy layer's chain
and its exact rewriting when you would rather have those.

TPROXY would have given both, and is not used: it leaves no NAT entry to key the return
path off, so it cannot reach a service on this host at all. It was ruled out for that,
before UDP came up.

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
service and nothing else:**

```bash
sudo tcpdump -i firegex0 -w decrypted.pcap
```

No filter expression, no port to look up, and one capture covering the whole instance
rather than one per service. Wireshark takes the same interface live, or opens the file
afterwards. Run it on the **host** running firegex: the container shares the host's
network namespace, so the interface is there. It exists only while some TLS service is
running.

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

A pattern **blocks** the connection:

```
FLAG\{[a-z0-9]+\}   service → client   → FLAG{redacted}
X-Debug: [^\r\n]*    client → service   → X-Debug: off
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

Rewriting is proxy-only, and not because it was left unimplemented: on NFQUEUE a
replacement of a different length desynchronises the stream, and the connection breaks
some time later in a way nobody would trace back to the rule. Starting an NFQUEUE
service with a rewriting pattern is refused, saying so.

Two things to know about a rewrite:

- **The replacement is literal.** No `$1` capture references — hyperscan reports where a
  match is, not what its groups captured, and inventing groups would mean a second engine
  deciding them.
- **It works within one chunk of the stream.** Bytes already forwarded cannot be taken
  back, so a match split across two of them is not rewritten. Blocking has no such limit,
  because a block can still refuse the connection after the fact.

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

The same holds for rewriting: set a pattern to rewrite and the tester shows you what the
sample **becomes**, produced by running the engine's own rewriting code over it rather
than by describing what it would do.

Two details follow from being honest rather than approximate. A pattern is judged against
the mode it will actually run in — blocking matches live streams, rewriting scans blocks,
and hyperscan does not accept quite the same patterns in both — so the tester's verdict is
the one the datapath will reach. And occasionally a pattern is valid, will run, and still
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
  {"id": "traversal",  "pattern": "\\.\\./", "direction": "c2s", "action": "block"},
  {"id": "flag-leak",  "pattern": "FLAG\\{[a-z0-9]+\\}", "direction": "s2c",
   "action": "rewrite", "with": "FLAG{redacted}"}
]
```

It binds the same hyperscan rather than approximating it with Python's `re`, so a
pattern it accepts is one firegex accepts, and one it rejects reports hyperscan's own
message. Where hyperscan is not installed it says so and stops, rather than quietly
answering with a different engine.

Two honest limits. `fgex regex proxy` matches **per chunk**, while a blocking rule on a
real service matches across the whole stream — so a pattern split over two reads is
caught in production and not in the simulator, never the other way round. And the
simulator terminates the connection itself, so it always has the exact rewriting the
proxy layer has, even when you are aiming at an NFQUEUE service.

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
