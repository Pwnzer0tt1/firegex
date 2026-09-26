"""The one service model: a network layer, and an ordered chain of filters on it.

Firegex used to have a module per combination — `nfregex` was NFQUEUE plus regexes,
`nfproxy` was NFQUEUE plus Python, `porthijack` was a redirect, `tls` was its own module — and
each one owned its own services, its own page and its own database. Choosing how to
inspect traffic therefore also chose how to intercept it, and the two have nothing to
do with each other.

Here they are separate. A [`Service`] says only where the traffic is and how to get
hold of it; a [`Filter`] says what to do with it. Any filter runs on any transport
that can host it, and the service does not have to be recreated to change either.
"""

import base64
import uuid

from utils import is_ip_parse


class TRANSPORT:
    """How the traffic is intercepted."""

    #: Packets are queued to userspace and a verdict is handed back to the kernel.
    #: Nothing is terminated, so the service sees the original connection, and the
    #: kernel keeps forwarding if the filter dies. It cannot rewrite a payload
    #: without desynchronising the stream.
    NFQUEUE = "nfqueue"
    #: The connection is terminated and reopened towards the service. That buys exact
    #: rewriting, kernel-side reassembly, backpressure and TLS; it costs the kernel's
    #: fail-open backstop, which the engine rebuilds itself.
    PROXY = "proxy"
    #: The traffic is handed to a proxy the operator runs themselves, by rewriting the
    #: destination on the way in and undoing it on the way out. Firegex inspects
    #: nothing here — it only arranges for their proxy to be in the path — so no filter
    #: can be attached. It is the escape hatch for a protocol nothing built in
    #: understands.
    EXTERNAL = "external"

    ALL = (NFQUEUE, PROXY, EXTERNAL)


class L4:
    """What a service speaks on the wire. A property of the service.

    `tls` sits beside `tcp` and `udp` rather than being a flag on top of one of them,
    because that is the shape of the thing: a service speaks TLS or it does not, and
    "TLS" is what an operator would answer if asked what is on the wire. It used to be a
    boolean, which made three combinations representable that are not real — TLS on a
    UDP service, on the nfqueue layer, and on a hand-off — and each of them had to be
    caught by a check written by hand. Two of those are now unrepresentable instead.

    What the *kernel* matches on is a different question with a smaller answer, which is
    what `l4_of` gives: an address carries that, so `(ip, port, proto)` stays a key that
    means what it says. Without it a TCP service and a TLS service could both claim one
    `ip:port`, which on the wire is the same port twice.
    """

    TCP = "tcp"
    UDP = "udp"
    #: TLS over TCP, terminated by the engine.
    TLS = "tls"
    #: QUIC, terminated by the engine. UDP on the wire, TLS 1.3 inside it, and streams
    #: inside that — which is the only reason a filter has anything to look at: once past
    #: the Initial packet, QUIC encrypts the frames and the stream boundaries along with
    #: the payload, so a layer that forwards has nothing to show anybody.
    QUIC = "quic"
    #: Every version of HTTP, on whichever transport each address carries it.
    #:
    #: The odd one out, and deliberately so. The other four say what is on the wire;
    #: this one says what the *service* is, and lets each address say how it is reached
    #: — `:80` in the clear, `:443` under TLS, `:443/udp` under QUIC. One service, one
    #: chain, one certificate, and HTTP/1.1, HTTP/2 and HTTP/3 all rendered to the
    #: filters as the same HTTP/1.1.
    #:
    #: It exists because the alternative was two or three services with hand-copied
    #: filter chains: HTTP/1.1 and HTTP/2 live on `tls` (TCP) and HTTP/3 on `quic`
    #: (UDP), and a chain that has to be kept in step by hand is a chain that stops
    #: protecting one of them silently — the same argument that put several addresses
    #: under one service in the first place.
    #:
    #: Nothing about the *kernel* becomes ambiguous, because nothing here is asked of
    #: the kernel: each address still carries its own `tcp` or `udp`, which is what the
    #: rules match and what `(ip, port, proto)` is keyed on. What the connection turns
    #: out to be — TLS or not, HTTP/2 or not — is decided by the engine per connection,
    #: from what the client actually sent.
    HTTP = "http"

    ALL = (TCP, UDP, TLS, QUIC, HTTP)

    @staticmethod
    def l4_of(proto: str) -> str:
        """The transport a rule has to match to catch this service's traffic.

        Two of the four are the other two wearing a hat: `tls` is TCP on the wire and
        `quic` is UDP. That is what keeps `(ip, port, proto)` a key meaning what it says
        — without it a TLS service and a TCP one, or a QUIC service and a UDP one, could
        each claim one `ip:port` between them, which on the wire is the same port twice.

        `http` answers `tcp` here, which is the right *default* for an address that does
        not say otherwise and never the whole answer: an `http` service's addresses each
        carry their own, because it is the one protocol whose addresses are not all on
        the same transport. Ask `Service.carries` rather than the service's protocol
        whenever the question is about the kernel.
        """
        return L4.UDP if str(proto) in (L4.UDP, L4.QUIC) else L4.TCP

    @staticmethod
    def edges_of(proto: str) -> tuple[str, ...]:
        """Which transports an address of this service may be reached on.

        One for every protocol but `http`, which is the point of `http`.
        """
        if str(proto) == L4.HTTP:
            return (L4.TCP, L4.UDP)
        return (L4.l4_of(proto),)


class PROTO:
    """Which application protocol a Python filter is written against.

    Never chosen: **read off the filter's own code**. The library decides when a filter
    is called from what its parameters are annotated with, so asking for an
    `HttpRequest` is what makes a file an HTTP filter and asking only for a `RawPacket`
    is what makes one protocol-agnostic. Stored here so the interface can show it and
    so a chain can be described without executing anything; the code remains the only
    thing that decides it.

    A file that asks for two *different* application protocols is refused when it is
    saved, naming both functions — a connection is only ever one of them.
    """

    TCP = "tcp"
    HTTP = "http"

    ALL = (TCP, HTTP)


class KIND:
    """What a filter is."""

    #: Patterns matched by hyperscan. Both transports match with the same library, so
    #: a pattern means the same thing wherever it runs.
    REGEX = "regex"
    #: The user's own Python, running out of process.
    PYFILTER = "pyfilter"

    ALL = (REGEX, PYFILTER)


class STATUS:
    STOP = "stop"
    ACTIVE = "active"


# A matching pattern closes the connection. There is no second action, and there is no
# `action` column any more.
#
# There used to be `rewrite`: replace the matched bytes and let the traffic continue. It
# was removed because it could not keep the promise it made. Rewriting scanned one chunk
# at a time — bytes already forwarded cannot be taken back, so a match straddling two
# chunks was never rewritable — and the result was measured: a pattern sent whole reached
# the service rewritten, and the same pattern split across two TCP segments reached it
# *intact*. Blocking, which scans in hyperscan's stream mode, caught the split version.
#
# So the failure was silent and the operator had no way to see it: no block, no log, no
# counter, just a rewrite rule that had quietly not applied. A filter that works on the
# sender's segmentation is worse than no filter, because it is trusted. Blocking is the
# verdict this can honestly offer on a stream, so it is the only one offered.


class MODE:
    """Which half of the traffic a pattern is matched against."""

    CLIENT_TO_SERVER = "C"
    SERVER_TO_CLIENT = "S"
    BOTH = "B"

    ALL = (CLIENT_TO_SERVER, SERVER_TO_CLIENT, BOTH)


class UPSTREAM:
    """What the service *behind one address* speaks.

    The engine used to have one answer and never asked: whatever the client spoke, the
    service was assumed to speak too — a TLS connection was re-encrypted on the way out,
    a QUIC one re-encoded as QUIC. That is right whenever firegex is carrying somebody
    else's encryption, and wrong in the case an operator most often has, which is a
    service that speaks neither and never will.

    So it is three answers now, and they are about the *service*, not about the client:

    * `same` — it speaks what the client spoke. The default, and what every service did
      before there was a choice;
    * `tcp` — it answers in the clear. Firegex terminates the client's TLS or QUIC and
      forwards the plaintext, which makes firegex the thing that *adds* the encryption
      rather than the thing that carries it;
    * `tls` — it speaks TLS, whatever the client used to get here. On a TLS service that
      is `same` by another name; under QUIC it is the one that matters, because it is
      how an HTTPS-only service is reached from an HTTP/3 client.

    Under QUIC the last two are not a pass-through: HTTP/3 has no cleartext form, so what
    reaches the service is the HTTP/1.1 the filters were already being shown. That is the
    one place in the engine where what leaves is not the version that arrived, and it is
    only ever the operator's explicit choice.
    """

    SAME = "same"
    TCP = "tcp"
    TLS = "tls"

    ALL = (SAME, TCP, TLS)

    @staticmethod
    def env(upstream: str) -> str:
        """What the engine is told. One variable, because it is one question."""
        return {UPSTREAM.TCP: "plain", UPSTREAM.TLS: "tls"}.get(str(upstream), "same")


class Address:
    """One address a service is protected on.

    A service is one thing to protect and one way of intercepting it; *where* it is
    reachable is a list, because the same service routinely answers on more than one
    address — a v4 and a v6 one, a public and an internal one, two ports of the same
    daemon. Making the operator create one service per address meant keeping their
    filter chains in step by hand, and a chain that drifted was a chain that stopped
    protecting one of them silently.

    The transport protocol is carried here as well as on the service. Denormalised on
    purpose: it is what makes `(ip, port, proto)` a usable uniqueness key, so a TCP
    service and a UDP one can share an address the way the kernel lets them. It is
    derived — `L4.l4_of(edge)` — because `tls` is TCP on the wire and `quic` is UDP, and
    what the kernel matches is a smaller question than what the address carries.

    Two things an address says for itself, and both are why it says anything at all:
    **what is spoken at it** (`edge`) and **where that traffic goes** (`target_port`).
    Firegex was transparent and only transparent — the client dialled the service's own
    address and the engine dialled it back as the client — which meant a service could
    only be protected where it already listened. One service answering in the clear on
    `:80`, reached over TLS on `:443` and over HTTP/3 on a UDP port, is three rows
    pointing at one port.
    """

    def __init__(
        self,
        address_id: str,
        service_id: str,
        ip_int: str,
        port: int,
        proto: str = L4.TCP,
        edge: str | None = None,
        target_port: int | None = None,
        upstream: str = UPSTREAM.SAME,
        proxy_ip: str | None = None,
        proxy_port: int | None = None,
        **other,
    ):
        self.id = address_id
        self.service_id = service_id
        self.ip_int = ip_int
        self.port = port
        self.proto = proto
        #: What clients speak *at this address*: one of `tcp`, `tls`, `udp`, `quic` —
        #: the same words a service speaks, minus `http`, which is the one that means
        #: "ask the addresses". For every protocol but that one it is the service's own
        #: and the operator never sees it; on an `http` service it is the choice, and it
        #: is what decides whether this address needs a certificate behind it and which
        #: transport the kernel matches.
        self.edge = str(edge or proto)
        #: Where the traffic that arrives here is actually sent, when that is not the
        #: port it arrived on. `None` is the transparent case and the default: firegex
        #: dials the address the client dialled, as the client, and the service sees
        #: exactly what it would have seen without any of this.
        #:
        #: Set, this address is a *publication*: one service answered on `:80` in the
        #: clear and reached on `:443` under TLS, or on a QUIC port, without moving. The
        #: address is where the world knocks; this is where the service is.
        self.target_port = int(target_port) if target_port else None
        #: What the service *behind this address* speaks. See [`UPSTREAM`]. It belongs to
        #: the address rather than to the service because that is where the question has
        #: an answer: one daemon is reached over TLS on one port and in the clear on
        #: another, and what firegex does on the way out is a property of the way in.
        self.upstream = str(upstream or UPSTREAM.SAME)
        #: Where the operator's own proxy is listening for *this* address. Only for
        #: `external`, and per address rather than per service: the return rule rewrites
        #: the source port back to the original one, so two addresses handed to the same
        #: proxy endpoint could not be told apart on the way out.
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port

    @classmethod
    def from_dict(cls, var: dict):
        return cls(**var)

    def to_dict(self) -> dict:
        return {
            "address_id": self.id,
            "service_id": self.service_id,
            "ip_int": self.ip_int,
            "port": self.port,
            "proto": self.proto,
            "edge": self.edge,
            "target_port": self.target_port,
            "upstream": self.upstream,
            "proxy_ip": self.proxy_ip,
            "proxy_port": self.proxy_port,
        }

    @property
    def is_interface(self) -> bool:
        return not is_ip_parse(self.ip_int)

    @property
    def is_ipv6(self) -> bool:
        return ":" in str(self.ip_int) if not self.is_interface else False

    def __repr__(self):
        return f"<Address {self.ip_int}:{self.port}/{self.proto}>"


class Service:
    """One protected endpoint and the transport in front of it."""

    def __init__(
        self,
        service_id: str,
        name: str,
        status: str,
        proto: str,
        transport: str,
        fail_open: bool = True,
        max_connections: int = 0,
        over_limit_forwards: bool = False,
        first_byte_timeout: int = 0,
        tls_cert: str | None = None,
        tls_key: str | None = None,
        addresses: list | None = None,
        **other,
    ):
        self.id = service_id
        self.name = name
        self.status = status
        self.proto = proto
        self.transport = transport
        self.fail_open = bool(fail_open)
        #: How many connections or UDP flows may be carried at once; 0 means no limit.
        self.max_connections = max(0, int(max_connections or 0))
        #: Whether what does not fit is forwarded with no filter in front of it.
        self.over_limit_forwards = bool(over_limit_forwards)
        #: Seconds a connection may carry nothing at all before it is closed; 0 is never.
        self.first_byte_timeout = max(0, int(first_byte_timeout or 0))
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        #: Every address this service is protected on. Filled by whoever read the
        #: service out of the database; a service with none is configured but
        #: unreachable, and starting it installs no rules.
        self.addresses: list[Address] = list(addresses or [])

    @classmethod
    def from_dict(cls, var: dict):
        return cls(**var)

    @property
    def decrypts(self) -> bool:
        """Whether the engine decrypts this service's traffic before filtering it.

        Read off what the service speaks rather than held beside it. Only the proxy layer
        can do it: decrypting means terminating the connection, and that is what that
        layer does. It was once orthogonal to the layer, which took an nginx in front of
        NFQUEUE to arrange — so the connection was terminated anyway, and the one
        property that layer has over the other was already gone.

        Named for what it does rather than for TLS, because two protocols do it now and
        QUIC is the one with no alternative: TLS over TCP can at least be carried past
        unopened, while a QUIC packet past the handshake has its frames encrypted too.
        Both need the same thing from the operator, which is a certificate.

        `http` is in the list because a certificate is the whole of what it adds: a
        cleartext HTTP service is already `tcp`, and HTTP/2 in the clear is recognised
        there from the connection preface whatever the service is called. What `http`
        buys over that is the TLS and the QUIC edges, and neither exists without one.
        """
        return str(self.proto) in (L4.TLS, L4.QUIC, L4.HTTP)

    @property
    def l4(self) -> str:
        """The transport the kernel sees, which is what a rule has to match.

        Only meaningful where a service has one. An `http` service is reached on both,
        and everything that used to ask this of such a service asks `carries` instead:
        the answer here is its addresses' default, not a claim about all of them.
        """
        return L4.l4_of(self.proto)

    def carries(self, l4: str) -> bool:
        """Whether any of this service's addresses is reached over `l4`.

        The question every rule, listener and relay actually has, and the one that
        stopped having a single answer when `http` arrived. A service with no addresses
        yet is answered from its protocol, so a check made at creation — before there is
        an address to look at — still means something.
        """
        if not self.addresses:
            return l4 in L4.edges_of(self.proto)
        return any(L4.l4_of(addr.proto or self.proto) == l4 for addr in self.addresses)

    @property
    def udp_addresses(self) -> list:
        """The addresses that need a relay of their own: datagrams, and QUIC."""
        return [
            addr
            for addr in self.addresses
            if L4.l4_of(addr.proto or self.proto) == L4.UDP
        ]

    @property
    def has_ipv6(self) -> bool:
        """Whether any of its addresses is IPv6.

        Decides the family a proxy listener has to be opened in, which is why it is a
        property of the service and not of one address: one listener serves them all.
        """
        return any(addr.is_ipv6 for addr in self.addresses)

    @property
    def has_ipv6_tcp(self) -> bool:
        """Whether the *TCP* listener needs to be able to accept IPv6.

        The narrower question, and the one worth asking before rebuilding a service: the
        only listener that can have its family wrong is the TCP one. Everything relayed
        per address — datagrams, and QUIC — binds a socket in the family of the address
        when it arrives. On an `http` service the two sit side by side, so an IPv6 HTTP/3
        address must not cost every TCP connection on the service a restart it did not
        need.
        """
        udp = {addr.id for addr in self.udp_addresses}
        return any(addr.is_ipv6 for addr in self.addresses if addr.id not in udp)

    def to_dict(self) -> dict:
        # The certificate goes out, the key never does: it is write-only from the
        # API's point of view, and a service listing is the easiest place to leak it.
        return {
            "service_id": self.id,
            "name": self.name,
            "status": self.status,
            "proto": self.proto,
            "transport": self.transport,
            "fail_open": self.fail_open,
            "addresses": [addr.to_dict() for addr in self.addresses],
        }


class Filter:
    """One link in a service's chain."""

    def __init__(
        self,
        filter_id: str,
        service_id: str,
        position: int,
        kind: str,
        name: str,
        active: bool,
        proto: str = PROTO.TCP,
        blocked: int = 0,
        **other,
    ):
        self.id = filter_id
        self.service_id = service_id
        self.position = position
        self.kind = kind
        self.name = name
        self.active = bool(active)
        self.proto = proto
        self.blocked = blocked

    @classmethod
    def from_dict(cls, var: dict):
        return cls(**var)

    def to_dict(self) -> dict:
        return {
            "filter_id": self.id,
            "service_id": self.service_id,
            "position": self.position,
            "kind": self.kind,
            "name": self.name,
            "active": self.active,
            "proto": self.proto,
            "blocked": self.blocked,
        }


class Regex:
    """One pattern inside a regex filter.

    Stored base64-encoded because a pattern is bytes, not text: matching a raw byte
    sequence is a normal thing to want, and JSON has no way to carry one.
    """

    def __init__(
        self,
        regex_id: str,
        filter_id: str,
        regex: bytes,
        mode: str,
        case_sensitive: bool,
        active: bool,
        blocked: int = 0,
        **other,
    ):
        self.id = regex_id
        self.filter_id = filter_id
        self.regex = regex
        self.mode = mode
        self.case_sensitive = bool(case_sensitive)
        self.active = bool(active)
        self.blocked = blocked

    @classmethod
    def from_dict(cls, var: dict):
        var = dict(var)
        var["regex"] = base64.b64decode(var["regex"])
        return cls(**var)

    def to_dict(self) -> dict:
        return {
            "regex_id": self.id,
            "filter_id": self.filter_id,
            "regex": base64.b64encode(self.regex).decode(),
            "mode": self.mode,
            "case_sensitive": self.case_sensitive,
            "active": self.active,
            "blocked": self.blocked,
        }

    @property
    def is_input(self) -> bool:
        return self.mode in (MODE.CLIENT_TO_SERVER, MODE.BOTH)

    @property
    def is_output(self) -> bool:
        return self.mode in (MODE.SERVER_TO_CLIENT, MODE.BOTH)


def new_id() -> str:
    return str(uuid.uuid4())
