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

    ALL = (TCP, UDP, TLS)

    @staticmethod
    def l4_of(proto: str) -> str:
        """The transport a rule has to match to catch this service's traffic."""
        return L4.UDP if str(proto) == L4.UDP else L4.TCP


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


class Address:
    """One address a service is protected on.

    A service is one thing to protect and one way of intercepting it; *where* it is
    reachable is a list, because the same service routinely answers on more than one
    address — a v4 and a v6 one, a public and an internal one, two ports of the same
    daemon. Making the operator create one service per address meant keeping their
    filter chains in step by hand, and a chain that drifted was a chain that stopped
    protecting one of them silently.

    The transport protocol is carried here as well as on the service, and is always the
    service's own. Denormalised on purpose: it is what makes `(ip, port, proto)` a
    usable uniqueness key, so a TCP service and a UDP one can share an address the way
    the kernel lets them.
    """

    def __init__(
        self,
        address_id: str,
        service_id: str,
        ip_int: str,
        port: int,
        proto: str = L4.TCP,
        proxy_ip: str | None = None,
        proxy_port: int | None = None,
        **other,
    ):
        self.id = address_id
        self.service_id = service_id
        self.ip_int = ip_int
        self.port = port
        self.proto = proto
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
            "proxy_ip": self.proxy_ip,
            "proxy_port": self.proxy_port,
        }

    @property
    def is_ipv6(self) -> bool:
        return ":" in str(self.ip_int)

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
    def terminates_tls(self) -> bool:
        """Whether the engine decrypts this service's traffic before filtering it.

        Read off what the service speaks rather than held beside it. Only the proxy layer
        can do it: decrypting means terminating the connection, and that is what that
        layer does. It was once orthogonal to the layer, which took an nginx in front of
        NFQUEUE to arrange — so the connection was terminated anyway, and the one
        property that layer has over the other was already gone.
        """
        return str(self.proto) == L4.TLS

    @property
    def l4(self) -> str:
        """The transport the kernel sees, which is what a rule has to match."""
        return L4.l4_of(self.proto)

    @property
    def hands_off(self) -> bool:
        """Whether firegex only steers this traffic rather than inspecting it."""
        return self.transport == TRANSPORT.EXTERNAL

    @property
    def has_ipv6(self) -> bool:
        """Whether any of its addresses is IPv6.

        Decides the family a proxy listener has to be opened in, which is why it is a
        property of the service and not of one address: one listener serves them all.
        """
        return any(addr.is_ipv6 for addr in self.addresses)

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
