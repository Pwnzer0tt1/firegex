"""One nftables owner for both transports.

The rules a service needs depend entirely on how its traffic is intercepted, and
nothing else — not on what filters it runs. That is the whole point of separating the
two layers, and it is why this file dispatches on `srv.transport` and never looks at
a filter.

**NFQUEUE** is the simple half: match the service's address in prerouting and
postrouting, mark the direction, and queue with `bypass` so the kernel keeps
forwarding if userspace stops answering.

**Proxy** has to arrange the return path by hand, because it terminates connections.
The subtle part is that the service must still see the client's address. When the
engine dials the service as the client, two flows look almost identical:

    engine  -> client   src service:port  dst client:client_port   must leave the box
    service -> engine   src service:port  dst client:<ephemeral>   must stay local

No address distinguishes them. Conntrack does: the first belongs to the intercepted,
redirected connection, the second is a separate entry the engine opened itself. So
`ct status dnat` lets the first out, and everything else from a protected service is
marked home. That is what makes source preservation work even with the service on
this very host — which is also the case that ruled tproxy out, since tproxy leaves no
NAT entry to key off and so could never reach a local service at all.
"""

import subprocess

from modules.services.models import TRANSPORT, UPSTREAM, Address, Service
from utils import (
    NFTableManager,
    addr_parse,
    get_interface_ips,
    ip_family,
    ip_parse,
    is_ip_parse,
    nftables_int_to_json,
)

# Direction marks the NFQUEUE binaries read back off a packet.
QUEUE_MARK_INPUT = 0x1337
QUEUE_MARK_OUTPUT = 0x1338

#: How many filters an NFQUEUE service can chain.
#:
#: Each position is its own pair of base chains, because that is what makes a chain
#: possible there at all: a packet a filter accepts carries on to the next base chain in
#: the same hook, so filter order is chain priority order. Eight is not a technical
#: limit, it is a number of always-present chains worth paying for; nothing stops it
#: growing except that every position costs two chains whether or not anyone uses it.
MAX_CHAIN_POSITIONS = 8

#: Where the proxy layer's redirect sits in the prerouting and output hooks.
#:
#: **Before `dstnat` (-100), and that is the whole point.** Docker and podman publish a
#: container's port by appending their own chain to `nat PREROUTING`, which `iptables-nft`
#: registers at exactly `dstnat` — the priority this used to share. Two base chains at one
#: priority in two tables are ordered by neither of them, and measured on a host where the
#: DNAT went first: it rewrote the destination to the container's address, firegex's rule
#: (which matches the *published* address) stopped matching, its counter stayed at zero,
#: and traffic carrying a blocked pattern was answered by the container. The service still
#: read `ACTIVE`. Protection that disappears without saying so is the worst failure this
#: module has, and a race nobody arbitrates is not a thing to leave to luck.
#:
#: So the redirect runs first and the published port is captured before anybody can
#: rewrite it — which is the property the NFQUEUE layer already had for free by living at
#: `raw`, three hundred below any of this. The engine's own dial is not caught by the
#: rule it would otherwise match (`SELF_MARK`), so whatever DNAT the container runtime
#: installs still does its job on the way out, exactly as before.
#:
#: The floor is conntrack at -200: a `nat` chain registered before it has no connection to
#: attach a translation to. Anything between the two behaves identically; this one is far
#: enough from both to leave room.
NAT_PRIORITY = -120

# Shared by the divert rule and the return rule; policy routing keys off it.
PROXY_MARK = 0x1339
# Routing table holding the `local` default that makes marked packets be delivered
# here instead of routed by destination.
PROXY_ROUTE_TABLE = 1339
# Stamped by the engine on the connections it opens. Without excluding it, an
# intercept rule cannot tell the engine's own dial from the traffic it should
# intercept — and where both ends are local, the engine would redirect itself in a
# loop. Deliberately not PROXY_MARK:
# that one means "deliver this here", which would strand an outbound connection.
# Matches `transparent::SELF_MARK` in the engine.
PROXY_SELF_MARK = 0x133A


def resolve_target(srv: Service, addr: Address) -> tuple[str, int] | None:
    """Where one address's rules should point: at the address itself.

    This is the address the **world knocks on**, which is what a rule has to match, and
    it is not always where the service is — see [`service_at`]. The two were one answer
    for as long as firegex was transparent and only transparent, and making this one
    return the other quietly redirected the service's own port twice and left the
    published one unprotected, which is a service that looks configured and answers
    nothing.

    It used to be somewhere else for a TLS service. nginx terminated the connection on
    one derived loopback port and re-encrypted from a second, and the rules were pointed
    at the plaintext leg in between — which is why protecting one address cost two ports
    chosen by hashing `ip:port`, and why those ports could collide with something real.
    The engine terminates TLS itself now, so there is no leg to point at and no port to
    choose: the ciphertext arrives at the address the world dials, and is decrypted
    inside the process that filters it.

    The return type keeps its `None`, because a caller that installs nothing is still
    the right answer for an address that cannot be resolved.
    """
    return addr.ip_int, addr.port


def service_at(srv: Service, addr: Address) -> tuple[str, int] | None:
    """Where the service reached through one address actually is.

    The address itself, unless that address is a **publication**: one daemon answering
    HTTP/1.1 in the clear on `:80` can be reached over TLS on `:443` and over HTTP/3 on a
    UDP port, all three sent back to the port it already listens on. Firegex is then not
    transparent on those addresses, which is the point of them and the reason it is said
    per address rather than per service.

    Everything that *dials* asks this — the UDP and QUIC relays, whose upstream is fixed
    when they are bound, and the TCP listener, which is told through `FGEX_PROXY_TARGETS`
    because one listener fronts every address and recovers each connection's destination
    from conntrack. Everything that *matches* asks [`resolve_target`].
    """
    return addr.ip_int, (addr.target_port or addr.port)


def one_address(ip: str) -> str:
    """Strip any prefix: a rewrite target is one host, never a network.

    Service addresses are normalised to network form (`127.0.0.1/32`) because that is
    what a *match* wants. A `mangle` writes a single address into the packet and refuses
    anything else, so the two cannot share a representation.
    """
    return str(ip).split("/")[0]


def hijack_endpoint(proxy_ip: str | None, service_ip: str) -> str:
    """Where the operator's own proxy listens for one address, as a single host.

    The one spelling of the default, because it is asked in three places that must agree:
    the rule that sends traffic to that proxy, the rule that undoes the rewrite on the way
    back, and the uniqueness check that stops two addresses sharing one endpoint. Loopback
    is where such a proxy normally is, in the family of the address it fronts.

    It is resolved when an address is **written**, not only when its rules are built. The
    column used to be left NULL and defaulted here — and SQLite's UNIQUE treats every NULL
    as distinct, so the partial index meant to forbid two addresses behind one endpoint
    happily accepted any number of them as long as nobody typed the address out. They then
    all resolved to the same loopback port, which is exactly the collision the index exists
    to prevent: the return rule recognises the proxy by address and port, so it could not
    tell them apart on the way out.
    """
    return one_address(proxy_ip or "") or (
        "::1" if ip_family(one_address(service_ip)) == "ip6" else "127.0.0.1"
    )


class NoRelayAddress(Exception):
    """An address a UDP relay cannot be bound for."""


def udp_relay_host(ip: str) -> str:
    """The concrete address a UDP relay binds for `ip`, which may be an interface name.

    A relay has to bind somewhere, and an interface name is not somewhere — so the
    interface's own address stands in for it, resolved when it is needed rather than
    stored, because an interface's address is the host's to change. IPv4 first and
    link-local last: an interface almost always carries a link-local IPv6 address it was
    never configured with, and binding the relay to that one would put the service on an
    address nobody dials.
    """
    if is_ip_parse(ip):
        return one_address(ip)
    candidates = [one_address(addr.split("%")[0]) for addr in get_interface_ips(ip)]
    ordered = sorted(
        candidates,
        key=lambda a: (ip_family(a) == "ip6", a.lower().startswith(("fe80:", "169.254."))),
    )
    if not ordered:
        raise NoRelayAddress(
            f"interface '{ip}' has no IP address assigned, so there is nothing for a "
            f"UDP relay to bind to"
        )
    return ordered[0]


#: Written on the output-hook rules an interface address installs, so they can be found
#: again. There is nothing in the packet that names the interface there — see
#: `interface_addresses` — so the rule says which interface it belongs to itself.
IFACE_COMMENT = "iface "


def interface_addresses(ip: str) -> list[str]:
    """Every address an interface carries right now, as a rule can match them.

    Link-local is left out for the reason `udp_relay_host` takes it last: an interface
    almost always carries an `fe80::` it was never configured with, and nothing dials a
    service there.
    """
    if is_ip_parse(ip):
        return [one_address(ip)]
    return [
        one_address(addr.split("%")[0])
        for addr in get_interface_ips(ip)
        if not addr.lower().startswith(("fe80:", "169.254."))
    ]


def udp_relay_key(ip: str, port: int) -> str:
    """How a UDP relay's upstream is spelled, everywhere it is spelled.

    The engine reports one `UDP <upstream> <port>` line per relay and is asked for a new
    one by the same token, so the transport's map of them, the rule that points traffic
    at one, and the manager adding an address to a running service all have to agree on
    it exactly. Written out at each of those it stops agreeing the first time one of
    them is changed, and the symptom is a service whose UDP silently goes nowhere.
    """
    host = one_address(ip)
    return f"[{host}]:{port}" if ip_family(host) == "ip6" else f"{host}:{port}"


def udp_relay_slot(ip: str, port: int, onward: str) -> str:
    """Which relay carries one address: where it sends, and what is spoken there.

    The engine names each relay this way on its `UDP <slot> <port>` line, and it is what
    the transport's map, the rule that points at a relay and the manager adding an address
    are keyed on. Where it sends alone was not enough: two addresses reaching one service
    port can want different answers — HTTP/3 relayed as QUIC to `udp/443` beside HTTP/3
    turned into HTTPS on `tcp/443` — and an address whose answer was edited on a running
    service was handed the relay it already had, so the new choice reached nothing until a
    restart. `onward` is `UPSTREAM.env(...)`'s word.
    """
    return f"{udp_relay_key(ip, port)}|{onward}"


class InstalledRule:
    """A rule already in the ruleset, matched back to the service that owns it.

    Rules are found by what they match rather than by a handle we remember, so a
    restart that lost its bookkeeping still cleans up after itself.
    """

    def __init__(self, chain: str, handle: int, proto: str, port: int, ip_int: str,
                 packets: int = 0, bytes_: int = 0):
        self.chain = chain
        self.handle = handle
        self.proto = proto
        self.port = int(port)
        self.ip_int = str(ip_int)
        #: What the kernel has counted on this rule.
        self.packets = int(packets)
        self.bytes = int(bytes_)

    def _is(self, ip: str, port: int) -> bool:
        """Whether this rule matches one particular address and port.

        Both halves together, because an installed rule is identified by the pair: the
        two legs of a hand-off match different addresses on **different ports**, and
        comparing the port against only one of them is what made the outbound one
        invisible.
        """
        if self.port != int(port):
            return False
        if is_ip_parse(self.ip_int) and is_ip_parse(ip):
            return ip_parse(self.ip_int) == ip_parse(ip)
        if not is_ip_parse(self.ip_int) and not is_ip_parse(ip):
            return self.ip_int == ip
        return False

    def matches(self, srv: Service, addr: Address) -> bool:
        """Whether this installed rule is one of `addr`'s."""
        # The address already carries the transport the kernel matches on, derived
        # from the service's: `tls` is TCP on the wire.
        if self.proto != str(addr.proto):
            return False
        target = resolve_target(srv, addr)
        if target is None:
            return False
        target_ip, target_port = target
        if self._is(target_ip, target_port):
            return True
        # The return leg of an external hand-off matches the operator's proxy, not the
        # service — **and their port, not the service's**. The port was compared against
        # the service's before either identity was considered, so this branch was only
        # ever reached when the two happened to be the same number: every other hand-off
        # left its outbound rule behind on stop, still rewriting the source of anything
        # from that proxy endpoint, and installed a second copy on the next start.
        if srv.transport == TRANSPORT.EXTERNAL and addr.proxy_port and is_ip_parse(target_ip):
            proxy_ip = hijack_endpoint(addr.proxy_ip, target_ip)
            return self._is(proxy_ip, addr.proxy_port)
        return False

    def matches_any(self, srv: Service, addresses: list[Address]) -> bool:
        return any(self.matches(srv, addr) for addr in addresses)


def _chain(name: str, ctype: str, hook: str, prio: int) -> dict:
    return {
        "add": {
            "chain": {
                "family": "inet",
                "table": FiregexTables.table_name,
                "name": name,
                "type": ctype,
                "hook": hook,
                "prio": prio,
                "policy": "accept",
            }
        }
    }


def _drop_chain(name: str) -> list[dict]:
    return [
        {"flush": {"chain": {"table": FiregexTables.table_name, "family": "inet", "name": name}}},
        {"delete": {"chain": {"table": FiregexTables.table_name, "family": "inet", "name": name}}},
    ]


class FiregexTables(NFTableManager):
    # NFQUEUE transport: one pair of chains per position in the filter chain.
    @staticmethod
    def queue_input_chain(position: int) -> str:
        return f"fgex_queue_in_{position}"

    @staticmethod
    def queue_output_chain(position: int) -> str:
        return f"fgex_queue_out_{position}"

    # External transport: hand the traffic to a proxy the operator runs
    hijack_in_chain = "fgex_hijack_in"
    hijack_local_chain = "fgex_hijack_local"
    hijack_out_chain = "fgex_hijack_out"
    # Proxy transport
    divert_chain = "fgex_divert"
    nat_chain = "fgex_nat"
    nat_output_chain = "fgex_nat_out"
    route_chain = "fgex_route"

    def __init__(self):
        super().__init__(
            [
                *[
                    chain
                    for position in range(MAX_CHAIN_POSITIONS)
                    # Increasing priority means increasing position: netfilter walks the
                    # base chains of a hook in priority order, so this *is* the chain.
                    for chain in (
                        _chain(self.queue_input_chain(position), "filter", "prerouting",
                               -307 + position),
                        _chain(self.queue_output_chain(position), "filter", "postrouting",
                               107 + position),
                    )
                ],
                # Earlier than the queue chains, so traffic destined for somebody else's
                # proxy is redirected before anything here tries to inspect it.
                _chain(self.hijack_in_chain, "filter", "prerouting", -310),
                # Locally generated traffic never reaches prerouting: it goes straight
                # from output to postrouting. Without this chain a hand-off would work
                # for the outside world and silently not for anything on this host —
                # including firegex's own tests, which is how the gap was found.
                _chain(self.hijack_local_chain, "filter", "output", -310),
                _chain(self.hijack_out_chain, "filter", "postrouting", 110),
                # Before conntrack, so a reply to one of the engine's transparent
                # sockets is recognised as ours before anything rewrites it.
                _chain(self.divert_chain, "filter", "prerouting", -150),
                # Installed once, never per service: a packet that already belongs to
                # one of the engine's transparent sockets is a reply to a connection
                # it opened while impersonating a client, and has to be delivered
                # locally rather than forwarded on towards that client.
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": self.table_name,
                            "chain": self.divert_chain,
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"socket": {"key": "transparent"}},
                                        "right": 1,
                                    }
                                },
                                {"mangle": {"key": {"meta": {"key": "mark"}}, "value": PROXY_MARK}},
                                {"accept": None},
                            ],
                        }
                    }
                },
                _chain(self.nat_chain, "nat", "prerouting", NAT_PRIORITY),
                # Locally generated traffic never reaches the nat prerouting hook, and
                # a client on this host protecting a service on this host is exactly that.
                # Same priority for the same reason: a container runtime publishes a port
                # in `nat OUTPUT` as well, so the race is the same one on this hook.
                _chain(self.nat_output_chain, "nat", "output", NAT_PRIORITY),
                # `route`, so changing the mark forces the packet to be re-routed.
                _chain(self.route_chain, "route", "output", -150),
                # Installed once. A packet on the intercepted (redirected) connection
                # is the engine answering a client and has to leave normally; anything
                # else from a protected service is a reply to the engine's own dial,
                # and the per-service rule below marks it home.
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": self.table_name,
                            "chain": self.route_chain,
                            "expr": [
                                {
                                    "match": {
                                        "op": "in",
                                        "left": {"ct": {"key": "status"}},
                                        "right": "dnat",
                                    }
                                },
                                {"accept": None},
                            ],
                        }
                    }
                },
            ],
            [
                *[
                    cmd
                    for position in range(MAX_CHAIN_POSITIONS)
                    for cmd in (
                        *_drop_chain(self.queue_input_chain(position)),
                        *_drop_chain(self.queue_output_chain(position)),
                    )
                ],
                *_drop_chain(self.hijack_in_chain),
                *_drop_chain(self.hijack_local_chain),
                *_drop_chain(self.hijack_out_chain),
                *_drop_chain(self.divert_chain),
                *_drop_chain(self.nat_chain),
                *_drop_chain(self.nat_output_chain),
                *_drop_chain(self.route_chain),
            ],
        )

    #: How the mark and the routing table are spelled to `ip`, derived from the constants
    #: above rather than written out. They were four literal `"0x1339"` and `"1339"`
    #: strings beside the two names that already held those numbers — the shape of drift
    #: this file argues against everywhere else, and the one place where it would be
    #: silent: the policy route would simply point at a table nothing marks.
    PROXY_MARK_ARG = f"{PROXY_MARK:#x}"
    PROXY_TABLE_ARG = str(PROXY_ROUTE_TABLE)

    def _policy_route(self, action: str) -> None:
        """Add or delete the rule and route that bring the engine's return traffic home.

        `check=False` throughout: adding one that is already there and deleting one that
        is not are both the state being asked for, and neither is worth an exception.
        """
        for family in ([], ["-6"]):
            subprocess.run(
                ["ip", *family, "rule", action, "fwmark", self.PROXY_MARK_ARG,
                 "lookup", self.PROXY_TABLE_ARG],
                check=False, stderr=subprocess.DEVNULL,
            )
        if action != "add":
            # The route goes with the rule that reached it, so deleting it is belt and
            # braces rather than a step of its own.
            return
        for family in ([], ["-6"]):
            subprocess.run(
                ["ip", *family, "route", "add", "local", "default", "dev", "lo",
                 "table", self.PROXY_TABLE_ARG],
                check=False, stderr=subprocess.DEVNULL,
            )

    def reset(self):
        super().reset()
        try:
            self._policy_route("del")
        except Exception:
            pass

    def init(self):
        super().init()
        # The `local` default route is what makes marked packets be delivered here
        # instead of routed by destination; without it a preserved-source connection
        # does not fail, it hangs.
        try:
            self._policy_route("add")
        except Exception as e:
            print("Failed to configure ip rules for transparent proxy:", e)

    # --- rule fragments -------------------------------------------------------

    def _not_ours(self) -> list:
        """Skip the connections the engine opened itself."""
        return [
            {
                "match": {
                    "op": "!=",
                    "left": {"meta": {"key": "mark"}},
                    "right": PROXY_SELF_MARK,
                }
            }
        ]

    #: Counted by the kernel on the rules that intercept a service's traffic.
    #:
    #: Free — netfilter already evaluates these rules — and it is the only measure of
    #: "how much arrived" that no filter can skew, because nothing in userspace is
    #: involved in producing it. It counts packets, which is what the wire carries; a
    #: block is a refused connection, so the two are never divided by one another.
    COUNTER = {"counter": {"packets": 0, "bytes": 0}}

    def _match(self, ip: str, port: int, family: str, l4: str, addr: str, field: str) -> list:
        if not is_ip_parse(ip):
            iface_key = "iifname" if addr == "daddr" else "oifname"
            return [
                {
                    "match": {
                        "op": "==",
                        "left": {"meta": {"key": iface_key}},
                        "right": ip,
                    }
                },
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": l4, "field": field}},
                        "right": int(port),
                    }
                },
            ]
        return [
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": family, "field": addr}},
                    "right": nftables_int_to_json(ip),
                }
            },
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": l4, "field": field}},
                    "right": int(port),
                }
            },
        ]

    def _rule(self, chain: str, expr: list, insert: bool = False,
              comment: str | None = None) -> dict:
        verb = "insert" if insert else "add"
        return {
            verb: {
                "rule": {
                    "family": "inet",
                    "table": self.table_name,
                    "chain": chain,
                    "expr": expr,
                    **({"comment": comment} if comment else {}),
                }
            }
        }

    # --- installing -----------------------------------------------------------

    def add(self, srv: Service, addresses: list[Address] | None = None, *,
            queue_nums: list[int] | None = None, proxy_port: int | None = None,
            udp_ports: dict | None = None):
        """Steer a started service's traffic into whatever is now listening for it.

        Always called after the process is up: a rule pointing at a queue nobody is
        reading, or a port nobody is bound to, is worse than no rule at all.

        One address at a time, each skipped if it is already steered. Passing a subset
        is how an address is added to a running service without the others losing their
        connections — the datapath is the same one, only the rules that point at it are
        new.
        """
        installed = self.get()
        for addr in addresses if addresses is not None else srv.addresses:
            if any(rule.matches(srv, addr) for rule in installed):
                continue  # already steered; nothing to do and nothing to duplicate

            target = resolve_target(srv, addr)
            if target is None:
                continue
            target_ip, target_port = target
            is_iface = not is_ip_parse(target_ip)
            family = "ip" if is_iface else ip_family(target_ip)
            l4 = str(addr.proto)

            if srv.transport == TRANSPORT.NFQUEUE:
                self._add_queue(srv, target_ip, target_port, family, l4, queue_nums or [])
            elif srv.transport == TRANSPORT.EXTERNAL:
                self._add_external(srv, addr, target_ip, target_port, family, l4)
            else:
                # UDP is relayed by a socket of its own per address, so the rule points
                # at that address's port rather than at the one shared TCP listener.
                port = proxy_port
                if l4 == "udp":
                    # Keyed by where the relay *sends* and what it speaks there, which is
                    # how the engine reported it: a published address and the service
                    # behind it are two ports, and the relay is filed under the second.
                    service_ip, service_port = service_at(srv, addr)
                    key = udp_relay_slot(udp_relay_host(service_ip), service_port,
                                         UPSTREAM.env(addr.upstream))
                    port = (udp_ports or {}).get(key)
                    if port is None:
                        raise Exception(
                            f"the proxy transport has no UDP relay listening for {key}"
                        )
                self._add_proxy(srv, target_ip, target_port, family, l4, port)

    def _add_queue(self, srv: Service, ip: str, port: int, family: str, l4: str,
                   queue_nums: list[int]):
        """One rule pair per filter, each in the chain that runs at its position.

        A packet a filter accepts goes on to the next base chain in the same hook, so
        the filters see it in position order and the first one to refuse it is the last
        one that sees it. That is the whole mechanism: the chain is the priorities.
        """
        if not queue_nums:
            raise Exception("the nfqueue transport needs at least one queue number")
        if len(queue_nums) > MAX_CHAIN_POSITIONS:
            raise Exception(
                f"the nfqueue transport chains at most {MAX_CHAIN_POSITIONS} filters"
            )
        cmds = []
        for position, queue_num in enumerate(queue_nums):
            # **`bypass` is the service's own fail-open policy, not a constant.** It tells
            # the kernel to accept a packet when nothing is bound to the queue, which is
            # exactly what happens when the interceptor dies — and it was set on every
            # rule regardless. So a service with fail_open *off*, whose whole point is
            # that traffic stops rather than passes when filtering stops, went wide open
            # the moment its binary crashed: the one case the setting exists for. The
            # other half of the same policy is `FIREGEX_NFQUEUE_FAIL_OPEN`, which decides
            # what the process does while it is alive; the two have to agree or the
            # answer depends on how the filtering stopped.
            queue = {"queue": {
                "num": str(queue_num),
                **({"flags": ["bypass"]} if srv.fail_open else {}),
            }}
            cmds.append(self._rule(
                self.queue_output_chain(position),
                self._match(ip, port, family, l4, "saddr", "sport")
                + [
                    self.COUNTER,
                    {"mangle": {"key": {"meta": {"key": "mark"}}, "value": QUEUE_MARK_OUTPUT}},
                    queue,
                ],
                insert=True,
            ))
            cmds.append(self._rule(
                self.queue_input_chain(position),
                self._match(ip, port, family, l4, "daddr", "dport")
                + [
                    self.COUNTER,
                    {"mangle": {"key": {"meta": {"key": "mark"}}, "value": QUEUE_MARK_INPUT}},
                    queue,
                ],
                insert=True,
            ))
        self.cmd(*cmds)

    def _add_external(self, srv: Service, addr: Address, ip: str, port: int, family: str,
                      l4: str):
        """Put somebody else's proxy in the path, invisibly.

        A stateless rewrite rather than NAT: the destination is changed on the way in
        and changed back on the way out, so the operator's proxy sees the connection
        arrive and the client sees answers from the address it dialled. Conntrack is
        not involved, which is what lets this coexist with a service that is also being
        proxied or queued elsewhere.

        The proxy endpoint belongs to the address, not to the service: the return rule
        recognises traffic by the proxy's own address and port and rewrites the source
        port back, so two addresses sharing one proxy endpoint could not be told apart
        on the way out. Every address gets its own.
        """
        if not is_ip_parse(ip):
            raise Exception("the external transport requires a concrete IP address, not an interface")
        if not addr.proxy_port:
            raise Exception("the external transport needs the port your proxy listens on")
        # One host, not a network: a hand-off points at the single address the
        # operator's proxy is listening on, so any prefix a normaliser added is dropped.
        proxy_ip = hijack_endpoint(addr.proxy_ip, ip)
        inbound = self._match(ip, port, family, l4, "daddr", "dport") + [
            self.COUNTER,
            {"mangle": {"key": {"payload": {"protocol": l4, "field": "dport"}},
                        "value": int(addr.proxy_port)}},
            {"mangle": {"key": {"payload": {"protocol": family, "field": "daddr"}},
                        "value": addr_parse(one_address(proxy_ip))}},
        ]
        self.cmd(
            self._rule(self.hijack_in_chain, inbound, insert=True),
            self._rule(self.hijack_local_chain, inbound, insert=True),
            self._rule(
                self.hijack_out_chain,
                self._match(proxy_ip, addr.proxy_port, ip_family(proxy_ip), l4, "saddr", "sport")
                + [
                    {"mangle": {"key": {"payload": {"protocol": l4, "field": "sport"}},
                                "value": int(port)}},
                    {"mangle": {"key": {"payload": {"protocol": ip_family(proxy_ip), "field": "saddr"}},
                                "value": addr_parse(one_address(ip))}},
                ],
                insert=True,
            ),
        )

    def _add_proxy(self, srv: Service, ip: str, port: int, family: str, l4: str, proxy_port: int):
        if proxy_port is None:
            raise Exception("the proxy transport needs a listening port")
        # Conntrack rewrites the destination and remembers the original, which the
        # engine reads back with SO_ORIGINAL_DST. It is also what tells the return
        # rule which packets are the engine answering a client.
        #
        # Both hooks: prerouting catches what arrives from outside, output catches
        # what this host generates, which is the only way a client on this host reaches
        # a service on it. Conntrack NATs a connection once, so a rule in each is not a
        # double translation.
        is_iface = not is_ip_parse(ip)
        # **The match is the interface, and nothing narrower.** Pinning the destination to
        # the addresses the interface carries was tried, to stop a service protecting
        # `docker0:443` from also taking every container's outbound HTTPS — which it does,
        # measured, terminating it with the service's certificate. It was reverted: an
        # interface name exists precisely for the case where **the address is not the
        # operator's to know**, which includes firegex sitting in front of a service on
        # another machine reached through that link, and pinning to this host's own
        # addresses quietly removes that. Protecting an interface protects what crosses
        # it; naming a link that carries other people's traffic is a choice, and the
        # answer to not wanting it is a narrower address, not a narrower rule.
        redirect = (
            self._not_ours()
            + self._match(ip, port, family, l4, "daddr", "dport")
            + [self.COUNTER, {"redirect": {"port": int(proxy_port)}}]
        )
        cmds = [self._rule(self.nat_chain, redirect)]
        cmds.append(
            self._rule(
                self.route_chain,
                self._match(ip, port, family, l4, "saddr", "sport")
                + [{"mangle": {"key": {"meta": {"key": "mark"}}, "value": PROXY_MARK}}],
            )
        )
        if not is_iface:
            cmds.append(self._rule(self.nat_output_chain, redirect))
        else:
            # An interface address has to be caught in the output hook too, and cannot be
            # caught the same way. `iifname` means nothing for a packet this host is
            # generating, and `oifname` is the wrong question twice over: `oifname eth0
            # dport 80` would mean *we* are calling somebody else's port 80, which is the
            # host's own outbound traffic and none of firegex's business — and a
            # connection from this host to one of its **own** addresses is routed through
            # `lo` anyway, so it would never match.
            #
            # So the destination is matched instead, against the addresses that interface
            # carries. That is exactly "this host calling a service it protects", and it
            # is what an operator means when they protect `lo` and then curl `127.0.0.1`.
            # Without it the service was intercepted for the outside world and silently
            # not for anything on the box, which is the shape of an interception canary
            # failing and is how this was reported.
            #
            # The addresses are resolved now rather than stored, and that is the cost:
            # one the interface gains later is not covered *for traffic this host
            # generates* until the service restarts. Inbound keeps matching `iifname`, so
            # it follows the interface as it always did. `udp_relay_host` pays the same
            # price for the same reason.
            #
            # The rule carries the interface's name as a comment because nothing else in
            # it does. `delete()` finds a rule by what it matches, and these match an
            # address; without the comment they would be left behind on every stop — a
            # redirect to a port nobody is listening on any more.
            for addr in interface_addresses(ip):
                cmds.append(self._rule(
                    self.nat_output_chain,
                    self._not_ours()
                    + self._match(addr, port, ip_family(addr), l4, "daddr", "dport")
                    + [self.COUNTER, {"redirect": {"port": int(proxy_port)}}],
                    comment=f"{IFACE_COMMENT}{ip}",
                ))
        self.cmd(*cmds)

    # --- reading back ---------------------------------------------------------

    def get(self) -> list[InstalledRule]:
        res = []
        chains = [
            *[self.queue_input_chain(p) for p in range(MAX_CHAIN_POSITIONS)],
            *[self.queue_output_chain(p) for p in range(MAX_CHAIN_POSITIONS)],
            self.hijack_in_chain,
            self.hijack_local_chain,
            self.hijack_out_chain,
            self.divert_chain,
            self.nat_chain,
            self.nat_output_chain,
            self.route_chain,
        ]
        for rule in self.list_rules(tables=[self.table_name], chains=chains):
            try:
                expr = rule["expr"]
                # An intercept rule starts with the self-mark exclusion; every other
                # per-service rule starts with the address. The two rules init()
                # installs match on `socket` or on `ct`, and fall out here.
                if "meta" in expr[0].get("match", {}).get("left", {}):
                    if expr[0].get("match", {}).get("left", {}).get("meta", {}).get("key") == "mark":
                        expr = expr[1:]
                match_left = expr[0].get("match", {}).get("left", {})
                if "payload" in match_left:
                    right = expr[0]["match"]["right"]
                    if isinstance(right, str):
                        ip_int = str(ip_parse(right))
                    else:
                        ip_int = f'{right["prefix"]["addr"]}/{right["prefix"]["len"]}'
                elif "meta" in match_left and match_left["meta"].get("key") in ("iifname", "oifname"):
                    ip_int = str(expr[0]["match"]["right"])
                else:
                    continue
                # An output-hook rule installed for an interface matches one of that
                # interface's addresses, so what it matches does not say whose it is.
                # The comment does, and reading it back here is what lets the rest of
                # this file go on treating the rule as the interface's — including
                # `delete()`, which would otherwise never find it.
                note = str(rule.get("comment") or "")
                if note.startswith(IFACE_COMMENT):
                    ip_int = note[len(IFACE_COMMENT):]
                counter = next(
                    (e["counter"] for e in expr if isinstance(e, dict) and "counter" in e),
                    {},
                )
                res.append(
                    InstalledRule(
                        chain=rule["chain"],
                        handle=int(rule["handle"]),
                        proto=expr[1]["match"]["left"]["payload"]["protocol"],
                        port=expr[1]["match"]["right"],
                        ip_int=ip_int,
                        packets=counter.get("packets", 0),
                        bytes_=counter.get("bytes", 0),
                    )
                )
            except (KeyError, TypeError, IndexError):
                continue  # a rule of a shape we did not write; not ours to touch
        return res

    def traffic(self, srv: Service, addresses: list[Address] | None = None) -> dict:
        """How much has arrived for this service, counted by the kernel.

        Only the *inbound* rules, and only one of them per address. The nfqueue layer
        installs a rule pair per filter, all seeing the same packets, so summing them
        would multiply the answer by the length of the chain; and the return-path rules
        count traffic going the other way, which is a different question. Position zero
        is the first filter in the chain, so it sees everything.

        Packets, never connections: this is what the wire carried. A block is a refused
        connection, so the two are reported side by side and never divided.
        """
        # Only the layers whose rules the kernel evaluates for **every** packet.
        #
        # The proxy layer's rule lives in a `nat` chain, and conntrack translates a
        # connection once: every packet after the first is handled from the conntrack
        # entry without the rule being walked again. Its counter therefore counts new
        # connections, not packets — a perfectly good number, and not the one the label
        # says. The engine already reports connections properly, so this reports nothing
        # there rather than a packet count that is off by the length of every flow.
        inbound = {
            TRANSPORT.NFQUEUE: {self.queue_input_chain(0)},
            TRANSPORT.EXTERNAL: {self.hijack_in_chain, self.hijack_local_chain},
        }.get(srv.transport, set())
        targets = addresses if addresses is not None else srv.addresses
        packets = total_bytes = 0
        for rule in self.get():
            if rule.chain in inbound and rule.matches_any(srv, targets):
                packets += rule.packets
                total_bytes += rule.bytes
        return {"packets": packets, "bytes": total_bytes}

    def delete(self, srv: Service, addresses: list[Address] | None = None):
        """Take back the rules for these addresses, or for all of the service's.

        Passing a subset is how one address is removed from a running service: the
        others keep their rules, and the datapath keeps their connections.
        """
        targets = addresses if addresses is not None else srv.addresses
        cmds = [
            {
                "delete": {
                    "rule": {
                        "family": "inet",
                        "table": self.table_name,
                        "chain": rule.chain,
                        "handle": rule.handle,
                    }
                }
            }
            for rule in self.get()
            if rule.matches_any(srv, targets)
        ]
        if cmds:
            self.cmd(*cmds)
