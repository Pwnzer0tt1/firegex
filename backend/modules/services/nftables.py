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

from modules.services.models import TRANSPORT, Address, Service
from utils import NFTableManager, addr_parse, ip_family, ip_parse, nftables_int_to_json

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


def one_address(ip: str) -> str:
    """Strip any prefix: a rewrite target is one host, never a network.

    Service addresses are normalised to network form (`127.0.0.1/32`) because that is
    what a *match* wants. A `mangle` writes a single address into the packet and refuses
    anything else, so the two cannot share a representation.
    """
    return str(ip).split("/")[0]


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
        if self.port == int(target_port) and ip_parse(self.ip_int) == ip_parse(target_ip):
            return True
        # The return leg of an external hand-off matches the operator's proxy, not the
        # service. Recognising only the inbound rule would leave the outbound one behind
        # every time a service was stopped, and it would keep rewriting.
        if srv.transport == TRANSPORT.EXTERNAL and addr.proxy_port:
            proxy_ip = one_address(addr.proxy_ip or "") or (
                "::1" if ip_family(target_ip) == "ip6" else "127.0.0.1"
            )
            return self.port == int(addr.proxy_port) and ip_parse(self.ip_int) == ip_parse(proxy_ip)
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
                _chain(self.nat_chain, "nat", "prerouting", -100),
                # Locally generated traffic never reaches the nat prerouting hook, and
                # a client on this host protecting a service on this host is exactly that.
                _chain(self.nat_output_chain, "nat", "output", -100),
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

    def reset(self):
        super().reset()
        import subprocess
        try:
            subprocess.run(["ip", "rule", "del", "fwmark", "0x1339", "lookup", "1339"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "-6", "rule", "del", "fwmark", "0x1339", "lookup", "1339"], check=False, stderr=subprocess.DEVNULL)
            # Route rules are often automatically deleted when the rule goes or don't error out if missing, but let's be explicit
        except Exception:
            pass

    def init(self):
        super().init()
        import subprocess
        # Configure ip rules for proxy transparent return path
        try:
            # We don't care about errors if rules already exist etc, but we'll try to add them
            subprocess.run(["ip", "rule", "add", "fwmark", "0x1339", "lookup", "1339"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "-6", "rule", "add", "fwmark", "0x1339", "lookup", "1339"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "route", "add", "local", "default", "dev", "lo", "table", "1339"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "1339"], check=False, stderr=subprocess.DEVNULL)
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

    def _rule(self, chain: str, expr: list, insert: bool = False) -> dict:
        verb = "insert" if insert else "add"
        return {
            verb: {
                "rule": {
                    "family": "inet",
                    "table": self.table_name,
                    "chain": chain,
                    "expr": expr,
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
            family = ip_family(target_ip)
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
                    key = (
                        f"[{one_address(target_ip)}]:{target_port}"
                        if family == "ip6" else f"{one_address(target_ip)}:{target_port}"
                    )
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
            queue = {"queue": {"num": str(queue_num), "flags": ["bypass"]}}
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
        if not addr.proxy_port:
            raise Exception("the external transport needs the port your proxy listens on")
        # One host, not a network: a hand-off points at the single address the
        # operator's proxy is listening on, so any prefix a normaliser added is dropped.
        proxy_ip = one_address(addr.proxy_ip or "") or ("::1" if family == "ip6" else "127.0.0.1")
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
        redirect = (
            self._not_ours()
            + self._match(ip, port, family, l4, "daddr", "dport")
            + [self.COUNTER, {"redirect": {"port": int(proxy_port)}}]
        )
        self.cmd(
            self._rule(self.nat_chain, redirect),
            self._rule(self.nat_output_chain, redirect),
            # Source preservation is not optional. A protected service that suddenly
            # sees one address for the whole internet is a silent regression against
            # the NFQUEUE transport, and the operator would find out from their own
            # rate limiter rather than from us.
            self._rule(
                self.route_chain,
                self._match(ip, port, family, l4, "saddr", "sport")
                + [{"mangle": {"key": {"meta": {"key": "mark"}}, "value": PROXY_MARK}}],
            ),
        )

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
                    expr = expr[1:]
                if "payload" not in expr[0].get("match", {}).get("left", {}):
                    continue
                right = expr[0]["match"]["right"]
                if isinstance(right, str):
                    ip_int = str(ip_parse(right))
                else:
                    ip_int = f'{right["prefix"]["addr"]}/{right["prefix"]["len"]}'
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
