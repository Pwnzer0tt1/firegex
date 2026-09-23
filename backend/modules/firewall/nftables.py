"""The plain-nftables firewall, in tables of firegex's own.

**Everything here is named `fgex_`, and that is not only cosmetic.** This module used to
write into the tables called `filter` and `mangle` — the ones `iptables-nft` claims —
putting base chains named INPUT and FORWARD beside iptables' own and setting their
policy. Two things went wrong with that, and both were reported from real hosts:

* **iptables stops working.** `iptables-nft` refuses a whole table as soon as it holds
  one rule it cannot express in its own format, and the first thing this module writes
  is a native `ct state` match — iptables stores that as an `xt` match blob instead. From
  then on `iptables -L`, `iptables-save` and everything built on them answer
  ``table `filter' is incompatible, use 'nft' tool``, on a box where Docker, ufw,
  fail2ban or the organisers' own scripts are the ones asking. It took nothing exotic to
  trigger: `allow_established` and `drop_invalid` are the two settings that write `ct
  state`, and both are on in any sane configuration.
* **Stopping firegex opened the host.** `reset()` set the policy of `filter INPUT` back
  to `accept`, and that chain belonged to the *administrator*: a host carrying a
  default-deny policy had it quietly removed the moment the firegex firewall was
  disabled.

Owning the tables fixes both by construction: a base chain carries its own policy
wherever it lives, so default-deny is expressed exactly as before, and a `drop` is
terminal no matter which table's chain reached it. What changes is that firegex now
*adds* a layer instead of taking over somebody else's — an `accept` here means "firegex
does not block this", never "nothing else will", which is what it already meant in
practice. Everything installed is visible under one prefix and removed by deleting two
tables per family.

One thing did change, and `dnat_rules` is what puts it back: sharing iptables' own
`FORWARD` chain, traffic Docker or podman accepted for a published port never met
firegex's policy, while a chain of our own is evaluated on its own — so a drop policy
dropped every connection to a published container port. `allow_dnat` (on by default)
leaves destination-NATed traffic no rule of ours matched to the rules that published it.
"""

from modules.firewall.models import FirewallSettings, Action, Rule, Protocol, Mode, Table
from utils import nftables_int_to_json, ip_family, NFTableManager, is_ip_parse
import copy

#: Where a rule's `table` — which is the operator's word, stored in the database and
#: shown in the interface — actually lands. The two are deliberately not the same string
#: any more: "filter" and "mangle" describe what a rule *does*, and used to double as the
#: name of somebody else's table.
NFT_TABLES = {
    Table.FILTER: "fgex_filter",
    Table.MANGLE: "fgex_mangle",
}


class FiregexTables(NFTableManager):
    rules_chain_in = "fgex_rules_in"
    rules_chain_out = "fgex_rules_out"
    rules_chain_fwd = "fgex_rules_fwd"
    filter_table = NFT_TABLES[Table.FILTER]
    mangle_table = NFT_TABLES[Table.MANGLE]

    #: The base chains, and the one rules chain each of them hands over to. Hook and
    #: priority are the same ones the rules used to be evaluated at, so what reaches a
    #: rule is unchanged; only the table around it is firegex's.
    base_chains = [
        # (table, chain, hook, priority, follows the configured policy)
        ("filter", "fgex_input", "input", 0, True, rules_chain_in),
        ("filter", "fgex_forward", "forward", 0, True, rules_chain_fwd),
        ("filter", "fgex_output", "output", 0, False, rules_chain_out),
        ("mangle", "fgex_prerouting", "prerouting", -150, False, rules_chain_in),
        ("mangle", "fgex_postrouting", "postrouting", -150, False, rules_chain_out),
    ]

    #: The rules chains, and which table each lives in. `fgex_rules_fwd` is filter-only:
    #: mangle has no forward hook in this layout, which is why a mangle rule in forward
    #: mode is refused by the router before it gets here.
    rules_chains = [
        ("filter", rules_chain_in), ("filter", rules_chain_out), ("filter", rules_chain_fwd),
        ("mangle", rules_chain_in), ("mangle", rules_chain_out),
    ]

    def _table(self, which: str) -> str:
        return self.filter_table if which == "filter" else self.mangle_table

    def _skeleton(self, policy: str):
        """Everything that has to exist before a single rule can be added.

        The base chains are flushed and re-pointed rather than inspected for a jump that
        may already be there. Each holds exactly one rule and nothing else, so rebuilding
        is shorter than checking and cannot leave a duplicate behind; the version that
        checked had to, because the chain belonged to iptables and emptying it was not
        firegex's to do.
        """
        for family in ("ip", "ip6"):
            for table in (self.filter_table, self.mangle_table):
                yield {"add": {"table": {"name": table, "family": family}}}
            for which, chain in self.rules_chains:
                yield {"add": {"chain": {
                    "family": family, "table": self._table(which), "name": chain,
                }}}
            for which, chain, hook, prio, follows_policy, target in self.base_chains:
                table = self._table(which)
                yield {"add": {"chain": {
                    "family": family, "table": table, "name": chain,
                    "type": "filter", "hook": hook, "prio": prio,
                    "policy": policy if follows_policy else Action.ACCEPT,
                }}}
                yield {"flush": {"chain": {"family": family, "table": table, "name": chain}}}
                yield {"add": {"rule": {
                    "family": family, "table": table, "chain": chain,
                    "expr": [{"jump": {"target": target}}],
                }}}

    def init_comands(self, policy:str=Action.ACCEPT, opt:
        FirewallSettings|None = None):
        rules = list(self._skeleton(policy))
        if opt is None:
            return rules
        
        if opt.allow_loopback:
            rules.extend([
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_out,
                    "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "iif" }}, "right": "lo"}},{"accept": None}]
                }}},
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "iif" }}, "right": "lo"}},{"accept": None}]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_out,
                    "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "iif" }}, "right": "lo"}},{"accept": None}]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "iif" }}, "right": "lo"}},{"accept": None}]
                }}}
            ])
        if opt.allow_established:
            rules.extend([
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [{ "match": {"op": "in", "left": { "ct": { "key": "state" }},"right": ["related", "established"]} },{ "accept": None }]
                }}},
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_fwd,
                    "expr": [{ "match": {"op": "in", "left": { "ct": { "key": "state" }},"right": ["related", "established"]} },{ "accept": None }]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [{ "match": {"op": "in", "left": { "ct": { "key": "state" }},"right": ["related", "established"]} },{ "accept": None }]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_fwd,
                    "expr": [{ "match": {"op": "in", "left": { "ct": { "key": "state" }},"right": ["related", "established"]} },{ "accept": None }]
                }}}
            ])
        if opt.drop_invalid:
            rules.extend([
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [{ "match": {"op": "==", "left": { "ct": { "key": "state" }},"right": "invalid"} },{ "drop": None }]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [{ "match": {"op": "==", "left": { "ct": { "key": "state" }},"right": "invalid"} },{ "drop": None }]
                }}}
            ])
        if opt.allow_icmp:
            rules.extend([
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "icmp"} },{ "accept": None }]
                }}},
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_fwd,
                    "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "icmp"} },{ "accept": None }]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "ipv6-icmp"} },{ "accept": None }]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_fwd,
                    "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "ipv6-icmp"} },{ "accept": None }]
                }}}
            ])
        if opt.multicast_dns:
            rules.extend([
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [
                        { 'match': {'left': {'payload': {'protocol': "ip", 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json("224.0.0.251/32")} },
                        { 'match': {'left': {'payload': {'protocol': "udp", 'field': 'dport'}}, 'op': '==', 'right': 5353} },
                        { "accept": None }
                    ]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [
                        { 'match': {'left': {'payload': {'protocol': "ip6", 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json("ff02::fb/128")} },
                        { 'match': {'left': {'payload': {'protocol': "udp", 'field': 'dport'}}, 'op': '==', 'right': 5353} },
                        { "accept": None }
                    ]
                }}},
            ])
        if opt.allow_upnp:
            rules.extend([
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [
                        { 'match': {'left': {'payload': {'protocol': "ip", 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json("239.255.255.250/32")} },
                        { 'match': {'left': {'payload': {'protocol': "udp", 'field': 'dport'}}, 'op': '==', 'right': 1900} },
                        { "accept": None }
                    ]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [
                        { 'match': {'left': {'payload': {'protocol': "ip6", 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json("ff02::f/128")} },
                        { 'match': {'left': {'payload': {'protocol': "udp", 'field': 'dport'}}, 'op': '==', 'right': 1900} },
                        { "accept": None }
                    ]
                }}},
            ])
        if opt.allow_dhcp:
            rules.extend([
                { "add":{ "rule": {
                    "family": "ip", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [
                        { 'match': {'left': {'payload': {'protocol': "udp", 'field': 'sport'}}, 'op': '==', 'right': 67} },
                        { 'match': {'left': {'payload': {'protocol': "udp", 'field': 'dport'}}, 'op': '==', 'right': 68} },
                        { "accept": None }
                    ]
                }}},
                { "add":{ "rule": {
                    "family": "ip6", "table": self.filter_table, "chain": self.rules_chain_in,
                    "expr": [
                        { 'match': {'left': {'payload': {'protocol': "udp", 'field': 'sport'}}, 'op': '==', 'right': 67} },
                        { 'match': {'left': {'payload': {'protocol': "udp", 'field': 'dport'}}, 'op': '==', 'right': 68} },
                        { "accept": None }
                    ]
                }}},
            ])
        return rules
    
    def __init__(self):
        # Taking the firewall down is now deleting what firegex owns, nothing more.
        # This used to have to put things *back*: the base chains were the host's, so
        # stopping meant re-adding `filter INPUT` with an accept policy — which silently
        # undid an administrator's default-deny — and flushing the rules chains one by
        # one because deleting the table around them was not an option. `add` before
        # `delete` is there because a batch is atomic and deleting a table that is not
        # there fails the whole thing; adding one that already exists does nothing.
        super().__init__(self.init_comands(), [
            command
            for family in ("ip", "ip6")
            for table in (self.filter_table, self.mangle_table)
            for command in (
                {"add": {"table": {"name": table, "family": family}}},
                {"delete": {"table": {"name": table, "family": family}}},
            )
        ])

    def set(self, srvs:list[Rule], policy:str=Action.ACCEPT, opt:FirewallSettings = None):
        srvs = list(srvs)
        self.reset()
        if policy == Action.REJECT:
            policy = Action.DROP
            srvs.append(Rule(
                proto=Protocol.ANY,
                src="",
                dst="",
                port_src_from=1,
                port_dst_from=1,
                port_src_to=65535,
                port_dst_to=65535,
                action=Action.REJECT,
                mode=Mode.IN,
                table=Table.FILTER
            ))
        
        # No hooking step any more: the base chains are firegex's own and `_skeleton`
        # already pointed each of them at its rules chain.
        rules = self.init_comands(policy, opt) + self.get_rules(*srvs) + self.dnat_rules(opt)
        self.cmd(*rules)

    def dnat_rules(self, opt: FirewallSettings | None) -> list[dict]:
        """Leave port-forwarded traffic to the rules that forwarded it, when no rule of
        ours has matched it.

        A consequence of owning the base chains that the move to them did not keep. In
        iptables' own `FORWARD` chain, which is where firegex's rules used to be, Docker's
        and podman's accept for a published port came first or came after firegex's jump
        in the same chain — either way, traffic to a container's published port was
        accepted without ever meeting firegex's policy. A base chain of our own is
        evaluated on its own, so with the policy at drop every connection to a published
        container port was dropped, on the CTF box where that is how every service is
        reached. The rules chain still runs first, so a forward rule the operator wrote
        applies to that traffic exactly as before; this only decides what the *policy*
        does with what no rule matched, and the runtime's own chain still decides on its
        own whether it accepts it.
        """
        if opt is None or not opt.allow_dnat:
            return []
        return [
            {"add": {"rule": {
                "family": family, "table": self.filter_table, "chain": "fgex_forward",
                "expr": [
                    {"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}},
                    {"accept": None},
                ],
            }}}
            for family in ("ip", "ip6")
        ]

    def get_rules(self,*srvs:Rule):
        rules = []
        final_srvs:list[Rule] = []
        for ele in srvs:
            if ele.proto == Protocol.BOTH:
                udp_rule = copy.deepcopy(ele)
                udp_rule.proto = Protocol.UDP.value
                ele.proto = Protocol.TCP.value
                final_srvs.append(udp_rule)
            final_srvs.append(ele)
            
        families = ["ip", "ip6"]
                
        for srv in final_srvs:
            ip_filters = []
            
            if srv.src != "":
                if is_ip_parse(srv.src):
                    ip_filters.append({'match': {'left': {'payload': {'protocol': ip_family(srv.src), 'field': 'saddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.src)}})
                    families = [ip_family(srv.src)]
                else:
                    ip_filters.append({"match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": srv.src} })
            
            if srv.dst != "":
                if is_ip_parse(srv.dst):
                    ip_filters.append({'match': {'left': {'payload': {'protocol': ip_family(srv.dst), 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.dst)}})
                    families = [ip_family(srv.dst)]
                else:
                    ip_filters.append({"match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": srv.dst} })
                
            port_filters = []
            if srv.proto not in [Protocol.ANY, Protocol.BOTH]:
                if srv.port_src_from != 1 or srv.port_src_to != 65535: #Any Port
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'sport'}}, 'op': '>=', 'right': int(srv.port_src_from)}})
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'sport'}}, 'op': '<=', 'right': int(srv.port_src_to)}})
                if srv.port_dst_from != 1 or srv.port_dst_to != 65535: #Any Port
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'op': '>=', 'right': int(srv.port_dst_from)}})
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'op': '<=', 'right': int(srv.port_dst_to)}})
                if len(port_filters) == 0:
                    port_filters.append({'match': {'left': {'meta': {'key': 'l4proto'}}, 'op': '==', 'right': srv.proto}}) #filter the protocol if no port is specified
            
            end_rules =  [{'accept': None} if srv.action == "accept" else {'reject': {}} if (srv.action == "reject" and not srv.output_mode) else {'drop': None}]
            #If srv.output_mode is True, then the rule is in the output chain, so the reject action is not allowed
            for fam in families:
                rules.append({ "add":{ "rule": {
                    "family": fam,
                    # `srv.table` is the operator's word for what the rule does, kept in
                    # the database and in the API; the table it lands in is firegex's.
                    # The two were one string until that string was iptables' table.
                    "table": NFT_TABLES.get(srv.table, self.filter_table),
                    "chain": self.rules_chain_out if srv.output_mode else self.rules_chain_in if srv.input_mode else self.rules_chain_fwd,
                    "expr": ip_filters + port_filters + end_rules
                }}})
        return rules

    def add(self, *srvs:Rule):
        self.cmd(*self.get_rules(*srvs))