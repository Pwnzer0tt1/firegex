from modules.firewall.models import FirewallSettings, Action, Rule, Protocol, Mode, Table
from utils import nftables_int_to_json, ip_family, NFTableManager, is_ip_parse
import copy

class FiregexTables(NFTableManager):
    rules_chain_in = "firegex_firewall_rules_in"
    rules_chain_out = "firegex_firewall_rules_out"
    rules_chain_fwd = "firegex_firewall_rules_fwd"
    filter_table = "filter"
    mangle_table = "mangle"
    
    def init_comands(self, policy:str=Action.ACCEPT, opt:
        FirewallSettings|None = None):
        rules = [
            {"add":{"table":{"name":self.filter_table,"family":"ip"}}},
            {"add":{"table":{"name":self.filter_table,"family":"ip6"}}},
            
            {"add":{"table":{"name":self.mangle_table,"family":"ip"}}},
            {"add":{"table":{"name":self.mangle_table,"family":"ip6"}}},
            
            {"add":{"chain":{"family":"ip","table":self.filter_table, "name":"INPUT","type":"filter","hook":"input","prio":0,"policy":policy}}},
            {"add":{"chain":{"family":"ip6","table":self.filter_table,"name":"INPUT","type":"filter","hook":"input","prio":0,"policy":policy}}},
            {"add":{"chain":{"family":"ip","table":self.filter_table,"name":"FORWARD","type":"filter","hook":"forward","prio":0,"policy":policy}}},
            {"add":{"chain":{"family":"ip6","table":self.filter_table,"name":"FORWARD","type":"filter","hook":"forward","prio":0,"policy":policy}}},
            {"add":{"chain":{"family":"ip","table":self.filter_table,"name":"OUTPUT","type":"filter","hook":"output","prio":0,"policy":Action.ACCEPT}}},
            {"add":{"chain":{"family":"ip6","table":self.filter_table,"name":"OUTPUT","type":"filter","hook":"output","prio":0,"policy":Action.ACCEPT}}},
            
            {"add":{"chain":{"family":"ip","table":self.mangle_table, "name":"PREROUTING","type":"filter","hook":"prerouting","prio":-150,"policy":Action.ACCEPT}}},
            {"add":{"chain":{"family":"ip6","table":self.mangle_table,"name":"PREROUTING","type":"filter","hook":"prerouting","prio":-150,"policy":Action.ACCEPT}}},
            {"add":{"chain":{"family":"ip","table":self.mangle_table, "name":"POSTROUTING","type":"filter","hook":"postrouting","prio":-150,"policy":Action.ACCEPT}}},
            {"add":{"chain":{"family":"ip6","table":self.mangle_table,"name":"POSTROUTING","type":"filter","hook":"postrouting","prio":-150,"policy":Action.ACCEPT}}},
            
            {"add":{"chain":{"family":"ip","table":self.filter_table,"name":self.rules_chain_in}}},
            {"add":{"chain":{"family":"ip6","table":self.filter_table,"name":self.rules_chain_in}}},
            {"add":{"chain":{"family":"ip","table":self.filter_table,"name":self.rules_chain_out}}},
            {"add":{"chain":{"family":"ip6","table":self.filter_table,"name":self.rules_chain_out}}},
            {"add":{"chain":{"family":"ip","table":self.filter_table,"name":self.rules_chain_fwd}}},
            {"add":{"chain":{"family":"ip6","table":self.filter_table,"name":self.rules_chain_fwd}}},
            
            {"add":{"chain":{"family":"ip","table":self.mangle_table,"name":self.rules_chain_in}}},
            {"add":{"chain":{"family":"ip6","table":self.mangle_table,"name":self.rules_chain_in}}},
            {"add":{"chain":{"family":"ip","table":self.mangle_table,"name":self.rules_chain_out}}},
            {"add":{"chain":{"family":"ip6","table":self.mangle_table,"name":self.rules_chain_out}}},
        ]
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
        super().__init__(self.init_comands(),[      
            #Needed to reset to ALLOW when fireall is disabled (DO NOT REMOVE)                       
            {"add":{"chain":{"family":"ip","table":self.filter_table, "name":"INPUT","type":"filter","hook":"input","prio":0,"policy":Action.ACCEPT}}},
            {"add":{"chain":{"family":"ip6","table":self.filter_table,"name":"INPUT","type":"filter","hook":"input","prio":0,"policy":Action.ACCEPT}}},
            {"add":{"chain":{"family":"ip","table":self.filter_table,"name":"FORWARD","type":"filter","hook":"forward","prio":0,"policy":Action.ACCEPT}}},
            {"add":{"chain":{"family":"ip6","table":self.filter_table,"name":"FORWARD","type":"filter","hook":"forward","prio":0,"policy":Action.ACCEPT}}},
              
            {"flush":{"chain":{"table":self.filter_table,"family":"ip", "name":self.rules_chain_in}}},
            {"flush":{"chain":{"table":self.filter_table,"family":"ip", "name":self.rules_chain_out}}},
            {"flush":{"chain":{"table":self.filter_table,"family":"ip", "name":self.rules_chain_fwd}}},
            {"flush":{"chain":{"table":self.filter_table,"family":"ip6", "name":self.rules_chain_in}}},
            {"flush":{"chain":{"table":self.filter_table,"family":"ip6", "name":self.rules_chain_out}}},
            {"flush":{"chain":{"table":self.filter_table,"family":"ip6", "name":self.rules_chain_fwd}}},
            
            {"flush":{"chain":{"table":self.mangle_table,"family":"ip", "name":self.rules_chain_in}}},
            {"flush":{"chain":{"table":self.mangle_table,"family":"ip", "name":self.rules_chain_out}}},
            {"flush":{"chain":{"table":self.mangle_table,"family":"ip6", "name":self.rules_chain_in}}},
            {"flush":{"chain":{"table":self.mangle_table,"family":"ip6", "name":self.rules_chain_out}}}
        ])
        
    def chain_to_firegex(self, chain:str, table:str):
        if table == self.filter_table:
            match chain:
                case "INPUT":
                    return self.rules_chain_in
                case "OUTPUT":
                    return self.rules_chain_out
                case "FORWARD":
                    return self.rules_chain_fwd
        elif table == self.mangle_table:
            match chain:
                case "PREROUTING":
                    return self.rules_chain_in
                case "POSTROUTING":
                    return self.rules_chain_out
        return None
        
    def insert_firegex_chains(self):
        rules:list[dict] = list(self.list_rules(tables=[self.filter_table, self.mangle_table], chains=["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"]))
        for table in [self.filter_table, self.mangle_table]:
            for family in ["ip", "ip6"]:
                for chain in ["INPUT", "OUTPUT", "FORWARD"] if table == self.filter_table else ["PREROUTING", "POSTROUTING"]:
                    found = False
                    rule_to_add = [{ "jump": { "target": self.chain_to_firegex(chain, table) }}]
                    for r in rules:
                        if r.get("family") == family and r.get("table") == table and r.get("chain") == chain and r.get("expr") == rule_to_add:
                            found = True
                            break
                    if found:
                        continue
                    yield { "add":{ "rule": {
                            "family": family,
                            "table": table,
                            "chain": chain,
                            "expr": rule_to_add
                    }}}
    
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
        
        rules = self.init_comands(policy, opt) + list(self.insert_firegex_chains()) + self.get_rules(*srvs)
        self.cmd(*rules)

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
                    "table": srv.table,
                    "chain": self.rules_chain_out if srv.output_mode else self.rules_chain_in if srv.input_mode else self.rules_chain_fwd,
                    "expr": ip_filters + port_filters + end_rules
                }}})
        return rules

    def add(self, *srvs:Rule):
        self.cmd(*self.get_rules(*srvs))