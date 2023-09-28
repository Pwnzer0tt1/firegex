from modules.firewall.models import Rule, Protocol, Mode, Action
from utils import nftables_int_to_json, ip_family, NFTableManager, is_ip_parse
import copy

class FiregexTables(NFTableManager):
    rules_chain_in = "firewall_rules_in"
    rules_chain_out = "firewall_rules_out"
    rules_chain_fwd = "firewall_rules_fwd"
    
    def init_comands(self, policy:str=Action.ACCEPT, allow_loopback=False, allow_established=False, allow_icmp=False):
        return [
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.rules_chain_in,
                "type":"filter",
                "hook":"prerouting",
                "prio":0,
                "policy":policy
            }}},
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.rules_chain_fwd,
                "type":"filter",
                "hook":"forward",
                "prio":0,
                "policy":policy
            }}},
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.rules_chain_out,
                "type":"filter",
                "hook":"postrouting",
                "prio":0,
                "policy":Action.ACCEPT
            }}},    
        ] + ([
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_out,
                "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "iif" }}, "right": "lo"}},{"accept": None}]
            }}},
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_in,
                "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "iif" }}, "right": "lo"}},{"accept": None}]
            }}}
        ] if allow_loopback else []) + ([
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_in,
                "expr": [{ "match": {"op": "in", "left": { "ct": { "key": "state" }},"right": ["established"]} }, { "accept": None }]
            }}},
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_fwd,
                "expr": [{ "match": {"op": "in", "left": { "ct": { "key": "state" }},"right": ["established"]} }, { "accept": None }]
            }}}
        ] if allow_established else []) + ([
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_in,
                "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "icmp"} }, { "accept": None }]
            }}},
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_fwd,
                "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "icmp"} }, { "accept": None }]
            }}},
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_in,
                "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "ipv6-icmp"} }, { "accept": None }]
            }}},
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_fwd,
                "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } }, "right": "ipv6-icmp"} }, { "accept": None }]
            }}}
        ] if allow_icmp else [])
    
    def __init__(self):
        super().__init__(self.init_comands(),[
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_in}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_in}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_out}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_out}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_fwd}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_fwd}}},
        ])
    
    def set(self, srvs:list[Rule], policy:str="accept", allow_loopback=False, allow_established=False, allow_icmp=False):
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
                mode=Mode.IN
            ))
        rules = self.init_comands(policy, allow_loopback=allow_loopback, allow_established=allow_established, allow_icmp=allow_icmp) + self.get_rules(*srvs)
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
                
        for srv in final_srvs:
            ip_filters = []
            
            if srv.src != "":
                if is_ip_parse(srv.src):
                    ip_filters.append({'match': {'left': {'payload': {'protocol': ip_family(srv.src), 'field': 'saddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.src)}})
                else:
                    ip_filters.append({"match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": srv.src} })
            
            if srv.dst != "":
                if is_ip_parse(srv.dst):
                    ip_filters.append({'match': {'left': {'payload': {'protocol': ip_family(srv.dst), 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.dst)}})
                else:
                    ip_filters.append({"match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": srv.dst} })
                
            port_filters = []
            if not srv.proto in [Protocol.ANY, Protocol.BOTH]:
                if srv.port_src_from != 1 or srv.port_src_to != 65535: #Any Port
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'sport'}}, 'op': '>=', 'right': int(srv.port_src_from)}})
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'sport'}}, 'op': '<=', 'right': int(srv.port_src_to)}})
                if srv.port_dst_from != 1 or srv.port_dst_to != 65535: #Any Port
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'op': '>=', 'right': int(srv.port_dst_from)}})
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'op': '<=', 'right': int(srv.port_dst_to)}})
                if len(port_filters) == 0:
                    port_filters.append({'match': {'left': {'meta': {'key': 'l4proto'}}, 'op': '==', 'right': srv.proto}}) #filter the protocol if no port is specified
            
            end_rules =  [{'accept': None} if srv.action == "accept" else {'reject': {}} if (srv.action == "reject" and not srv.output_mode) else {'drop': None}]
            rules.append({ "add":{ "rule": {
                "family": "inet",
                "table": self.table_name,
                "chain": self.rules_chain_out if srv.output_mode else self.rules_chain_in if srv.input_mode else self.rules_chain_fwd,
                "expr": ip_filters + port_filters + end_rules
                #If srv.output_mode is True, then the rule is in the output chain, so the reject action is not allowed
            }}})
        return rules

    def add(self, *srvs:Rule):
        self.cmd(*self.get_rules(*srvs))