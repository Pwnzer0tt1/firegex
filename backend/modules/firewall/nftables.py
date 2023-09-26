from modules.firewall.models import Rule
from utils import nftables_int_to_json, ip_parse, ip_family, NFTableManager


class FiregexHijackRule():
    def __init__(self, proto:str, ip_src:str, ip_dst:str, port_src_from:int, port_dst_from:int, port_src_to:int, port_dst_to:int, action:str, target:str, id:int):
        self.id = id
        self.target = target
        self.proto = proto
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.port_src_from = min(port_src_from, port_src_to)
        self.port_dst_from = min(port_dst_from, port_dst_to)
        self.port_src_to = max(port_src_from, port_src_to)
        self.port_dst_to = max(port_dst_from, port_dst_to)
        self.action = action

    def __eq__(self, o: object) -> bool:
        if isinstance(o, FiregexHijackRule) or isinstance(o, Rule):
            return self.action == o.action and self.proto == o.proto and\
                ip_parse(self.ip_src) == ip_parse(o.ip_src) and ip_parse(self.ip_dst) == ip_parse(o.ip_dst) and\
                int(self.port_src_from) == int(o.port_src_from) and int(self.port_dst_from) == int(o.port_dst_from) and\
                int(self.port_src_to) == int(o.port_src_to) and int(self.port_dst_to) == int(o.port_dst_to)
        return False


class FiregexTables(NFTableManager):
    rules_chain_in = "firewall_rules_in"
    rules_chain_out = "firewall_rules_out"
    
    def init_comands(self, policy:str="accept", policy_out:str="accept", allow_loopback=False, allow_established=False):
        return [
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.rules_chain_in,
                "type":"filter",
                "hook":"prerouting",
                "prio":-150,
                "policy":policy
            }}},
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.rules_chain_out,
                "type":"filter",
                "hook":"postrouting",
                "prio":-150,
                "policy":policy_out
            }}},    
        ] + ([
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_out,
                "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "iif"}}, "right": "lo"}},{"accept": None}]
            }}},
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_in,
                "expr": [{ "match": { "op": "==", "left": { "meta": { "key": "iif"}}, "right": "lo"}},{"accept": None}]
            }}}
        ] if allow_loopback else []) + ([
            { "add":{ "rule": {
                "family": "inet", "table": self.table_name, "chain": self.rules_chain_in,
                "expr": [{ "match": {"op": "in", "left": { "ct": { "key": "state" }},"right": ["established"]} }, { "accept": None }]
            }}}
        ] if allow_established else [])
    
    def __init__(self):
        super().__init__(self.init_comands(),[
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_in}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_in}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_out}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_out}}},
        ])
    
    def set(self, srvs:list[Rule], policy:str="accept", allow_loopback=False, allow_established=False):
        srvs = list(srvs)
        self.reset()
        if policy == "reject":
            policy = "drop"
            srvs.append(Rule(
                proto="any",
                ip_src="any",
                ip_dst="any",
                port_src_from=1,
                port_dst_from=1,
                port_src_to=65535,
                port_dst_to=65535,
                action="reject",
                mode="I"
            ))
        rules = self.init_comands(policy, allow_loopback=allow_loopback, allow_established=allow_established) + self.get_rules(*srvs)
        self.cmd(*rules)

    def get_rules(self,*srvs:Rule):
        rules = []
        for srv in srvs:
            ip_filters = []
            if srv.ip_src.lower() != "any" and srv.ip_dst.lower() != "any":
                ip_filters = [
                    {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_src), 'field': 'saddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.ip_src)}},
                    {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_dst), 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.ip_dst)}},
                ]
            
            port_filters = []
            if srv.proto != "any":
                if srv.port_src_from != 1 or srv.port_src_to != 65535: #Any Port
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'sport'}}, 'op': '>=', 'right': int(srv.port_src_from)}})
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'sport'}}, 'op': '<=', 'right': int(srv.port_src_to)}})
                if srv.port_dst_from != 1 or srv.port_dst_to != 65535: #Any Port
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'op': '>=', 'right': int(srv.port_dst_from)}})
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'op': '<=', 'right': int(srv.port_dst_to)}})
                if len(port_filters) == 0:
                    port_filters.append({'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'sport'}}, 'op': '!=', 'right': 0}}) #filter the protocol if no port is specified
            
            end_rules =  [{'accept': None} if srv.action == "accept" else {'reject': {}} if (srv.action == "reject" and not srv.output_mode) else {'drop': None}]
            rules.append({ "add":{ "rule": {
                "family": "inet",
                "table": self.table_name,
                "chain": self.rules_chain_out if srv.output_mode else self.rules_chain_in,
                "expr": ip_filters + port_filters + end_rules
                #If srv.output_mode is True, then the rule is in the output chain, so the reject action is not allowed
            }}})
        return rules

    def add(self, *srvs:Rule):
        self.cmd(*self.get_rules(*srvs))