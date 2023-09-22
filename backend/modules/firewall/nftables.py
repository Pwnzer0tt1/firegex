from modules.firewall.models import Rule
from utils import nftables_int_to_json, ip_parse, ip_family, NFTableManager, nftables_json_to_int


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
    
    def __init__(self):
        super().__init__([
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.rules_chain_in,
                "type":"filter",
                "hook":"prerouting",
                "prio":-300,
                "policy":"accept"
            }}},
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.rules_chain_out,
                "type":"filter",
                "hook":"postrouting",
                "prio":-300,
                "policy":"accept"
            }}},    
        ],[
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_in}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_in}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_out}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_out}}},
        ])
    
    def delete_all(self):
        self.cmd(
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_in}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.rules_chain_out}}},
        )
    
    def set(self, srv:list[Rule]):
        self.delete_all()
        for ele in srv: self.add(ele)

    def add(self, srv:Rule):
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
                
        self.cmd({ "insert":{ "rule": {
            "family": "inet",
            "table": self.table_name,
            "chain": self.rules_chain_out if srv.output_mode else self.rules_chain_in,
            "expr": [
                    {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_src), 'field': 'saddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.ip_src)}},
                    {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_dst), 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.ip_dst)}},
                ] + port_filters + [{'accept': None} if srv.action == "accept" else {'reject': {}} if srv.action == "reject" else {'drop': None}]
        }}})