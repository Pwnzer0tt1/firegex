from modules.porthijack.models import Service
from utils import addr_parse, ip_parse, ip_family, NFTableManager, nftables_json_to_int

class FiregexHijackRule():
    def __init__(self, proto:str, public_port:int,proxy_port:int, ip_src:str, ip_dst:str, target:str, id:int):
        self.id = id
        self.target = target
        self.proto = proto
        self.public_port = public_port
        self.proxy_port = proxy_port
        self.ip_src = str(ip_src)
        self.ip_dst = str(ip_dst)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, FiregexHijackRule) or isinstance(o, Service):
            return self.public_port == o.public_port and self.proto == o.proto and ip_parse(self.ip_src) == ip_parse(o.ip_src)
        return False

class FiregexTables(NFTableManager):
    prerouting_porthijack = "prerouting_porthijack"
    postrouting_porthijack = "postrouting_porthijack"
    
    def __init__(self):
        super().__init__([
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.prerouting_porthijack,
                "type":"filter",
                "hook":"prerouting",
                "prio":-300,
                "policy":"accept"
            }}},
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.postrouting_porthijack,
                "type":"filter",
                "hook":"postrouting",
                "prio":-300,
                "policy":"accept"
            }}}
        ],[
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.prerouting_porthijack}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.prerouting_porthijack}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.postrouting_porthijack}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.postrouting_porthijack}}}
        ])

    def add(self, srv:Service):
        
        for ele in self.get():
            if ele.__eq__(srv):
                return
        
        self.cmd({ "insert":{ "rule": {
            "family": "inet",
            "table": self.table_name,
            "chain": self.prerouting_porthijack,
            "expr": [
                    {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_src), 'field': 'daddr'}}, 'op': '==', 'right': addr_parse(srv.ip_src)}},
                    {'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'op': '==', 'right': int(srv.public_port)}},
                    {'mangle': {'key': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'value': int(srv.proxy_port)}},
                    {'mangle': {'key': {'payload': {'protocol': ip_family(srv.ip_src), 'field': 'daddr'}}, 'value': addr_parse(srv.ip_dst)}}
                ]
        }}})
        self.cmd({ "insert":{ "rule": {
            "family": "inet",
            "table": self.table_name,
            "chain": self.postrouting_porthijack,
            "expr": [
                    {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_dst), 'field': 'saddr'}}, 'op': '==', 'right': addr_parse(srv.ip_dst)}},
                    {'match': {'left': { "payload": {"protocol": str(srv.proto), "field": "sport"}}, "op": "==", "right": int(srv.proxy_port)}},
                    {'mangle': {'key': {'payload': {'protocol': str(srv.proto), 'field': 'sport'}}, 'value': int(srv.public_port)}},
                    {'mangle': {'key': {'payload': {'protocol': ip_family(srv.ip_dst), 'field': 'saddr'}}, 'value': addr_parse(srv.ip_src)}}
                ]
        }}})


    def get(self) -> list[FiregexHijackRule]:
        res = []
        for filter in self.list_rules(tables=[self.table_name], chains=[self.prerouting_porthijack,self.postrouting_porthijack]):
            res.append(FiregexHijackRule(
                target=filter["chain"],
                id=int(filter["handle"]),
                proto=filter["expr"][1]["match"]["left"]["payload"]["protocol"],
                public_port=filter["expr"][1]["match"]["right"] if filter["chain"] == self.prerouting_porthijack else filter["expr"][2]["mangle"]["value"],
                proxy_port=filter["expr"][1]["match"]["right"] if filter["chain"] == self.postrouting_porthijack else filter["expr"][2]["mangle"]["value"], 
                ip_src=nftables_json_to_int(filter["expr"][0]["match"]["right"]) if filter["chain"] == self.prerouting_porthijack else nftables_json_to_int(filter["expr"][3]["mangle"]["value"]),
                ip_dst=nftables_json_to_int(filter["expr"][0]["match"]["right"]) if filter["chain"] == self.postrouting_porthijack else nftables_json_to_int(filter["expr"][3]["mangle"]["value"]), 
            ))
        return res

    def delete(self, srv:Service):
        for filter in self.get():
            if filter.__eq__(srv):
                self.cmd({ "delete":{ "rule": {
                    "family": "inet",
                    "table": self.table_name,
                    "chain": filter.target,
                    "handle": filter.id
                }}})