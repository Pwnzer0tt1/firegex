from modules.nfproxy.models import Service
from utils import ip_parse, ip_family, NFTableManager, nftables_int_to_json

class FiregexFilter:
    def __init__(self, proto:str, port:int, ip_int:str, target:str, id:int):
        self.id = id
        self.target = target
        self.proto = proto
        self.port = int(port)
        self.ip_int = str(ip_int)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, FiregexFilter) or isinstance(o, Service):
            return self.port == o.port and self.proto == o.proto and ip_parse(self.ip_int) == ip_parse(o.ip_int)
        return False

class FiregexTables(NFTableManager):
    input_chain = "nfproxy_input"
    output_chain = "nfproxy_output"
    
    def __init__(self):
        super().__init__([
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.input_chain,
                "type":"filter",
                "hook":"prerouting",
                "prio":-150,
                "policy":"accept"
            }}},
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.output_chain,
                "type":"filter",
                "hook":"postrouting",
                "prio":-150,
                "policy":"accept"
            }}}
        ],[
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.input_chain}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.input_chain}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.output_chain}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.output_chain}}},
        ])

    def add(self, srv:Service, queue_range):
        
        for ele in self.get():
            if ele.__eq__(srv):
                return
                
        init, end = queue_range
        if init > end:
            init, end = end, init
        self.cmd(
            { "insert":{ "rule": {
                "family": "inet",
                "table": self.table_name,
                "chain": self.output_chain,
                "expr": [
                        {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_int), 'field': 'saddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.ip_int)}},
                        {'match': {"left": { "payload": {"protocol": str(srv.proto), "field": "sport"}}, "op": "==", "right": int(srv.port)}},
                        {"queue": {"num": str(init) if init == end else {"range":[init, end] }, "flags": ["bypass"]}}
                ]
            }}},
            {"insert":{"rule":{
                "family": "inet",
                "table": self.table_name,
                "chain": self.input_chain,
                "expr": [
                        {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_int), 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.ip_int)}},
                        {'match': {"left": { "payload": {"protocol": str(srv.proto), "field": "dport"}}, "op": "==", "right": int(srv.port)}},
                        {"queue": {"num": str(init) if init == end else {"range":[init, end] }, "flags": ["bypass"]}}
                    ]
            }}}
        )


    def get(self) -> list[FiregexFilter]:
        res = []
        for filter in self.list_rules(tables=[self.table_name], chains=[self.input_chain,self.output_chain]):
            ip_int = None
            if isinstance(filter["expr"][0]["match"]["right"],str):
                ip_int = str(ip_parse(filter["expr"][0]["match"]["right"]))
            else:
                ip_int = f'{filter["expr"][0]["match"]["right"]["prefix"]["addr"]}/{filter["expr"][0]["match"]["right"]["prefix"]["len"]}'
            res.append(FiregexFilter(
                target=filter["chain"],
                id=int(filter["handle"]),
                proto=filter["expr"][1]["match"]["left"]["payload"]["protocol"],
                port=filter["expr"][1]["match"]["right"],
                ip_int=ip_int
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
            