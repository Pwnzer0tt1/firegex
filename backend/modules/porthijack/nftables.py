from typing import List
from utils import ip_parse, ip_family, NFTableManager

class FiregexFilter():
    def __init__(self, proto:str, port:int, ip_int:str, queue=None, target:str=None, id=None):
        self.id = int(id) if id else None
        self.queue = queue
        self.target = target
        self.proto = proto
        self.port = int(port)
        self.ip_int = str(ip_int)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, FiregexFilter):
            return self.port == o.port and self.proto == o.proto and ip_parse(self.ip_int) == ip_parse(o.ip_int)
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

    def add(self, ip_int, proto, public_port, proxy_port):
        ip_int = ip_parse(ip_int)
        ip_addr = str(ip_int).split("/")[0]
        ip_addr_cidr = int(str(ip_int).split("/")[1])
        self.cmd({ "insert":{ "rule": {
            "family": "inet",
            "table": self.table_name,
            "chain": self.prerouting_porthijack,
            "expr": [
                    {'match': {'left': {'payload': {'protocol': ip_family(ip_int), 'field': 'daddr'}}, 'op': '==', 'right': {"prefix": {"addr": ip_addr, "len": ip_addr_cidr}}}},
                    {'match': {'left': { "payload": {"protocol": str(proto), "field": "dport"}}, "op": "==", "right": int(public_port)}},
                    {'mangle': {'key': {'payload': {'protocol': str(proto), 'field': 'dport'}}, 'value': int(proxy_port)}}
                ]
        }}})
        self.cmd({ "insert":{ "rule": {
            "family": "inet",
            "table": self.table_name,
            "chain": self.postrouting_porthijack,
            "expr": [
                    {'match': {'left': {'payload': {'protocol': ip_family(ip_int), 'field': 'saddr'}}, 'op': '==', 'right': {"prefix": {"addr": ip_addr, "len": ip_addr_cidr}}}},
                    {'match': {'left': { "payload": {"protocol": str(proto), "field": "sport"}}, "op": "==", "right": int(proxy_port)}},
                    {'mangle': {'key': {'payload': {'protocol': str(proto), 'field': 'sport'}}, 'value': int(public_port)}}
                ]
        }}})

    def get(self) -> List[FiregexFilter]:
        res = []
        for filter in self.list_rules(tables=[self.table_name], chains=[self.input_chain,self.output_chain]):
            queue_str = filter["expr"][2]["queue"]["num"]
            queue = None
            if isinstance(queue_str,dict): queue = int(queue_str["range"][0]), int(queue_str["range"][1])
            else: queue = int(queue_str), int(queue_str)
            ip_int = None
            if isinstance(filter["expr"][0]["match"]["right"],str):
                ip_int = str(ip_parse(filter["expr"][0]["match"]["right"]))
            else:
                ip_int = f'{filter["expr"][0]["match"]["right"]["prefix"]["addr"]}/{filter["expr"][0]["match"]["right"]["prefix"]["len"]}'
            res.append(FiregexFilter(
                target=filter["chain"],
                id=int(filter["handle"]),
                queue=queue,
                proto=filter["expr"][1]["match"]["left"]["payload"]["protocol"],
                port=filter["expr"][1]["match"]["right"],
                ip_int=ip_int
            ))
        return res
            