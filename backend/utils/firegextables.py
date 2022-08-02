from typing import List
import nftables
from utils import ip_parse, ip_family

class FiregexFilter():
    def __init__(self, proto:str, port:int, ip_int:str, queue=None, target:str=None, id=None):
        self.nftables = nftables.Nftables()
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

class FiregexTables:

    def __init__(self):
        self.table_name = "firegex"
        self.nft = nftables.Nftables()
    
    def raw_cmd(self, *cmds):
        return self.nft.json_cmd({"nftables": list(cmds)})

    def cmd(self, *cmds):
        code, out, err = self.raw_cmd(*cmds)

        if code == 0: return out
        else: raise Exception(err)
    
    def init(self):
        self.reset()
        code, out, err = self.raw_cmd({"create":{"table":{"name":self.table_name,"family":"inet"}}})
        if code == 0:
            self.cmd(
                {"create":{"chain":{
                    "family":"inet",
                    "table":self.table_name,
                    "name":"input",
                    "type":"filter",
                    "hook":"prerouting",
                    "prio":-150,
                    "policy":"accept"
                }}},
                {"create":{"chain":{
                    "family":"inet",
                    "table":self.table_name,
                    "name":"output",
                    "type":"filter",
                    "hook":"postrouting",
                    "prio":-150,
                    "policy":"accept"
                }}}
            )
        
            
    def reset(self):
        self.raw_cmd(
            {"flush":{"table":{"name":"firegex","family":"inet"}}},
            {"delete":{"table":{"name":"firegex","family":"inet"}}},
        )

    def list(self):
        return self.cmd({"list": {"ruleset": None}})["nftables"]

    def add_output(self, queue_range, proto, port, ip_int):
        init, end = queue_range
        if init > end: init, end = end, init
        ip_int = ip_parse(ip_int)
        ip_addr = str(ip_int).split("/")[0]
        ip_addr_cidr = int(str(ip_int).split("/")[1])
        self.cmd({ "insert":{ "rule": {
            "family": "inet",
            "table": self.table_name,
            "chain": "output",
            "expr": [
                    {'match': {'left': {'payload': {'protocol': ip_family(ip_int), 'field': 'saddr'}}, 'op': '==', 'right': {"prefix": {"addr": ip_addr, "len": ip_addr_cidr}}}},
                    {'match': {"left": { "payload": {"protocol": str(proto), "field": "sport"}}, "op": "==", "right": int(port)}},
                    {"queue": {"num": str(init) if init == end else {"range":[init, end] }, "flags": ["bypass"]}}
                ]
        }}})

    def add_input(self, queue_range, proto = None, port = None, ip_int = None):
        init, end = queue_range
        if init > end: init, end = end, init
        ip_int = ip_parse(ip_int)
        ip_addr = str(ip_int).split("/")[0]
        ip_addr_cidr = int(str(ip_int).split("/")[1])
        self.cmd({"insert":{"rule":{
            "family": "inet",
            "table": self.table_name,
            "chain": "input",
            "expr": [
                    {'match': {'left': {'payload': {'protocol': ip_family(ip_int), 'field': 'daddr'}}, 'op': '==', 'right': {"prefix": {"addr": ip_addr, "len": ip_addr_cidr}}}},
                    {'match': {"left": { "payload": {"protocol": str(proto), "field": "dport"}}, "op": "==", "right": int(port)}},
                    {"queue": {"num": str(init) if init == end else {"range":[init, end] }, "flags": ["bypass"]}}
                ]
        }}})

    def get(self) -> List[FiregexFilter]:
        res = []
        for filter in [ele["rule"] for ele in self.list() if "rule" in ele and ele["rule"]["table"] == self.table_name]:
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
            