
from ipaddress import ip_interface
import nftables, traceback

def ip_parse(ip:str):
    return str(ip_interface(ip).network)

def ip_family(ip:str):
    return "ip6" if ip_interface(ip).version == 6 else "ip"

class Singleton(object):
    __instance = None
    def __new__(class_, *args, **kwargs):
        if not isinstance(class_.__instance, class_):
            class_.__instance = object.__new__(class_, *args, **kwargs)
        return class_.__instance

class NFTableManager(Singleton):
    
    table_name = "firegex"
    
    def __init__(self, init_cmd, reset_cmd):
        self.__init_cmds = init_cmd
        self.__reset_cmds = reset_cmd
        self.nft = nftables.Nftables()
    
    def raw_cmd(self, *cmds):
        return self.nft.json_cmd({"nftables": list(cmds)})

    def cmd(self, *cmds):
        code, out, err = self.raw_cmd(*cmds)

        if code == 0: return out
        else: raise Exception(err)
    
    def init(self):
        self.reset()
        self.raw_cmd({"add":{"table":{"name":self.table_name,"family":"inet"}}})
        self.cmd(*self.__init_cmds)
            
    def reset(self):
        self.raw_cmd(*self.__reset_cmds)

    def list(self):
        return self.cmd({"list": {"ruleset": None}})["nftables"]


class FiregexTables(NFTableManager):
    prerouting_porthijack = "porthijack"
    
    def __init__(self):
        super().__init__([
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.prerouting_porthijack,
                "type":"nat",
                "hook":"output",
                "prio":-100,
                "policy":"accept"
            }}}
        ],[
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.prerouting_porthijack}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.prerouting_porthijack}}}
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
                    {'redirect' : {'port' : int(proxy_port), 'flags' : []}}
                ]
        }}})
"""
    def add_output(self, queue_range, proto, port, ip_int):


    def add_input(self, queue_range, proto = None, port = None, ip_int = None):
        init, end = queue_range
        if init > end: init, end = end, init
        ip_int = ip_parse(ip_int)
        ip_addr = str(ip_int).split("/")[0]
        ip_addr_cidr = int(str(ip_int).split("/")[1])
        self.cmd({"insert":{"rule":{
            "family": "inet",
            "table": self.table_name,
            "chain": self.input_chain,
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
"""
try:
    #print(FiregexTables().list())
    FiregexTables().init()
    FiregexTables().add("127.0.0.1","tcp", 8080, 8081)
    input()
except:
    traceback.print_exc()
    FiregexTables().reset()

#https://www.mankier.com/5/libnftables-json