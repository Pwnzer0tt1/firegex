
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
