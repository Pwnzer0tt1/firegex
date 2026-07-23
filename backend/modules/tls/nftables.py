from utils import NFTableManager, nftables_int_to_json, ip_family
from modules.tls.manager import TLSManager

class TLSTables(NFTableManager):
    nat_chain = "tls_nat"
    
    def __init__(self):
        super().__init__([
            {"add":{"chain":{ #NAT chain for DNAT
                "family":"inet",
                "table":self.table_name,
                "name":self.nat_chain,
                "type":"nat",
                "hook":"prerouting",
                "prio":-100,
                "policy":"accept"
            }}}
        ],[
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.nat_chain}}},
        ])

    def reload(self):
        self.init()
        manager = TLSManager()
        streams = manager.get_active_streams()
        cmds = []
        for srv in streams:
            loopback_ip = "::1" if ip_family(srv["ip_int"]) == "ip6" else "127.0.0.1"
            cmds.append({"insert":{ "rule": { # Redirect TLS traffic to local Nginx SSL proxy
                "family": "inet",
                "table": self.table_name,
                "chain": self.nat_chain,
                "expr": [
                        {'match': {'left': {'payload': {'protocol': ip_family(srv["ip_int"]), 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json(srv["ip_int"])}},
                        {'match': {'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'op': '==', 'right': int(srv["port"])}},
                        {'match': {'left': {'meta': {'key': 'iifname'}}, 'op': '!=', 'right': 'lo'}},
                        {'dnat': {'family': ip_family(srv["ip_int"]), 'addr': loopback_ip, 'port': int(srv["ssl_port"])}}
                ]
            }}})
        if cmds:
            self.cmd(*cmds)

tls_firewall = TLSTables()
