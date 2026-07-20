from modules.nfregex.models import Service
from utils import ip_parse, ip_family, NFTableManager, nftables_int_to_json
from modules.nfproxy.nginx import get_tls_ports

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

    def matches(self, srv: Service) -> bool:
        if self.port == srv.port and ip_parse(self.ip_int) == ip_parse(srv.ip_int):
            return True
        ssl_port, clear_port = get_tls_ports(srv.ip_int, srv.port)
        loopback_ip = "::1" if ip_family(srv.ip_int) == "ip6" else "127.0.0.1"
        if ip_parse(self.ip_int) == ip_parse(loopback_ip) and self.port in (ssl_port, clear_port):
            return True
        return False

class FiregexTables(NFTableManager):
    input_chain = "nfregex_input"
    output_chain = "nfregex_output"
    nat_chain = "nfregex_nat"
    
    def __init__(self):
        super().__init__([
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.input_chain,
                "type":"filter",
                "hook":"prerouting",
                "prio":-307,
                "policy":"accept"
            }}},
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.output_chain,
                "type":"filter",
                "hook":"postrouting",
                "prio":107,
                "policy":"accept"
            }}},
            {"add":{"chain":{
                "family":"inet",
                "table":self.table_name,
                "name":self.nat_chain,
                "type":"nat",
                "hook":"prerouting",
                "prio":-100,
                "policy":"accept"
            }}}
        ],[
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.input_chain}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.input_chain}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.output_chain}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.output_chain}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.nat_chain}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.nat_chain}}},
        ])

    def add(self, srv:Service, queue_range):
        
        for ele in self.get():
            if ele.matches(srv):
                return
                
        init, end = queue_range
        if init > end:
            init, end = end, init

        if srv.tls_enabled:
            ssl_port, clear_port = get_tls_ports(srv.ip_int, srv.port)
            loopback_ip = "::1" if ip_family(srv.ip_int) == "ip6" else "127.0.0.1"
            self.cmd(
                { "insert":{ "rule": { # Redirect TLS traffic to local Nginx SSL proxy
                    "family": "inet",
                    "table": self.table_name,
                    "chain": self.nat_chain,
                    "expr": [
                            {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_int), 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.ip_int)}},
                            {'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'op': '==', 'right': int(srv.port)}},
                            {'match': {'left': {'meta': {'key': 'iifname'}}, 'op': '!=', 'right': 'lo'}},
                            {'dnat': {'family': ip_family(srv.ip_int), 'addr': loopback_ip, 'port': int(ssl_port)}}
                    ]
                }}},
                {"insert":{"rule":{ # Send cleartext inbound traffic to NFQUEUE
                    "family": "inet",
                    "table": self.table_name,
                    "chain": self.input_chain,
                    "expr": [
                            {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_int), 'field': 'daddr'}}, 'op': '==', 'right': loopback_ip}},
                            {'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'dport'}}, 'op': '==', 'right': int(clear_port)}},
                            {"mangle": {"key": {"meta": {"key": "mark"}},"value": 0x1337}},
                            {"queue": {"num": str(init) if init == end else {"range":[init, end] }, "flags": ["bypass"]}}
                        ]
                }}},
                {"insert":{"rule":{ # Send cleartext outbound traffic to NFQUEUE
                    "family": "inet",
                    "table": self.table_name,
                    "chain": self.output_chain,
                    "expr": [
                            {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_int), 'field': 'saddr'}}, 'op': '==', 'right': loopback_ip}},
                            {'match': {'left': {'payload': {'protocol': str(srv.proto), 'field': 'sport'}}, 'op': '==', 'right': int(clear_port)}},
                            {"mangle": {"key": {"meta": {"key": "mark"}},"value": 0x1338}},
                            {"queue": {"num": str(init) if init == end else {"range":[init, end] }, "flags": ["bypass"]}}
                        ]
                }}}
            )
        else:
            self.cmd(
                { "insert":{ "rule": {
                    "family": "inet",
                    "table": self.table_name,
                    "chain": self.output_chain,
                    "expr": [
                            {'match': {'left': {'payload': {'protocol': ip_family(srv.ip_int), 'field': 'saddr'}}, 'op': '==', 'right': nftables_int_to_json(srv.ip_int)}},
                            {'match': {"left": { "payload": {"protocol": str(srv.proto), "field": "sport"}}, "op": "==", "right": int(srv.port)}},
                            {"mangle": {"key": {"meta": {"key": "mark"}},"value": 0x1338}},
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
                            {"mangle": {"key": {"meta": {"key": "mark"}},"value": 0x1337}},
                            {"queue": {"num": str(init) if init == end else {"range":[init, end] }, "flags": ["bypass"]}}
                        ]
                }}}
            )


    def get(self) -> list[FiregexFilter]:
        res = []
        for filter in self.list_rules(tables=[self.table_name], chains=[self.input_chain,self.output_chain,self.nat_chain]):
            try:
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
            except (KeyError, TypeError, IndexError):
                pass  # Rule has unexpected structure (e.g., intermediate NAT rule), skip
        return res

    def delete(self, srv:Service):
        delete_cmds = []
        for filter in self.get():
            if filter.matches(srv):
                delete_cmds.append({ "delete":{ "rule": {
                    "family": "inet",
                    "table": self.table_name,
                    "chain": filter.target,
                    "handle": filter.id
                }}})
        if delete_cmds:
            self.cmd(*delete_cmds)
            