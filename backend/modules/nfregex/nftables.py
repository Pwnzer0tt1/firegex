from modules.nfregex.models import Service
from utils import ip_parse, ip_family, NFTableManager, nftables_int_to_json
from modules.tls.manager import get_tls_ports, TLSManager

def resolve_target(srv: Service) -> tuple[str, int] | None:
    """Returns the (ip_int, port) a service's intercept rule should actually match.
    For target_type=='tls' this is the loopback clear_port where nginx exposes the
    decrypted plaintext, not the service's own (real backend) ip_int/port. Returns
    None if the linked TLS stream can't be resolved (e.g. it was deleted)."""
    if srv.target_type == "tls":
        tls_stream = TLSManager().get_stream(srv.tls_stream_id)
        if not tls_stream:
            return None
        _, clear_port = get_tls_ports(tls_stream["ip_int"], tls_stream["port"])
        loopback_ip = "::1" if ip_family(tls_stream["ip_int"]) == "ip6" else "127.0.0.1"
        return loopback_ip, clear_port
    return srv.ip_int, srv.port

class FiregexFilter:
    def __init__(self, proto:str, port:int, ip_int:str, target:str, id:int):
        self.id = id
        self.target = target
        self.proto = proto
        self.port = int(port)
        self.ip_int = str(ip_int)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, FiregexFilter):
            return self.port == o.port and self.proto == o.proto and ip_parse(self.ip_int) == ip_parse(o.ip_int)
        if isinstance(o, Service):
            return self.matches(o)
        return False

    def matches(self, srv: Service) -> bool:
        if self.proto != str(srv.proto):
            return False
        target = resolve_target(srv)
        if target is None:
            return False
        target_ip, target_port = target
        return self.port == target_port and ip_parse(self.ip_int) == ip_parse(target_ip)

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
            }}}
        ],[
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.input_chain}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.input_chain}}},
            {"flush":{"chain":{"table":self.table_name,"family":"inet", "name":self.output_chain}}},
            {"delete":{"chain":{"table":self.table_name,"family":"inet", "name":self.output_chain}}},
        ])

    def add(self, srv:Service, queue_range):

        for ele in self.get():
            if ele.matches(srv):
                return

        target = resolve_target(srv)
        if target is None:
            return
        target_ip, target_port = target

        init, end = queue_range
        if init > end:
            init, end = end, init

        self.cmd(
            { "insert":{ "rule": {
                "family": "inet",
                "table": self.table_name,
                "chain": self.output_chain,
                "expr": [
                        {'match': {'left': {'payload': {'protocol': ip_family(target_ip), 'field': 'saddr'}}, 'op': '==', 'right': nftables_int_to_json(target_ip)}},
                        {'match': {"left": { "payload": {"protocol": str(srv.proto), "field": "sport"}}, "op": "==", "right": int(target_port)}},
                        {"mangle": {"key": {"meta": {"key": "mark"}},"value": 0x1338}},
                        {"queue": {"num": str(init) if init == end else {"range":[init, end] }, "flags": ["bypass"]}}
                ]
            }}},
            {"insert":{"rule":{
                "family": "inet",
                "table": self.table_name,
                "chain": self.input_chain,
                "expr": [
                        {'match': {'left': {'payload': {'protocol': ip_family(target_ip), 'field': 'daddr'}}, 'op': '==', 'right': nftables_int_to_json(target_ip)}},
                        {'match': {"left": { "payload": {"protocol": str(srv.proto), "field": "dport"}}, "op": "==", "right": int(target_port)}},
                        {"mangle": {"key": {"meta": {"key": "mark"}},"value": 0x1337}},
                        {"queue": {"num": str(init) if init == end else {"range":[init, end] }, "flags": ["bypass"]}}
                    ]
            }}}
        )


    def get(self) -> list[FiregexFilter]:
        res = []
        for filter in self.list_rules(tables=[self.table_name], chains=[self.input_chain,self.output_chain]):
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
            