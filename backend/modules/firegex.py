from typing import List
from pypacker import interceptor
from pypacker.layer3 import ip, ip6
from pypacker.layer4 import tcp, udp
from ipaddress import ip_interface
from modules.iptables import IPTables
import os, traceback

from modules.sqlite import Service

class FilterTypes:
    INPUT = "FIREGEX-INPUT"
    OUTPUT = "FIREGEX-OUTPUT"

QUEUE_BASE_NUM = 1000

class FiregexFilter():
    def __init__(self, proto:str, port:int, ip_int:str, queue=None, target=None, id=None, func=None):
        self.target = target
        self.id = int(id) if id else None
        self.queue = queue
        self.proto = proto
        self.port = int(port)
        self.ip_int = str(ip_int)
        self.func = func

    def __eq__(self, o: object) -> bool:
        if isinstance(o, FiregexFilter):
            return self.port == o.port and self.proto == o.proto and ip_interface(self.ip_int) == ip_interface(o.ip_int)
        return False
    
    def ipv6(self):
        return ip_interface(self.ip_int).version == 6

    def ipv4(self):
        return ip_interface(self.ip_int).version == 4

    def input_func(self):
        def none(pkt): return True
        def wrap(pkt): return self.func(pkt, True)
        return wrap if self.func else none
        
    def output_func(self):
        def none(pkt): return True
        def wrap(pkt): return self.func(pkt, False)
        return wrap if self.func else none

class FiregexTables(IPTables):

    def __init__(self, ipv6=False):
        super().__init__(ipv6, "mangle")
        self.create_chain(FilterTypes.INPUT)
        self.add_chain_to_input(FilterTypes.INPUT)
        self.create_chain(FilterTypes.OUTPUT)
        self.add_chain_to_output(FilterTypes.OUTPUT)
    
    def target_in_chain(self, chain, target):
        for filter in self.list()[chain]:
            if filter.target == target:
                return True
        return False
    
    def add_chain_to_input(self, chain):
        if not self.target_in_chain("PREROUTING", str(chain)):
            self.insert_rule("PREROUTING", str(chain))
    
    def add_chain_to_output(self, chain):
        if not self.target_in_chain("POSTROUTING", str(chain)):
            self.insert_rule("POSTROUTING", str(chain))

    def add_output(self, queue_range, proto = None, port = None, ip_int = None):
        init, end = queue_range
        if init > end: init, end = end, init
        self.append_rule(FilterTypes.OUTPUT,"NFQUEUE"
            * (["-p", str(proto)] if proto else []),
            * (["-s", str(ip_int)] if ip_int else []),
            * (["--sport", str(port)] if port else []),
            * (["--queue-num", f"{init}"] if init == end else ["--queue-balance", f"{init}:{end}"]),
            "--queue-bypass"
        )

    def add_input(self, queue_range, proto = None, port = None, ip_int = None):
        init, end = queue_range
        if init > end: init, end = end, init
        self.append_rule(FilterTypes.INPUT, "NFQUEUE",
            * (["-p", str(proto)] if proto else []),
            * (["-d", str(ip_int)] if ip_int else []),
            * (["--dport", str(port)] if port else []),
            * (["--queue-num", f"{init}"] if init == end else ["--queue-balance", f"{init}:{end}"]),
            "--queue-bypass"
        )

    def get(self) -> List[FiregexFilter]:
        res = []
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            for filter in self.list()[filter_type]:
                port = filter.sport() if filter_type == FilterTypes.OUTPUT else filter.dport()
                queue = filter.nfqueue()
                if queue and port:
                    res.append(FiregexFilter(
                        target=filter_type,
                        id=filter.id,
                        queue=queue,
                        proto=filter.prot,
                        port=port,
                        ip_int=filter.source if filter_type == FilterTypes.OUTPUT else filter.destination
                    ))
        return res
    
    def add(self, filter:FiregexFilter):
        if filter in self.get(): return None
        return FiregexInterceptor( iptables=self, filter=filter, n_threads=int(os.getenv("N_THREADS_NFQUEUE","1")))

    def delete_all(self):
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            self.flush_chain(filter_type)
    
    def delete_by_srv(self, srv:Service):
        for filter in self.get():
            if filter.port == srv.port and filter.proto == srv.proto and ip_interface(filter.ip_int) == ip_interface(srv.ip_int):
                self.delete_rule(filter.target, filter.id)

class FiregexInterceptor:
    def __init__(self, iptables: FiregexTables, filter: FiregexFilter, n_threads:int = 1):
        self.filter = filter
        self.ipv6 = self.filter.ipv6()
        self.itor_input, codes = self._start_queue(filter.input_func(), n_threads)
        iptables.add_input(queue_range=codes, proto=self.filter.proto, port=self.filter.port, ip_int=self.filter.ip_int)
        self.itor_output, codes = self._start_queue(filter.output_func(), n_threads)
        iptables.add_output(queue_range=codes, proto=self.filter.proto, port=self.filter.port, ip_int=self.filter.ip_int)

    def _start_queue(self,func,n_threads):
        def func_wrap(ll_data, ll_proto_id, data, ctx, *args):
            pkt_parsed = ip6.IP6(data) if self.ipv6 else ip.IP(data)
            try:
                data = None
                if not pkt_parsed[tcp.TCP] is None:
                    data = pkt_parsed[tcp.TCP].body_bytes
                if not pkt_parsed[tcp.TCP] is None:
                    data = pkt_parsed[udp.UDP].body_bytes
                if data:
                    if func(data):
                        return data, interceptor.NF_ACCEPT
                    elif pkt_parsed[tcp.TCP]:
                        pkt_parsed[tcp.TCP].flags &= 0x00
                        pkt_parsed[tcp.TCP].flags |= tcp.TH_FIN | tcp.TH_ACK
                        pkt_parsed[tcp.TCP].body_bytes = b""
                        return pkt_parsed.bin(), interceptor.NF_ACCEPT
                    else: return b"", interceptor.NF_DROP
                else: return data, interceptor.NF_ACCEPT
            except Exception:
                traceback.print_exc()
                return data, interceptor.NF_ACCEPT
        
        ictor = interceptor.Interceptor()
        starts = QUEUE_BASE_NUM
        while True:
            if starts >= 65536:
                raise Exception("Netfilter queue is full!")
            queue_ids = list(range(starts,starts+n_threads))
            try:
                ictor.start(func_wrap, queue_ids=queue_ids)
                break
            except interceptor.UnableToBindException as e:
                starts = e.queue_id + 1
        return ictor, (starts, starts+n_threads-1)

    def stop(self):
        self.itor_input.stop()
        self.itor_output.stop()