from typing import List
from pypacker import interceptor
from pypacker.layer3 import ip, ip6
from pypacker.layer4 import tcp, udp
from subprocess import Popen, PIPE
import os, traceback, pcre, re
from ipaddress import ip_interface

QUEUE_BASE_NUM = 1000

class FilterTypes:
    INPUT = "FIREGEX-INPUT"
    OUTPUT = "FIREGEX-OUTPUT"

class ProtoTypes:
    TCP = "tcp"
    UDP = "udp"

class IPTables:

    def __init__(self, ipv6=False, table="mangle"):
        self.ipv6 = ipv6
        self.table = table
    
    def command(self, params):
        params = ["-t", self.table] + params
        if os.geteuid() != 0:
            exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
        return Popen(["ip6tables"]+params if self.ipv6 else ["iptables"]+params, stdout=PIPE, stderr=PIPE).communicate()

    def list_filters(self, param):
        stdout, strerr = self.command(["-L", str(param), "--line-number", "-n"])
        output = [re.findall(r"([^ ]*)[ ]{,10}([^ ]*)[ ]{,5}([^ ]*)[ ]{,5}([^ ]*)[ ]{,5}([^ ]*)[ ]+([^ ]*)[ ]+(.*)", ele) for ele in stdout.decode().split("\n")]
        return [{
            "id": ele[0][0].strip(),
            "target": ele[0][1].strip(),
            "prot": ele[0][2].strip(),
            "opt": ele[0][3].strip(),
            "source": ele[0][4].strip(),
            "destination": ele[0][5].strip(),
            "details": " ".join(ele[0][6:]).strip() if len(ele[0]) >= 7 else "",
        } for ele in output if len(ele) > 0 and ele[0][0].isnumeric()]

    def delete_command(self, param, id):
        self.command(["-D", str(param), str(id)])
    
    def create_chain(self, name):
        self.command(["-N", str(name)])

    def flush_chain(self, name):
        self.command(["-F", str(name)])

    def add_chain_to_input(self, name):
        if not self.find_if_filter_exists("PREROUTING", str(name)):
            self.command(["-I", "PREROUTING", "-j", str(name)])
    
    def add_chain_to_output(self, name):
        if not self.find_if_filter_exists("POSTROUTING", str(name)):
            self.command(["-I", "POSTROUTING", "-j", str(name)])

    def find_if_filter_exists(self, type, target):
        for filter in self.list_filters(type):
            if filter["target"] == target:
                return True
        return False

    def add_s_to_c(self, queue_range, proto = None, port = None, ip_int = None):
        init, end = queue_range
        if init > end: init, end = end, init
        self.command(["-A", FilterTypes.OUTPUT,
            * (["-p", str(proto)] if proto else []),
            * (["-s", str(ip_int)] if ip_int else []),
            * (["--sport", str(port)] if port else []),
            "-j", "NFQUEUE",
            * (["--queue-num", f"{init}"] if init == end else ["--queue-balance", f"{init}:{end}"]),
            "--queue-bypass"
        ])

    def add_c_to_s(self, queue_range, proto = None, port = None, ip_int = None):
        init, end = queue_range
        if init > end: init, end = end, init
        self.command(["-A", FilterTypes.INPUT,
            * (["-p", str(proto)] if proto else []),
            * (["-d", str(ip_int)] if ip_int else []),
            * (["--dport", str(port)] if port else []),
            "-j", "NFQUEUE",
            * (["--queue-num", f"{init}"] if init == end else ["--queue-balance", f"{init}:{end}"]),
            "--queue-bypass"
        ])

class FiregexFilter():
    def __init__(self, type, number, queue, proto, port, ipv6, ip_int):
        self.type = type
        self.id = int(number)
        self.queue = queue
        self.proto = proto
        self.port = int(port)
        self.iptable = IPTables(ipv6)
        self.ip_int = str(ip_int)

    def __repr__(self) -> str:
        return f"<FiregexFilter type={self.type} id={self.id} port={self.port} proto={self.proto} queue={self.queue}>"

    def delete(self):
        self.iptable.delete_command(self.type, self.id)

class Interceptor:
    def __init__(self, iptables, ip_int, c_to_s, s_to_c, proto, ipv6, port, n_threads):
        self.proto = proto
        self.ipv6 = ipv6
        self.itor_c_to_s, codes = self._start_queue(c_to_s, n_threads)
        iptables.add_c_to_s(queue_range=codes, proto=proto, port=port, ip_int=ip_int)
        self.itor_s_to_c, codes = self._start_queue(s_to_c, n_threads)
        iptables.add_s_to_c(queue_range=codes, proto=proto, port=port, ip_int=ip_int)

    def _start_queue(self,func,n_threads):
        def func_wrap(ll_data, ll_proto_id, data, ctx, *args):
            pkt_parsed = ip6.IP6(data) if self.ipv6 else ip.IP(data)
            try:
                level4 = None
                if self.proto == ProtoTypes.TCP: level4 = pkt_parsed[tcp.TCP].body_bytes
                elif self.proto == ProtoTypes.UDP: level4 = pkt_parsed[udp.UDP].body_bytes
                if level4:
                    if func(level4):
                        return data, interceptor.NF_ACCEPT
                    elif self.proto == ProtoTypes.TCP:
                        pkt_parsed[tcp.TCP].flags &= 0x00
                        pkt_parsed[tcp.TCP].flags |= tcp.TH_FIN | tcp.TH_ACK
                        pkt_parsed[tcp.TCP].body_bytes = b""
                        return pkt_parsed.bin(), interceptor.NF_ACCEPT
                    else: return b"", interceptor.NF_DROP
                else: return pkt_parsed.bin(), interceptor.NF_ACCEPT
            except Exception:
                traceback.print_exc()
                return pkt_parsed.bin(), interceptor.NF_ACCEPT
        
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
        self.itor_c_to_s.stop()
        self.itor_s_to_c.stop()

class FiregexFilterManager:

    def __init__(self, srv):
        self.ipv6 = srv["ipv6"]
        self.iptables = IPTables(self.ipv6)
        self.iptables.create_chain(FilterTypes.INPUT)
        self.iptables.create_chain(FilterTypes.OUTPUT)
        self.iptables.add_chain_to_input(FilterTypes.INPUT)
        self.iptables.add_chain_to_output(FilterTypes.OUTPUT)

    def get(self) -> List[FiregexFilter]:
        res = []
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            for filter in self.iptables.list_filters(filter_type):
                queue_num = None
                balanced = re.findall(r"NFQUEUE balance ([0-9]+):([0-9]+)", filter["details"])
                numbered = re.findall(r"NFQUEUE num ([0-9]+)", filter["details"])
                port = re.findall(r"[sd]pt:([0-9]+)", filter["details"])
                if balanced: queue_num = (int(balanced[0][0]), int(balanced[0][1]))
                if numbered: queue_num = (int(numbered[0]), int(numbered[0]))
                if queue_num and port:
                    res.append(FiregexFilter(
                        type=filter_type,
                        number=filter["id"],
                        queue=queue_num,
                        proto=filter["prot"],
                        port=int(port[0]),
                        ipv6=self.ipv6,
                        ip_int=filter["source"] if filter_type == FilterTypes.OUTPUT else filter["destination"]
                    ))
        return res
    
    def add(self, proto, port, ip_int, func):
        for ele in self.get():
            if int(port) == ele.port and proto == ele.proto and ip_interface(ip_int) == ip_interface(ele.ip_int):
                return None
        
        def c_to_s(pkt): return func(pkt, True)
        def s_to_c(pkt): return func(pkt, False)

        itor = Interceptor( iptables=self.iptables, ip_int=ip_int,
                            c_to_s=c_to_s, s_to_c=s_to_c,
                            proto=proto, ipv6=self.ipv6, port=port,
                            n_threads=int(os.getenv("N_THREADS_NFQUEUE","1")))
        return itor

    def delete_all(self):
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            self.iptables.flush_chain(filter_type)
    
    def delete_by_srv(self, srv):
        for filter in self.get():
            if filter.port == int(srv["port"]) and filter.proto == srv["proto"] and ip_interface(filter.ip_int) == ip_interface(srv["ip_int"]):
                filter.delete()

class Filter:
    def __init__(self, regex, is_case_sensitive=True, is_blacklist=True, c_to_s=False, s_to_c=False, blocked_packets=0, code=None):
        self.regex = regex
        self.is_case_sensitive = is_case_sensitive
        self.is_blacklist = is_blacklist
        if c_to_s == s_to_c: c_to_s = s_to_c = True # (False, False) == (True, True)
        self.c_to_s = c_to_s
        self.s_to_c = s_to_c
        self.blocked = blocked_packets
        self.code = code
        self.compiled_regex = self.compile()
    
    def compile(self):
        if isinstance(self.regex, str): self.regex = self.regex.encode()
        if not isinstance(self.regex, bytes): raise Exception("Invalid Regex Paramether")
        return pcre.compile(self.regex if self.is_case_sensitive else b"(?i)"+self.regex)

    def check(self, data):
        return True if self.compiled_regex.search(data) else False

class Proxy:
    def __init__(self, srv, filters=None):
        self.srv = srv
        self.manager = FiregexFilterManager(self.srv)
        self.filters: List[Filter] = filters if filters else []
        self.interceptor = None
        
    def set_filters(self, filters):
        elements_to_pop = len(self.filters)
        for ele in filters:
            self.filters.append(ele)
        for _ in range(elements_to_pop):
            self.filters.pop(0)

    def start(self):
        if not self.interceptor:
            self.manager.delete_by_srv(self.srv)
            def regex_filter(pkt, by_client):
                try:
                    for filter in self.filters:
                        if (by_client and filter.c_to_s) or (not by_client and filter.s_to_c):
                            match = filter.check(pkt)
                            if (filter.is_blacklist and match) or (not filter.is_blacklist and not match):
                                filter.blocked+=1
                                return False
                except IndexError: pass
                return True

            self.interceptor = self.manager.add(self.srv["proto"], self.srv["port"], self.srv["ip_int"], regex_filter)


    def stop(self):
        self.manager.delete_by_srv(self.srv)
        if self.interceptor:
            self.interceptor.stop()
            self.interceptor = None

    def restart(self):
        self.stop()
        self.start()