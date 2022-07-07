from typing import List, Set
from netfilterqueue import NetfilterQueue
from threading import Lock, Thread
from scapy.all import IP, TCP, UDP
from subprocess import Popen, PIPE
import os, pcre2, traceback, asyncio
from kthread import KThread

QUEUE_BASE_NUM = 1000

def bind_queues(func, len_list=1):
    if len_list <= 0: raise Exception("len must be >= 1")
    queue_list = []
    starts = QUEUE_BASE_NUM
    end = starts
    
    def func_wrap(pkt):
        pkt_parsed = IP(pkt.get_payload())
        try:
            if pkt_parsed[UDP if UDP in pkt_parsed else TCP].payload: func(pkt, pkt_parsed)
            else: pkt.accept()
        except Exception:
            traceback.print_exc()
            pkt.accept()

    while True:
        if starts >= 65536:
            raise Exception("Netfilter queue is full!")
        try:
            for _ in range(len_list):
                queue_list.append(NetfilterQueue())
                queue_list[-1].bind(end, func_wrap)
                end+=1
            end-=1
            break
        except OSError:
            del queue_list[-1]
            for ele in queue_list:
                ele.unbind()
            queue_list = []
            starts = end = end+1
    return queue_list, (starts, end)

class FilterTypes:
    INPUT = "FIREGEX-INPUT"
    OUTPUT = "FIREGEX-OUTPUT"

class ProtoTypes:
    TCP = "tcp"
    UDP = "udp"

class IPTables:

    def command(params):
        if os.geteuid() != 0:
            exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
        return Popen(["iptables"]+params, stdout=PIPE, stderr=PIPE).communicate()

    def list_filters(param):
        stdout, strerr = IPTables.command(["-L", str(param), "--line-number", "-n"])
        output = [ele.split() for ele in stdout.decode().split("\n")]
        return [{
            "id": ele[0],
            "target": ele[1],
            "prot": ele[2],
            "opt": ele[3],
            "source": ele[4],
            "destination": ele[5],
            "details": " ".join(ele[6:]) if len(ele) >= 7 else "",
        } for ele in output if len(ele) >= 6 and ele[0].isnumeric()]

    def delete_command(param, id):
        IPTables.command(["-R", str(param), str(id)])
    
    def create_chain(name):
        IPTables.command(["-N", str(name)])

    def flush_chain(name):
        IPTables.command(["-F", str(name)])

    def add_chain_to_input(name):
        IPTables.command(["-I", "INPUT", "-j", str(name)])

    def add_chain_to_output(name):
        IPTables.command(["-I", "OUTPUT", "-j", str(name)])

    def add_s_to_c(proto, port, queue_range):
        init, end = queue_range
        if init > end: init, end = end, init
        IPTables.command([
            "-A", FilterTypes.OUTPUT, "-p", str(proto),
            "--sport", str(port), "-j", "NFQUEUE",
            "--queue-num" if init == end else "--queue-balance",
            f"{init}" if init == end else f"{init}:{end}", "--queue-bypass"
        ])

    def add_c_to_s(proto, port, queue_range):
        init, end = queue_range
        if init > end: init, end = end, init
        IPTables.command([
            "-A", FilterTypes.INPUT, "-p", str(proto),
            "--dport", str(port), "-j", "NFQUEUE",
            "--queue-num" if init == end else "--queue-balance",
            f"{init}" if init == end else f"{init}:{end}", "--queue-bypass"
        ])

class FiregexFilter():
    def __init__(self, type, number, queue, proto, port):
        self.type = type
        self.id = int(number)
        self.queue = queue
        self.proto = proto
        self.port = int(port)
    def __repr__(self) -> str:
        return f"<FiregexFilter type={self.type} id={self.id} port={self.port} proto={self.proto} queue={self.queue}>"

    def delete(self):
        IPTables.delete_command(self.type, self.id)

class FiregexFilterManager:

    def __init__(self):
        IPTables.create_chain(FilterTypes.INPUT)
        IPTables.create_chain(FilterTypes.OUTPUT)
        input_found = False
        output_found = False
        for filter in IPTables.list_filters("INPUT"):
            if filter["target"] == FilterTypes.INPUT:
                input_found = True
                break
        for filter in IPTables.list_filters("OUTPUT"):
            if filter["target"] == FilterTypes.OUTPUT:
                output_found = True
                break
        if not input_found: IPTables.add_chain_to_input(FilterTypes.INPUT)
        if not output_found: IPTables.add_chain_to_output(FilterTypes.OUTPUT)


    def get(self) -> List[FiregexFilter]:
        res = []
        balanced_mode = pcre2.PCRE2(b"NFQUEUE balance ([0-9]+):([0-9]+)")
        num_mode = pcre2.PCRE2(b"NFQUEUE num ([0-9]+)")
        port_selected = pcre2.PCRE2(b"[sd]pt:([0-9]+)")
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            for filter in IPTables.list_filters(filter_type):
                queue_num = None
                balanced = balanced_mode.search(filter["details"].encode())
                numbered = num_mode.search(filter["details"].encode())
                port = port_selected.search(filter["details"].encode())
                if balanced: queue_num = (int(balanced.group(1).decode()), int(balanced.group(2).decode()))
                if numbered: queue_num = (int(numbered.group(1).decode()), int(numbered.group(1).decode()))
                if queue_num and port:
                    res.append(FiregexFilter(
                        type=filter_type,
                        number=filter["id"],
                        queue=queue_num,
                        proto=filter["prot"],
                        port=port.group(1).decode()
                    ))
        return res
    
    def add(self, proto, port, func_c_to_s, func_s_to_c, n_threads = 1):
        for ele in self.get():
            if int(port) == ele.port: return None
        queues_c_to_s, codes = bind_queues(func_c_to_s, n_threads)
        IPTables.add_c_to_s(proto, port, codes)
        queues_s_to_c, codes = bind_queues(func_s_to_c, n_threads)
        IPTables.add_s_to_c(proto, port, codes)
        return queues_c_to_s + queues_s_to_c

    def delete_all(self):
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            IPTables.flush_chain(filter_type)
    
    def delete_by_port(self, port):
        for filter in self.get():
            if filter.port == int(port):
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
        return pcre2.PCRE2(self.regex if self.is_case_sensitive else b"(?i)"+self.regex)

    def check(self, data):
        return True if self.compiled_regex.search(data) else False

class Proxy:
    def __init__(self, public_port = 0, callback_blocked_update=None, filters=None):
        self.manager = FiregexFilterManager()
        self.port = public_port
        self.filters: Set[Filter] = set(filters) if filters else set([])
        self.use_filters = True
        self.callback_blocked_update = callback_blocked_update
        self.threads = []
        self.queue_list = []

    def start(self):
        self.manager.delete_by_port(self.port)

        def c_to_s(pkt, data):
            packet = bytes(data[TCP].payload)
            try:
                for filter in self.filters:
                    if filter.c_to_s:
                        match = filter.check(packet)
                        if (filter.is_blacklist and match) or (not filter.is_blacklist and not match):
                            filter.blocked+=1
                            self.callback_blocked_update(filter)
                            pkt.drop()
                            return 
            except IndexError:
                pass
            pkt.accept()

        def s_to_c(pkt, data):
            packet = bytes(data[TCP].payload)
            try:
                for filter in self.filters:
                    if filter.s_to_c:
                        match = filter.check(packet)
                        if (filter.is_blacklist and match) or (not filter.is_blacklist and not match):
                            filter.blocked+=1
                            self.callback_blocked_update(filter)
                            pkt.drop()
                            return 
            except IndexError:
                pass
            pkt.accept()

        self.queue_list = self.manager.add(ProtoTypes.TCP, self.port, c_to_s, s_to_c)
        for ele in self.queue_list:
            self.threads.append(KThread(target=ele.run))
            self.threads[-1].daemon = True
            self.threads[-1].start()

    def stop(self):
        self.manager.delete_by_port(self.port)
        for ele in self.threads:
            ele.kill()
            if ele.is_alive():
                print("Not killed succesffully") #TODO
        self.threads = []
        for ele in self.queue_list:
            ele.unbind()
        self.queue_list = []
        

    def restart(self):
        self.stop()
        self.start()