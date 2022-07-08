import multiprocessing
from threading import Thread
from typing import List
from netfilterqueue import NetfilterQueue
from multiprocessing import Manager, Process
from scapy.all import IP, TCP, UDP
from subprocess import Popen, PIPE
import os, traceback, pcre, re

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

    @staticmethod
    def command(params):
        if os.geteuid() != 0:
            exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
        return Popen(["iptables"]+params, stdout=PIPE, stderr=PIPE).communicate()

    @staticmethod
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

    @staticmethod
    def delete_command(param, id):
        IPTables.command(["-R", str(param), str(id)])
    
    @staticmethod
    def create_chain(name):
        IPTables.command(["-N", str(name)])

    @staticmethod
    def flush_chain(name):
        IPTables.command(["-F", str(name)])

    @staticmethod
    def add_chain_to_input(name):
        IPTables.command(["-I", "INPUT", "-j", str(name)])

    @staticmethod
    def add_chain_to_output(name):
        IPTables.command(["-I", "OUTPUT", "-j", str(name)])

    @staticmethod
    def add_s_to_c(proto, port, queue_range):
        init, end = queue_range
        if init > end: init, end = end, init
        IPTables.command([
            "-A", FilterTypes.OUTPUT, "-p", str(proto),
            "--sport", str(port), "-j", "NFQUEUE",
            "--queue-num" if init == end else "--queue-balance",
            f"{init}" if init == end else f"{init}:{end}", "--queue-bypass"
        ])

    @staticmethod
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
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            for filter in IPTables.list_filters(filter_type):
                queue_num = None
                balanced = re.findall(r"NFQUEUE balance ([0-9]+):([0-9]+)", filter["details"])
                numbered = re.findall(r"NFQUEUE num ([0-9]+)", filter["details"])
                port = re.findall(r"[sd]pt:([0-9]+)", filter["details"])
                if balanced: queue_num = (int(balanced[0]), int(balanced[1]))
                if numbered: queue_num = (int(numbered[0]), int(numbered[0]))
                if queue_num and port:
                    res.append(FiregexFilter(
                        type=filter_type,
                        number=filter["id"],
                        queue=queue_num,
                        proto=filter["prot"],
                        port=int(port[0])
                    ))
        return res
    
    def add(self, proto, port, func, n_threads = 1):
        for ele in self.get():
            if int(port) == ele.port: return None
        
        def c_to_s(pkt, data): return func(pkt, data, True)
        def s_to_c(pkt, data): return func(pkt, data, False)

        queues_c_to_s, codes = bind_queues(c_to_s, n_threads)
        IPTables.add_c_to_s(proto, port, codes)
        queues_s_to_c, codes = bind_queues(s_to_c, n_threads)
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
        return pcre.compile(self.regex if self.is_case_sensitive else b"(?i)"+self.regex)

    def check(self, data):
        return True if self.compiled_regex.search(data) else False
    
    def inc_block(self):
        print("INC", self.blocked)
        self.blocked+=1

class Proxy:
    def __init__(self, port, filters=None):
        self.manager = FiregexFilterManager()
        self.port = port
        self.filters = Manager().list(filters) if filters else Manager().list([])
        self.process = None
        
    def set_filters(self, filters):
        elements_to_pop = len(self.filters)
        for ele in filters:
            self.filters.append(ele)
        for _ in range(elements_to_pop):
            self.filters.pop(0)

    def _starter(self):
        self.manager.delete_by_port(self.port)
        def regex_filter(pkt, data, by_client):
            packet = bytes(data[TCP if TCP in data else UDP].payload)
            try:
                for filter in self.filters:
                    if (by_client and filter.c_to_s) or (not by_client and filter.s_to_c):
                        match = filter.check(packet)
                        if (filter.is_blacklist and match) or (not filter.is_blacklist and not match):
                            filter.inc_block()
                            pkt.drop()
                            return 
            except IndexError: pass
            pkt.accept()
        queue_list = self.manager.add(ProtoTypes.TCP, self.port, regex_filter)
        threads = []
        for ele in queue_list:
            threads.append(Thread(target=ele.run))
            threads[-1].daemon = True
            threads[-1].start()
        for ele in threads: ele.join()
        for ele in queue_list: ele.unbind()

    def start(self):
        self.process = Process(target=self._starter)
        self.process.start()

    def stop(self):
        self.manager.delete_by_port(self.port)
        if self.process:
            self.process.kill()
            self.process = None

    def restart(self):
        self.stop()
        self.start()

