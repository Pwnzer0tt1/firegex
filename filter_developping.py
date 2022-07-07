from argparse import ArgumentError
from tracemalloc import start
from typing import List
from netfilterqueue import NetfilterQueue
from threading import Thread
from scapy.all import IP, TCP, UDP
from subprocess import Popen, PIPE
import os, pcre2

QUEUE_BASE_NUM = 1000

def bind_queues(func, proto, len_list=1):
    if len_list <= 0: raise ArgumentError("len must be >= 1")
    queue_list = []
    starts = QUEUE_BASE_NUM
    end = starts
    
    def func_wrap(pkt):
        pkt_parsed = IP(pkt.get_payload())
        try:
            data = pkt_parsed[UDP if proto == ProtoTypes.UDP else TCP].payload
            print(data)
            if data: func(pkt, data)
            else: pkt.accept()
        except Exception:
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


class IPTables:
    def list_filters(param):
        if os.geteuid() != 0:
            exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
        process = Popen(["iptables", "-L", str(param), "--line-number", "-n"], stdout=PIPE)
        stdout, strerr = process.communicate()
        output = [ele.split() for ele in stdout.decode().split("\n")]
        output = [{
            "id": ele[0],
            "target": ele[1],
            "prot": ele[2],
            "opt": ele[3],
            "source": ele[4],
            "destination": ele[5],
            "details": " ".join(ele[6:]) if len(ele) >= 7 else "",
            "comment": "",
        } for ele in output if len(ele) >= 6 and ele[0].isnumeric()]
        comment_checker = pcre2.PCRE2(b'\/\* (.*) \*\/')
        for ele in output:
            res = comment_checker.search(ele["details"].encode())
            if res:
                ele["comment"] = res.group(1).decode()
        return output

    def delete_command(param, id):
        process = Popen(["iptables", "-R", str(param), str(id)])
        process.communicate()
    
    def add_s_to_c(proto, port, queue_range, comment):
        init, end = queue_range
        if init > end: init, end = end, init
        proc = Popen([
            "iptables", "-I", FilterTypes.OUTPUT, "-p", str(proto),
            "--sport", str(port), "-j", "NFQUEUE",
            "--queue-num" if init == end else "--queue-balance",
            f"{init}" if init == end else f"{init}:{end}", #"--queue-bypass",
            "-m", "comment", "--comment", str(comment)])
        proc.communicate()

    def add_c_to_s(proto, port, queue_range, comment):
        init, end = queue_range
        if init > end: init, end = end, init
        proc = Popen([
            "iptables", "-I", FilterTypes.INPUT, "-p", str(proto),
            "--dport", str(port), "-j", "NFQUEUE",
            "--queue-num" if init == end else "--queue-balance",
            f"{init}" if init == end else f"{init}:{end}", #"--queue-bypass",
            "-m", "comment", "--comment", str(comment)])
        proc.communicate()

class FilterTypes:
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"

class ProtoTypes:
    TCP = "tcp"
    UPD = "udp"

class FiregexFilter():
    def __init__(self, type, number, service, queue, proto, port):
        self.type = type
        self.id = int(number)
        self.service = service
        self.queue = queue
        self.proto = proto
        self.port = int(port)
    def __repr__(self) -> str:
        return f"<FiregexFilter type={self.type} id={self.id} port={self.port} proto={self.proto} service={self.service} queue={self.queue}>"

    def delete(self):
        IPTables.delete_command(self.type, self.id)

class FiregexFilterManager:
    def get() -> List[FiregexFilter]:
        res = []
        firegex_tag_decoder = pcre2.PCRE2(b"&firegex&(.*)&")
        balanced_mode = pcre2.PCRE2(b"NFQUEUE balance ([0-9]+):([0-9]+)")
        num_mode = pcre2.PCRE2(b"NFQUEUE num ([0-9]+)")
        port_selected = pcre2.PCRE2(b"[sd]pt:([0-9]+)")
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            for filter in IPTables.list_filters(filter_type):
                firegex_tag = firegex_tag_decoder.search(filter["comment"].encode())
                if firegex_tag:
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
                            service=firegex_tag.group(1).decode(),
                            queue=queue_num,
                            proto=filter["prot"],
                            port=port.group(1).decode()
                        ))
        return res
    
    def add(service:str, proto, port, func_c_to_s, func_s_to_c, n_threads = 1):
        if "&" in service: raise ArgumentError("Illegal service name! '&' is not allowed!")
        queues_c_to_s, codes = bind_queues(func_c_to_s, proto, n_threads)
        IPTables.add_c_to_s(proto, port, codes, f"&firegex&{service}&")
        queues_s_to_c, codes = bind_queues(func_s_to_c, proto, n_threads)
        IPTables.add_s_to_c(proto, port, codes, f"&firegex&{service}&")
        return queues_c_to_s + queues_s_to_c

    def delete_all():
        for filter in FiregexFilterManager.get():
            filter.delete()
    
    def delete_by_service(srv):
        for filter in FiregexFilterManager.get():
            if filter.service == srv:
                filter.delete()

def c_to_s(pkt, data):
    print("SENDING", data)
    pkt.accept()

def s_to_c(pkt, data):
    print("RECIVING", data)
    pkt.accept()

try:
    FiregexFilterManager.delete_by_service("test_service")
    thr_list = []
    q_list = FiregexFilterManager.add("test_service",ProtoTypes.TCP, 8080, c_to_s, s_to_c)
    print(FiregexFilterManager.get())
    for q in q_list:
        print(q.run)
        thr_list.append(Thread(target=q.run))
        thr_list[-1].start()

    for t in thr_list:
        t.join()
except KeyboardInterrupt:
    for q in q_list:
        q.unbind()

    FiregexFilterManager.delete_by_service("test_service")

#sudo iptables -I OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 10001 --queue-bypass -m comment --comment "&firegex&servid& Text"
#sudo iptables -I INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 10000 --queue-bypass -m comment --comment "&firegex&servid& Text"