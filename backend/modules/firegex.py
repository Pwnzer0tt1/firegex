from typing import Dict, List, Set
from utils import ip_parse, ip_family
from modules.sqlite import Service
import re, os, asyncio
import traceback, nftables

from modules.sqlite import Regex

QUEUE_BASE_NUM = 1000

class FiregexFilter():
    def __init__(self, proto:str, port:int, ip_int:str, queue=None, target:str=None, id=None):
        self.nftables = nftables.Nftables()
        self.id = int(id) if id else None
        self.queue = queue
        self.target = target
        self.proto = proto
        self.port = int(port)
        self.ip_int = str(ip_int)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, FiregexFilter):
            return self.port == o.port and self.proto == o.proto and ip_parse(self.ip_int) == ip_parse(o.ip_int)
        return False

class FiregexTables:

    def __init__(self):
        self.table_name = "firegex"
        self.nft = nftables.Nftables()
    
    def raw_cmd(self, *cmds):
        return self.nft.json_cmd({"nftables": list(cmds)})

    def cmd(self, *cmds):
        code, out, err = self.raw_cmd(*cmds)

        if code == 0: return out
        else: raise Exception(err)
    
    def init(self):
        code, out, err = self.raw_cmd({"create":{"table":{"name":self.table_name,"family":"inet"}}})
        if code == 0:
            self.cmd(
                {"create":{"chain":{
                    "family":"inet",
                    "table":self.table_name,
                    "name":"input",
                    "type":"filter",
                    "hook":"prerouting",
                    "prio":-150,
                    "policy":"accept"
                }}},
                {"create":{"chain":{
                    "family":"inet",
                    "table":self.table_name,
                    "name":"output",
                    "type":"filter",
                    "hook":"postrouting",
                    "prio":-150,
                    "policy":"accept"
                }}}
            )
        self.reset()
            
    def reset(self):
        self.cmd({"flush":{"table":{"name":"firegex","family":"inet"}}})

    def list(self):
        return self.cmd({"list": {"ruleset": None}})["nftables"]

    def add_output(self, queue_range, proto, port, ip_int):
        init, end = queue_range
        if init > end: init, end = end, init
        ip_int = ip_parse(ip_int)
        ip_addr = str(ip_int).split("/")[0]
        ip_addr_cidr = int(str(ip_int).split("/")[1])
        self.cmd({ "insert":{ "rule": {
            "family": "inet",
            "table": self.table_name,
            "chain": "output",
            "expr": [
                    {'match': {'left': {'payload': {'protocol': ip_family(ip_int), 'field': 'saddr'}}, 'op': '==', 'right': {"prefix": {"addr": ip_addr, "len": ip_addr_cidr}}}}, #ip_int
                    {'match': {'left': {'meta': {'key': 'l4proto'}}, 'op': '==', 'right': str(proto)}},
                    {'match': {"left": { "payload": {"protocol": str(proto), "field": "sport"}}, "op": "==", "right": int(port)}},
                    {"queue": {"num": str(init) if init == end else f"{init}-{end}", "flags": ["bypass"]}}
                ]
        }}})

    def add_input(self, queue_range, proto = None, port = None, ip_int = None):
        init, end = queue_range
        if init > end: init, end = end, init
        ip_int = ip_parse(ip_int)
        ip_addr = str(ip_int).split("/")[0]
        ip_addr_cidr = int(str(ip_int).split("/")[1])
        self.cmd({"insert":{"rule":{
            "family": "inet",
            "table": self.table_name,
            "chain": "input",
            "expr": [
                    {'match': {'left': {'payload': {'protocol': ip_family(ip_int), 'field': 'daddr'}}, 'op': '==', 'right': {"prefix": {"addr": ip_addr, "len": ip_addr_cidr}}}}, #ip_int
                    {'match': {"left": { "payload": {"protocol": str(proto), "field": "dport"}}, "op": "==", "right": int(port)}},
                    {"queue": {"num": str(init) if init == end else f"{init}-{end}", "flags": ["bypass"]}}
                ]
        }}})

    def get(self) -> List[FiregexFilter]:
        res = []
        for filter in [ele["rule"] for ele in self.list() if "rule" in ele and ele["rule"]["table"] == self.table_name]:
            queue_str = str(filter["expr"][2]["queue"]["num"]).split("-")
            queue = None
            if len(queue_str) == 1: queue = int(queue_str[0]), int(queue_str[0])
            else: queue = int(queue_str[0]), int(queue_str[1])
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
    
    async def add(self, filter:FiregexFilter):
        if filter in self.get(): return None
        return await FiregexInterceptor.start( filter=filter, n_queues=int(os.getenv("N_THREADS_NFQUEUE","1")))
    
    def delete_by_srv(self, srv:Service):
        for filter in self.get():
            if filter.port == srv.port and filter.proto == srv.proto and ip_parse(filter.ip_int) == ip_parse(srv.ip_int):
                print("DELETE CMD", {"delete":{"rule": {"handle": filter.id, "table": self.table_name, "chain": filter.target, "family": "inet"}}})
                self.cmd({"delete":{"rule": {"handle": filter.id, "table": self.table_name, "chain": filter.target, "family": "inet"}}})
            

class RegexFilter:
    def __init__(
        self, regex,
        is_case_sensitive=True,
        is_blacklist=True,
        input_mode=False,
        output_mode=False,
        blocked_packets=0,
        id=None,
        update_func = None
    ):
        self.regex = regex
        self.is_case_sensitive = is_case_sensitive
        self.is_blacklist = is_blacklist
        if input_mode == output_mode: input_mode = output_mode = True # (False, False) == (True, True)
        self.input_mode = input_mode
        self.output_mode = output_mode
        self.blocked = blocked_packets
        self.id = id
        self.update_func = update_func
        self.compiled_regex = self.compile()
    
    @classmethod
    def from_regex(cls, regex:Regex, update_func = None):
        return cls(
            id=regex.id, regex=regex.regex, is_case_sensitive=regex.is_case_sensitive,
            is_blacklist=regex.is_blacklist, blocked_packets=regex.blocked_packets,
            input_mode = regex.mode in ["C","B"], output_mode=regex.mode in ["S","B"],
            update_func = update_func
        )
    def compile(self):
        if isinstance(self.regex, str): self.regex = self.regex.encode()
        if not isinstance(self.regex, bytes): raise Exception("Invalid Regex Paramether")
        re.compile(self.regex) # raise re.error if it's invalid!
        case_sensitive = "1" if self.is_case_sensitive else "0"
        if self.input_mode:
            yield case_sensitive + "C" + self.regex.hex() if self.is_blacklist else case_sensitive + "c"+ self.regex.hex()
        if self.output_mode:
            yield case_sensitive + "S" + self.regex.hex() if self.is_blacklist else case_sensitive + "s"+ self.regex.hex()
    
    async def update(self):
        if self.update_func:
            if asyncio.iscoroutinefunction(self.update_func): await self.update_func(self)
            else: self.update_func(self)

class FiregexInterceptor:
    
    def __init__(self):
        self.filter:FiregexFilter
        self.filter_map_lock:asyncio.Lock
        self.filter_map: Dict[str, RegexFilter]
        self.regex_filters: Set[RegexFilter]
        self.update_config_lock:asyncio.Lock
        self.process:asyncio.subprocess.Process
        self.n_queues:int
        self.update_task: asyncio.Task
    
    @classmethod
    async def start(cls, filter: FiregexFilter, n_queues:int = 1):
        self = cls()
        self.filter = filter
        self.n_queues = n_queues
        self.filter_map_lock = asyncio.Lock()
        self.update_config_lock = asyncio.Lock()
        input_range, output_range = await self._start_binary()
        self.update_task = asyncio.create_task(self.update_blocked())
        FiregexTables().add_input(queue_range=input_range, proto=self.filter.proto, port=self.filter.port, ip_int=self.filter.ip_int)
        FiregexTables().add_output(queue_range=output_range, proto=self.filter.proto, port=self.filter.port, ip_int=self.filter.ip_int)
        return self
    
    async def _start_binary(self):
        proxy_binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),"./cppqueue")
        self.process = await asyncio.create_subprocess_exec(
            proxy_binary_path, str(self.n_queues),
            stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE
        )
        line_fut = self.process.stdout.readuntil()
        try:
            line_fut = await asyncio.wait_for(line_fut, timeout=3)
        except asyncio.TimeoutError:
            self.process.kill()
            raise Exception("Invalid binary output")
        line = line_fut.decode()
        if line.startswith("QUEUES "):
            params = line.split()
            return (int(params[2]), int(params[3])), (int(params[5]), int(params[6]))
        else:
            self.process.kill()
            raise Exception("Invalid binary output")

    async def update_blocked(self):
        try:
            while True:
                line = (await self.process.stdout.readuntil()).decode()
                if line.startswith("BLOCKED"):
                    regex_id = line.split()[1]
                    async with self.filter_map_lock:
                        if regex_id in self.filter_map:
                            self.filter_map[regex_id].blocked+=1
                            await self.filter_map[regex_id].update()
        except asyncio.CancelledError: pass
        except asyncio.IncompleteReadError: pass
        except Exception:
            traceback.print_exc()

    async def stop(self):
        self.update_task.cancel()
        if self.process and self.process.returncode is None:
            self.process.kill()
    
    async def _update_config(self, filters_codes):
        async with self.update_config_lock:
            self.process.stdin.write((" ".join(filters_codes)+"\n").encode())
            await self.process.stdin.drain()

    async def reload(self, filters:List[RegexFilter]):
        async with self.filter_map_lock:
            self.filter_map = self.compile_filters(filters)
            filters_codes = self.get_filter_codes()
            await self._update_config(filters_codes)
    
    def get_filter_codes(self):
        filters_codes = list(self.filter_map.keys())
        filters_codes.sort(key=lambda a: self.filter_map[a].blocked, reverse=True)
        return filters_codes

    def compile_filters(self, filters:List[RegexFilter]):
        res = {}
        for filter_obj in filters:
            try:
                raw_filters = filter_obj.compile()
                for filter in raw_filters:
                    res[filter] = filter_obj
            except Exception: pass
        return res