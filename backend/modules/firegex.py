from typing import Dict, List, Set
from ipaddress import ip_interface
from modules.iptables import IPTables
from modules.sqlite import Service
import re, os, asyncio
import traceback

from modules.sqlite import Regex

class FilterTypes:
    INPUT = "FIREGEX-INPUT"
    OUTPUT = "FIREGEX-OUTPUT"

QUEUE_BASE_NUM = 1000

class FiregexFilter():
    def __init__(self, proto:str, port:int, ip_int:str, queue=None, target=None, id=None):
        self.target = target
        self.id = int(id) if id else None
        self.queue = queue
        self.proto = proto
        self.port = int(port)
        self.ip_int = str(ip_int)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, FiregexFilter):
            return self.port == o.port and self.proto == o.proto and ip_interface(self.ip_int) == ip_interface(o.ip_int)
        return False
    
    def ipv6(self):
        return ip_interface(self.ip_int).version == 6

    def ipv4(self):
        return ip_interface(self.ip_int).version == 4

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
        self.append_rule(FilterTypes.OUTPUT,"NFQUEUE",
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
        iptables_filters = self.list()
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            for filter in iptables_filters[filter_type]:
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
    
    async def add(self, filter:FiregexFilter):
        if filter in self.get(): return None
        return await FiregexInterceptor.start( iptables=self, filter=filter, n_queues=int(os.getenv("N_THREADS_NFQUEUE","1")))

    def delete_all(self):
        for filter_type in [FilterTypes.INPUT, FilterTypes.OUTPUT]:
            self.flush_chain(filter_type)
    
    def delete_by_srv(self, srv:Service):
        for filter in self.get():
            if filter.port == srv.port and filter.proto == srv.proto and ip_interface(filter.ip_int) == ip_interface(srv.ip_int):
                self.delete_rule(filter.target, filter.id)
            

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
        self.ipv6:bool
        self.filter_map_lock:asyncio.Lock
        self.filter_map: Dict[str, RegexFilter]
        self.regex_filters: Set[RegexFilter]
        self.update_config_lock:asyncio.Lock
        self.process:asyncio.subprocess.Process
        self.n_queues:int
        self.update_task: asyncio.Task
        self.iptables:FiregexTables
    
    @classmethod
    async def start(cls, iptables: FiregexTables, filter: FiregexFilter, n_queues:int = 1):
        self = cls()
        self.filter = filter
        self.n_queues = n_queues
        self.iptables = iptables
        self.ipv6 = self.filter.ipv6()
        self.filter_map_lock = asyncio.Lock()
        self.update_config_lock = asyncio.Lock()
        input_range, output_range = await self._start_binary()
        self.update_task = asyncio.create_task(self.update_blocked())
        self.iptables.add_input(queue_range=input_range, proto=self.filter.proto, port=self.filter.port, ip_int=self.filter.ip_int)
        self.iptables.add_output(queue_range=output_range, proto=self.filter.proto, port=self.filter.port, ip_int=self.filter.ip_int)
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