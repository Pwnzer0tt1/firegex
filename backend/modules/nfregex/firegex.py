from modules.nfregex.nftables import FiregexTables
from utils import run_func
from modules.nfregex.models import Service, Regex
import re
import os
import asyncio
import traceback
from utils import DEBUG

nft = FiregexTables()

class RegexFilter:
    def __init__(
        self, regex,
        is_case_sensitive=True,
        input_mode=False,
        output_mode=False,
        blocked_packets=0,
        id=None,
        update_func = None
    ):
        self.regex = regex
        self.is_case_sensitive = is_case_sensitive
        if input_mode == output_mode:
            input_mode = output_mode = True # (False, False) == (True, True)
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
            blocked_packets=regex.blocked_packets,
            input_mode = regex.mode in ["C","B"], output_mode=regex.mode in ["S","B"],
            update_func = update_func
        )
    def compile(self):
        if isinstance(self.regex, str):
            self.regex = self.regex.encode()
        if not isinstance(self.regex, bytes):
            raise Exception("Invalid Regex Paramether")
        re.compile(self.regex) # raise re.error if it's invalid!
        case_sensitive = "1" if self.is_case_sensitive else "0"
        if self.input_mode:
            yield case_sensitive + "C" + self.regex.hex()
        if self.output_mode:
            yield case_sensitive + "S" + self.regex.hex()
    
    async def update(self):
        if self.update_func:
            await run_func(self.update_func, self)

class FiregexInterceptor:
    
    def __init__(self):
        self.srv:Service
        self.filter_map_lock:asyncio.Lock
        self.filter_map: dict[str, RegexFilter]
        self.regex_filters: set[RegexFilter]
        self.update_config_lock:asyncio.Lock
        self.process:asyncio.subprocess.Process
        self.update_task: asyncio.Task
    
    @classmethod
    async def start(cls, srv: Service):
        self = cls()
        self.srv = srv
        self.filter_map_lock = asyncio.Lock()
        self.update_config_lock = asyncio.Lock()
        queue_range = await self._start_binary()
        self.update_task = asyncio.create_task(self.update_blocked())
        nft.add(self.srv, queue_range)
        return self
    
    async def _start_binary(self):
        proxy_binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),"../cppqueue")
        self.process = await asyncio.create_subprocess_exec(
            proxy_binary_path,
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
            return (int(params[1]), int(params[2]))
        else:
            self.process.kill()
            raise Exception("Invalid binary output")

    async def update_blocked(self):
        try:
            while True:
                line = (await self.process.stdout.readuntil()).decode()
                if DEBUG:
                    print(line)
                if line.startswith("BLOCKED"):
                    regex_id = line.split()[1]
                    async with self.filter_map_lock:
                        if regex_id in self.filter_map:
                            self.filter_map[regex_id].blocked+=1
                            await self.filter_map[regex_id].update()
        except asyncio.CancelledError:
            pass
        except asyncio.IncompleteReadError:
            pass
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

    async def reload(self, filters:list[RegexFilter]):
        async with self.filter_map_lock:
            self.filter_map = self.compile_filters(filters)
            filters_codes = self.get_filter_codes()
            await self._update_config(filters_codes)
    
    def get_filter_codes(self):
        filters_codes = list(self.filter_map.keys())
        filters_codes.sort(key=lambda a: self.filter_map[a].blocked, reverse=True)
        return filters_codes

    def compile_filters(self, filters:list[RegexFilter]):
        res = {}
        for filter_obj in filters:
            try:
                raw_filters = filter_obj.compile()
                for filter in raw_filters:
                    res[filter] = filter_obj
            except Exception:
                pass
        return res

