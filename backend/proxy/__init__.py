import subprocess, re, os, asyncio

#c++ -o proxy proxy.cpp

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
    
    def compile(self):
        if isinstance(self.regex, str): self.regex = self.regex.encode()
        if not isinstance(self.regex, bytes): raise Exception("Invalid Regex Paramether")
        re.compile(self.regex) # raise re.error if is invalid!
        case_sensitive = "1" if self.is_case_sensitive else "0"
        if self.c_to_s:
            yield case_sensitive + "C" + self.regex.hex() if self.is_blacklist else case_sensitive + "c"+ self.regex.hex()
        if self.s_to_c:
            yield case_sensitive + "S" + self.regex.hex() if self.is_blacklist else case_sensitive + "s"+ self.regex.hex()

class Proxy:
    def __init__(self, internal_port=0, public_port=0, callback_blocked_update=None, filters=None, public_host="0.0.0.0", internal_host="127.0.0.1"):
        self.filter_map = {}
        self.filter_map_lock = asyncio.Lock()
        self.update_config_lock = asyncio.Lock()
        self.status_change = asyncio.Lock()
        self.public_host = public_host
        self.public_port = public_port
        self.internal_host = internal_host
        self.internal_port = internal_port
        self.filters = set(filters) if filters else set([])
        self.process = None
        self.callback_blocked_update = callback_blocked_update
    
    async def start(self, in_pause=False):
        await self.status_change.acquire()
        if not self.isactive():
            try:
                self.filter_map = self.compile_filters()
                filters_codes = list(self.filter_map.keys()) if not in_pause else []
                proxy_binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),"./proxy")

                self.process = await asyncio.create_subprocess_exec(
                    proxy_binary_path, str(self.public_host), str(self.public_port), str(self.internal_host), str(self.internal_port),
                    stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE
                )
                await self.update_config(filters_codes)
            finally:
                self.status_change.release()
            try:
                while True:
                    buff = await self.process.stdout.readuntil()
                    stdout_line = buff.decode()
                    if stdout_line.startswith("BLOCKED"):
                        regex_id = stdout_line.split()[1]
                        async with self.filter_map_lock:
                            self.filter_map[regex_id].blocked+=1
                            if self.callback_blocked_update: await self.callback_blocked_update(self.filter_map[regex_id])
            except Exception:
                return await self.process.wait()
        else:
            self.status_change.release()
                 

    async def stop(self):
        async with self.status_change:
            if self.isactive():
                self.process.kill()
                self.process = None
                return False
            return True

    async def restart(self, in_pause=False):
        status = await self.stop()
        await self.start(in_pause=in_pause)
        return status
    
    async def update_config(self, filters_codes):
        async with self.update_config_lock:
            if (self.isactive()):
                self.process.stdin.write((" ".join(filters_codes)+"\n").encode())
                await self.process.stdin.drain()

    async def reload(self):
        if self.isactive():
            async with self.filter_map_lock:
                self.filter_map = self.compile_filters()
                filters_codes = list(self.filter_map.keys())
                await self.update_config(filters_codes)

    def isactive(self):
        if self.process and not self.process.returncode is None:
            self.process = None
        return True if self.process else False

    async def pause(self):
        if self.isactive():
            await self.update_config([])
        else:
            await self.start(in_pause=True)

    def compile_filters(self):
        res = {}
        for filter_obj in self.filters:
            try:
                raw_filters = filter_obj.compile()
                for filter in raw_filters:
                    res[filter] = filter_obj
            except Exception: pass
        return res
