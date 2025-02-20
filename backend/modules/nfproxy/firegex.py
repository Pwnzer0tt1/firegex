from modules.nfproxy.nftables import FiregexTables
from utils import run_func
from modules.nfproxy.models import Service, PyFilter
import os
import asyncio
from utils import DEBUG
import traceback
from fastapi import HTTPException

nft = FiregexTables()

class FiregexInterceptor:
    
    def __init__(self):
        self.srv:Service
        self._stats_updater_cb:callable
        self.filter_map_lock:asyncio.Lock
        self.filter_map: dict[str, PyFilter]
        self.pyfilters: set[PyFilter]
        self.update_config_lock:asyncio.Lock
        self.process:asyncio.subprocess.Process
        self.update_task: asyncio.Task
        self.ack_arrived = False
        self.ack_status = None
        self.ack_fail_what = "Unknown"
        self.ack_lock = asyncio.Lock()
    
    async def _call_stats_updater_callback(self, filter: PyFilter):
        if self._stats_updater_cb:
            await run_func(self._stats_updater_cb(filter))
    
    @classmethod
    async def start(cls, srv: Service, stats_updater_cb:callable):
        self = cls()
        self._stats_updater_cb = stats_updater_cb
        self.srv = srv
        self.filter_map_lock = asyncio.Lock()
        self.update_config_lock = asyncio.Lock()
        queue_range = await self._start_binary()
        self.update_task = asyncio.create_task(self.update_stats())
        nft.add(self.srv, queue_range)
        if not self.ack_lock.locked():
            await self.ack_lock.acquire()
        return self
    
    async def _start_binary(self):
        proxy_binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),"../cpproxy")
        self.process = await asyncio.create_subprocess_exec(
            proxy_binary_path,
            stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE,
            env={
                "NTHREADS": os.getenv("NTHREADS","1"),
                "FIREGEX_NFQUEUE_FAIL_OPEN": "1" if self.srv.fail_open else "0",
            },
        )
        line_fut = self.process.stdout.readuntil()
        try:
            line_fut = await asyncio.wait_for(line_fut, timeout=3)
        except asyncio.TimeoutError:
            self.process.kill()
            raise Exception("Invalid binary output")
        line = line_fut.decode()
        if line.startswith("QUEUE "):
            params = line.split()
            return (int(params[1]), int(params[1]))
        else:
            self.process.kill()
            raise Exception("Invalid binary output")

    async def update_stats(self):
        try:
            while True:
                line = (await self.process.stdout.readuntil()).decode()
                if DEBUG:
                    print(line)
                if line.startswith("BLOCKED "):
                    filter_id = line.split()[1]
                    async with self.filter_map_lock:
                        if filter_id in self.filter_map:
                            self.filter_map[filter_id].blocked_packets+=1
                            await self.filter_map[filter_id].update()
                if line.startswith("MANGLED "):
                    filter_id = line.split()[1]
                    async with self.filter_map_lock:
                        if filter_id in self.filter_map:
                            self.filter_map[filter_id].edited_packets+=1
                            await self.filter_map[filter_id].update()
                if line.startswith("EXCEPTION"):
                    print("TODO EXCEPTION HANDLING") # TODO
                if line.startswith("ACK "):
                    self.ack_arrived = True
                    self.ack_status = line.split()[1].upper() == "OK"
                    if not self.ack_status:
                        self.ack_fail_what = " ".join(line.split()[2:])
                    self.ack_lock.release()
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
    
    async def _update_config(self, code):
        async with self.update_config_lock:
            self.process.stdin.write(len(code).to_bytes(4, byteorder='big')+code.encode())
            await self.process.stdin.drain()
            try:
                async with asyncio.timeout(3):
                    await self.ack_lock.acquire()
            except TimeoutError:
                pass
            if not self.ack_arrived or not self.ack_status:
                await self.stop()
                raise HTTPException(status_code=500, detail=f"NFQ error: {self.ack_fail_what}")

    async def reload(self, filters:list[PyFilter]):
        async with self.filter_map_lock:
            if os.path.exists(f"db/nfproxy_filters/{self.srv.id}.py"):
                with open(f"db/nfproxy_filters/{self.srv.id}.py") as f:
                    filter_file = f.read()
            else:
                filter_file = ""
            await self._update_config(
                "global __firegex_pyfilter_enabled\n" +
                "__firegex_pyfilter_enabled = [" + ", ".join([repr(f.name) for f in filters]) + "]\n" +
                "__firegex_proto = " + repr(self.srv.proto) + "\n" +
                "import firegex.nfproxy.internals\n\n" + 
                filter_file + "\n\n" +
                "firegex.nfproxy.internals.compile()"
            )

