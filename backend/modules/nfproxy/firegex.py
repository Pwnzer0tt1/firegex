from modules.nfproxy.nftables import FiregexTables
from utils import run_func
from modules.nfproxy.models import Service, PyFilter
import os
import asyncio
import socket
import shutil

nft = FiregexTables()

class FiregexInterceptor:
    
    def __init__(self):
        self.srv:Service
        self._stats_updater_cb:callable
        self.process:asyncio.subprocess.Process
        self.base_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "socks", self.srv.id
        )
        self.n_threads = int(os.getenv("NTHREADS","1"))
        
        self.connection_socket = os.path.join(self.base_dir, "connection.sock")
        self.vedict_sockets = [os.path.join(self.base_dir, f"vedict{i}.sock") for i in range(self.n_threads)]
        self.socks = []
    
    def add_sock(self, path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(path)
        self.socks.append(sock)
        return sock
    
    async def _call_stats_updater_callback(self, filter: PyFilter):
        if self._stats_updater_cb:
            await run_func(self._stats_updater_cb(filter))
    
    @classmethod
    async def start(cls, srv: Service, stats_updater_cb:callable):
        self = cls()
        self.srv = srv
        self._stats_updater_cb = stats_updater_cb
        os.makedirs(self.base_dir, exist_ok=True)
        self.add_sock(self.connection_socket)
        for path in self.vedict_sockets:
            self.add_sock(path)
        queue_range = await self._start_binary()
        # TODO starts python workers
        nft.add(self.srv, queue_range)
        return self
    
    async def _start_binary(self):
        proxy_binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),"../cppproxy")
        self.process = await asyncio.create_subprocess_exec(
            proxy_binary_path,
            stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE,
        )
        self.process.stdin.write(self.base_dir.encode().hex().encode()+b" 3\n")
        await self.process.stdin.drain()
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

    async def stop(self):
        if self.process and self.process.returncode is None:
            self.process.kill()
        for sock in self.socks:
            sock.close()
        shutil.rmtree(self.base_dir)

    async def reload(self, filters:list[PyFilter]):
        # filters are the functions to use in the workers (other functions are disabled or not flagged as filters)
        # TODO update filters in python workers (prob for new filters added) (reading from file????)
        pass