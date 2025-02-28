from modules.nfproxy.nftables import FiregexTables
from modules.nfproxy.models import Service, PyFilter
import os
import asyncio
import traceback
from fastapi import HTTPException
import time
from utils import run_func

nft = FiregexTables()

OUTSTREAM_BUFFER_SIZE = 1024*10

class FiregexInterceptor:
    
    def __init__(self):
        self.srv:Service
        self.filter_map_lock:asyncio.Lock
        self.filter_map: dict[str, PyFilter]
        self.update_config_lock:asyncio.Lock
        self.process:asyncio.subprocess.Process
        self.update_task: asyncio.Task
        self.server_task: asyncio.Task
        self.sock_path: str
        self.unix_sock: asyncio.Server
        self.ack_arrived = False
        self.ack_status = None
        self.ack_fail_what = "Queue response timed-out"
        self.ack_lock = asyncio.Lock()
        self.sock_reader:asyncio.StreamReader = None
        self.sock_writer:asyncio.StreamWriter = None
        self.sock_conn_lock:asyncio.Lock
        self.last_time_exception = 0
        self.outstrem_function = None
        self.expection_function = None
        self.outstrem_task: asyncio.Task
        self.outstrem_buffer = ""
    
    @classmethod
    async def start(cls, srv: Service, outstream_func=None, exception_func=None):
        self = cls()
        self.srv = srv
        self.filter_map_lock = asyncio.Lock()
        self.update_config_lock = asyncio.Lock()
        self.sock_conn_lock = asyncio.Lock()
        self.outstrem_function = outstream_func
        self.expection_function = exception_func
        if not self.sock_conn_lock.locked():
            await self.sock_conn_lock.acquire()
        self.sock_path = f"/tmp/firegex_nfproxy_{srv.id}.sock"
        if os.path.exists(self.sock_path):
            os.remove(self.sock_path)
        self.unix_sock = await asyncio.start_unix_server(self._server_listener,path=self.sock_path)
        self.server_task = asyncio.create_task(self.unix_sock.serve_forever())
        queue_range = await self._start_binary()
        self.update_task = asyncio.create_task(self.update_stats())
        nft.add(self.srv, queue_range)
        if not self.ack_lock.locked():
            await self.ack_lock.acquire()
        return self
    
    async def _stream_handler(self):
        while True:
            try:
                line = (await self.process.stdout.readuntil()).decode(errors="ignore")
                print(line, end="")
            except Exception as e:
                self.ack_arrived = False
                self.ack_status = False
                self.ack_fail_what = "Can't read from nfq client"
                self.ack_lock.release()
                await self.stop()
                raise HTTPException(status_code=500, detail="Can't read from nfq client") from e
            self.outstrem_buffer+=line
            if len(self.outstrem_buffer) > OUTSTREAM_BUFFER_SIZE:
                self.outstrem_buffer = self.outstrem_buffer[-OUTSTREAM_BUFFER_SIZE:]+"\n"
            if self.outstrem_function:
                await run_func(self.outstrem_function, self.srv.id, line)
    
    async def _start_binary(self):
        proxy_binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),"../cpproxy")
        self.process = await asyncio.create_subprocess_exec(
            proxy_binary_path, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={
                "NTHREADS": os.getenv("NTHREADS","1"),
                "FIREGEX_NFQUEUE_FAIL_OPEN": "1" if self.srv.fail_open else "0",
                "FIREGEX_NFPROXY_SOCK": self.sock_path
            },
        )
        self.outstrem_task = asyncio.create_task(self._stream_handler())
        try:
            async with asyncio.timeout(3):
                await self.sock_conn_lock.acquire()
                line_fut = await self.sock_reader.readuntil()
        except asyncio.TimeoutError:
            self.process.kill()
            raise Exception("Binary don't returned queue number until timeout")
        line = line_fut.decode()
        if line.startswith("QUEUE "):
            params = line.split()
            return (int(params[1]), int(params[1]))
        else:
            self.process.kill()
            raise Exception("Invalid binary output")

    async def _server_listener(self, reader:asyncio.StreamReader, writer:asyncio.StreamWriter):
        if self.sock_reader or self.sock_writer:
            writer.write_eof() # Technically never reached
            writer.close()
            reader.feed_eof()
            return
        self.sock_reader = reader
        self.sock_writer = writer
        self.sock_conn_lock.release()

    async def update_stats(self):
        try:
            while True:
                try:
                    line = (await self.sock_reader.readuntil()).decode()
                except Exception as e:
                    self.ack_arrived = False
                    self.ack_status = False
                    self.ack_fail_what = "Can't read from nfq client"
                    self.ack_lock.release()
                    await self.stop()
                    raise HTTPException(status_code=500, detail="Can't read from nfq client") from e
                if line.startswith("BLOCKED "):
                    filter_name = line.split()[1]
                    print("BLOCKED", filter_name)
                    async with self.filter_map_lock:
                        if filter_name in self.filter_map:
                            self.filter_map[filter_name].blocked_packets+=1
                            await self.filter_map[filter_name].update()  
                if line.startswith("MANGLED "):
                    filter_name = line.split()[1]
                    async with self.filter_map_lock:
                        if filter_name in self.filter_map:
                            self.filter_map[filter_name].edited_packets+=1
                            await self.filter_map[filter_name].update()
                if line.startswith("EXCEPTION"):
                    self.last_time_exception = int(time.time()*1000) #ms timestamp
                    if self.expection_function:
                        await run_func(self.expection_function, self.srv.id, self.last_time_exception)
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
        self.server_task.cancel()
        self.update_task.cancel()
        self.unix_sock.close()
        self.outstrem_task.cancel()
        if os.path.exists(self.sock_path):
            os.remove(self.sock_path)
        if self.process and self.process.returncode is None:
            self.process.kill()
    
    async def _update_config(self, code):
        async with self.update_config_lock:
            if self.sock_writer:
                self.sock_writer.write(len(code).to_bytes(4, byteorder='big')+code.encode())
                await self.sock_writer.drain()
                try:
                    async with asyncio.timeout(3):
                        await self.ack_lock.acquire()
                except TimeoutError:
                    self.ack_fail_what = "Queue response timed-out"
                if not self.ack_arrived or not self.ack_status:
                    await self.stop()
                    raise HTTPException(status_code=500, detail=f"NFQ error: {self.ack_fail_what}")
            else:
                raise HTTPException(status_code=400, detail="Socket not ready")

    async def reload(self, filters:list[PyFilter]):
        async with self.filter_map_lock:
            if os.path.exists(f"db/nfproxy_filters/{self.srv.id}.py"):
                with open(f"db/nfproxy_filters/{self.srv.id}.py") as f:
                    filter_file = f.read()
            else:
                filter_file = ""
            self.filter_map = {ele.name: ele for ele in filters}
            await self._update_config(

                filter_file + "\n\n" +
                "__firegex_pyfilter_enabled = [" + ", ".join([repr(f.name) for f in filters]) + "]\n" +
                "__firegex_proto = " + repr(self.srv.proto) + "\n" +
                "import firegex.nfproxy.internals\n" + 
                "firegex.nfproxy.internals.compile(globals())\n"
            )

