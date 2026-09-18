import asyncio
import time
import traceback
from modules.nfregex.firegex import FiregexInterceptor, RegexFilter
from modules.nfregex.nftables import FiregexTables, FiregexFilter
from modules.nfregex.models import Regex, Service
from utils.sqlite import SQLite
from utils import socketio_emit

class STATUS:
    STOP = "stop"
    ACTIVE = "active"

nft = FiregexTables()

MODULE = "nfregex"
# How many times a service may be brought back up before it is declared broken,
# and after how long without a crash the counter goes back to zero.
MAX_RESTART_ATTEMPTS = 5
CRASH_COUNTER_RESET_SECONDS = 60


class ServiceManager:
    def __init__(self, srv: Service, db):
        self.srv = srv
        self.db = db
        self.status = STATUS.STOP
        self.filters: dict[int, FiregexFilter] = {}
        self.lock = asyncio.Lock()
        self.interceptor = None
        self._crash_count = 0
        self._last_crash_time = 0.0
    
    async def _update_filters_from_db(self):
        regexes = [
            Regex.from_dict(ele) for ele in
                self.db.query("SELECT * FROM regexes WHERE service_id = ? AND active=1;", self.srv.id)
        ]
        #Filter check
        old_filters = set(self.filters.keys())
        new_filters = set([f.id for f in regexes])
        #remove old filters
        for f in old_filters:
            if f not in new_filters:
                del self.filters[f]
        #add new filters
        for f in new_filters:
            if f not in old_filters:
                filter = [ele for ele in regexes if ele.id == f][0]
                self.filters[f] = RegexFilter.from_regex(filter, self._stats_updater)
        if self.interceptor:
            await self.interceptor.reload(self.filters.values())
    
    def __update_status_db(self, status):
        self.db.query("UPDATE services SET status = ? WHERE service_id = ?;", status, self.srv.id)

    async def next(self,to,persist:bool=True):
        async with self.lock:
            if to == STATUS.STOP:
                await self.stop(persist=persist)
            if to == STATUS.ACTIVE:
                await self.restart()

    def _stats_updater(self,filter:RegexFilter):
        self.db.query("UPDATE regexes SET blocked_packets = ? WHERE regex_id = ?;", filter.blocked, filter.id)

    def _set_status(self,status,persist:bool=True):
        self.status = status
        if persist:
            self.__update_status_db(status)


    async def _on_interceptor_exit(self, returncode: int):
        """Recovers from an unexpected death of the interceptor binary.

        Restarting rebuilds both the process and its nftables rules; it is
        attempted a bounded number of times so that a systematically crashing
        interceptor does not turn into a restart loop. When the budget is
        exhausted the service is stopped for good, which at least removes the
        rules and makes the failure visible instead of leaving a service that
        claims to be active while filtering nothing.
        """
        async with self.lock:
            if self.interceptor is None or self.status != STATUS.ACTIVE:
                return  # Already being stopped on purpose
            # The process is already gone, but its sockets and reader tasks are
            # not: release them before building a replacement.
            await self.interceptor.stop()
            self.interceptor = None
            now = time.monotonic()
            if now - self._last_crash_time > CRASH_COUNTER_RESET_SECONDS:
                self._crash_count = 0
            self._last_crash_time = now
            self._crash_count += 1
            if self._crash_count > MAX_RESTART_ATTEMPTS:
                print(f"[error] [{MODULE}] Service {self.srv.id} crashed {self._crash_count} times (last exit code {returncode}), giving up and stopping it")
                await self.stop()
            else:
                print(f"[warning] [{MODULE}] Restarting the interceptor of service {self.srv.id} after exit code {returncode} ({self._crash_count}/{MAX_RESTART_ATTEMPTS})")
                try:
                    await self.start()
                except Exception:
                    traceback.print_exc()
                    await self.stop()
        await socketio_emit([MODULE])

    async def start(self):
        if not self.interceptor:
            nft.delete(self.srv)
            self.interceptor = await FiregexInterceptor.start(self.srv, on_exit=self._on_interceptor_exit)
            await self._update_filters_from_db()
            self._set_status(STATUS.ACTIVE)

    async def stop(self,persist:bool=True):
        nft.delete(self.srv)
        if self.interceptor:
            await self.interceptor.stop()
            self.interceptor = None
        self._set_status(STATUS.STOP,persist=persist)
    
    async def restart(self):
        await self.stop()
        await self.start()

    async def update_filters(self):
        async with self.lock:
            await self._update_filters_from_db()



class FirewallManager:
    def __init__(self, db:SQLite):
        self.db = db
        self.service_table: dict[str, ServiceManager] = {}
        self.lock = asyncio.Lock()

    async def close(self):
        for key in list(self.service_table.keys()):
            try:
                await self.remove(key, persist=False)
            except Exception:
                # Don't let one broken service block shutdown of the others
                self.service_table.pop(key, None)

    async def remove(self,srv_id,persist:bool=True):
        async with self.lock:
            if srv_id in self.service_table:
                await self.service_table[srv_id].next(STATUS.STOP,persist=persist)
                del self.service_table[srv_id]
    
    async def init(self):
        nft.init()
        await self.reload()

    async def reload(self):
        async with self.lock: 
            services = self.db.query('SELECT * FROM services;')
            
            for srv in services:
                if srv["service_id"] in self.service_table:
                    continue
                srv_obj = Service.from_dict(srv)
                self.service_table[srv_obj.id] = ServiceManager(srv_obj, self.db)
                await self.service_table[srv_obj.id].next(srv_obj.status)

    def get(self,srv_id) -> ServiceManager:
        if srv_id in self.service_table:
            return self.service_table[srv_id]
        else:
            raise ServiceNotFoundException()
        
class ServiceNotFoundException(Exception):
    pass
