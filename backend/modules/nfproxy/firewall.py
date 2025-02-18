import asyncio
from modules.nfproxy.firegex import FiregexInterceptor
from modules.nfproxy.nftables import FiregexTables, FiregexFilter
from modules.nfproxy.models import Service, PyFilter
from utils.sqlite import SQLite

class STATUS:
    STOP = "stop"
    ACTIVE = "active"

nft = FiregexTables()

class ServiceManager:
    def __init__(self, srv: Service, db):
        self.srv = srv
        self.db = db
        self.status = STATUS.STOP
        self.filters: dict[int, FiregexFilter] = {}
        self.lock = asyncio.Lock()
        self.interceptor = None
    
    async def _update_filters_from_db(self):
        pyfilters = [
            PyFilter.from_dict(ele) for ele in
                self.db.query("SELECT * FROM pyfilter WHERE service_id = ? AND active=1;", self.srv.id)
        ]
        #Filter check
        old_filters = set(self.filters.keys())
        new_filters = set([f.id for f in pyfilters])
        #remove old filters
        for f in old_filters:
            if f not in new_filters:
                del self.filters[f]
        #add new filters
        for f in new_filters:
            if f not in old_filters:
                self.filters[f] = [ele for ele in pyfilters if ele.id == f][0]
        if self.interceptor:
            await self.interceptor.reload(self.filters.values())
    
    def __update_status_db(self, status):
        self.db.query("UPDATE services SET status = ? WHERE service_id = ?;", status, self.srv.id)

    async def next(self,to):
        async with self.lock:
            if (self.status, to) == (STATUS.ACTIVE, STATUS.STOP):
                await self.stop()
                self._set_status(to)
            # PAUSE -> ACTIVE
            elif (self.status, to) == (STATUS.STOP, STATUS.ACTIVE):
                await self.restart()

    def _stats_updater(self,filter:PyFilter):
        self.db.query("UPDATE pyfilter SET blocked_packets = ?, edited_packets = ? WHERE filter_id = ?;", filter.blocked_packets, filter.edited_packets, filter.id)

    def _set_status(self,status):
        self.status = status
        self.__update_status_db(status)

    async def start(self):
        if not self.interceptor:
            nft.delete(self.srv)
            self.interceptor = await FiregexInterceptor.start(self.srv, self._stats_updater)
            await self._update_filters_from_db()
            self._set_status(STATUS.ACTIVE)

    async def stop(self):
        nft.delete(self.srv)
        if self.interceptor:
            await self.interceptor.stop()
            self.interceptor = None
    
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
            await self.remove(key)

    async def remove(self,srv_id):
        async with self.lock: 
            if srv_id in self.service_table:
                await self.service_table[srv_id].next(STATUS.STOP)
                del self.service_table[srv_id]
    
    async def init(self):
        nft.init()
        await self.reload()

    async def reload(self):
        async with self.lock: 
            for srv in self.db.query('SELECT * FROM services;'):
                srv = Service.from_dict(srv)
                if srv.id in self.service_table:
                    continue
                self.service_table[srv.id] = ServiceManager(srv, self.db)
                await self.service_table[srv.id].next(srv.status)

    def get(self,srv_id) -> ServiceManager:
        if srv_id in self.service_table:
            return self.service_table[srv_id]
        else:
            raise ServiceNotFoundException()
        
class ServiceNotFoundException(Exception):
    pass


