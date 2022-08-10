import asyncio
from typing import Dict
from modules.nfregex.firegex import FiregexInterceptor, RegexFilter, delete_by_srv
from modules.nfregex.nftables import FiregexTables, FiregexFilter
from modules.nfregex.models import Regex, Service
from utils.sqlite import SQLite

class STATUS:
    STOP = "stop"
    ACTIVE = "active"

class FirewallManager:
    def __init__(self, db:SQLite):
        self.db = db
        self.proxy_table: Dict[str, ServiceManager] = {}
        self.lock = asyncio.Lock()

    async def close(self):
        for key in list(self.proxy_table.keys()):
            await self.remove(key)

    async def remove(self,srv_id):
        async with self.lock: 
            if srv_id in self.proxy_table:
                await self.proxy_table[srv_id].next(STATUS.STOP)
                del self.proxy_table[srv_id]
    
    async def init(self):
        FiregexTables().init()
        await self.reload()

    async def reload(self):
        async with self.lock: 
            for srv in self.db.query('SELECT * FROM services;'):
                srv = Service.from_dict(srv)
                if srv.id in self.proxy_table:
                    continue
                self.proxy_table[srv.id] = ServiceManager(srv, self.db)
                await self.proxy_table[srv.id].next(srv.status)

    def get(self,srv_id):
        if srv_id in self.proxy_table:
            return self.proxy_table[srv_id]
        else:
            raise ServiceNotFoundException()
        
class ServiceNotFoundException(Exception): pass

class ServiceManager:
    def __init__(self, srv: Service, db):
        self.srv = srv
        self.db = db
        self.status = STATUS.STOP
        self.filters: Dict[int, FiregexFilter] = {}
        self.lock = asyncio.Lock()
        self.interceptor = None
    
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
            if not f in new_filters:
                del self.filters[f]
        #add new filters
        for f in new_filters:
            if not f in old_filters:
                filter = [ele for ele in regexes if ele.id == f][0]
                self.filters[f] = RegexFilter.from_regex(filter, self._stats_updater)
        if self.interceptor: await self.interceptor.reload(self.filters.values())
    
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

    def _stats_updater(self,filter:RegexFilter):
        self.db.query("UPDATE regexes SET blocked_packets = ? WHERE regex_id = ?;", filter.blocked, filter.id)

    def _set_status(self,status):
        self.status = status
        self.__update_status_db(status)

    async def start(self):
        if not self.interceptor:
            delete_by_srv(self.srv)
            self.interceptor = await FiregexInterceptor.start(FiregexFilter(self.srv.proto,self.srv.port, self.srv.ip_int))
            await self._update_filters_from_db()
            self._set_status(STATUS.ACTIVE)

    async def stop(self):
        delete_by_srv(self.srv)
        if self.interceptor:
            await self.interceptor.stop()
            self.interceptor = None
    
    async def restart(self):
        await self.stop()
        await self.start()

    async def update_filters(self):
        async with self.lock:
            await self._update_filters_from_db()