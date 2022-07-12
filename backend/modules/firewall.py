import traceback, asyncio, pcre
from typing import Dict
from modules.firegex import FiregexFilter, FiregexTables
from modules.sqlite import Regex, SQLite, Service

class STATUS:
    STOP = "stop"
    ACTIVE = "active"

class FirewallManager:
    def __init__(self, db:SQLite):
        self.db = db
        self.proxy_table: Dict[str, ServiceManager] = {}
        self.lock = asyncio.Lock()
        self.updater_task = None
    
    def init_updater(self, callback = None):
        if not self.updater_task:
            self.updater_task = asyncio.create_task(self._stats_updater(callback))
    
    def close_updater(self):
        if self.updater_task: self.updater_task.cancel()

    async def close(self):
        self.close_updater()
        if self.updater_task: self.updater_task.cancel()
        for key in list(self.proxy_table.keys()):
            await self.remove(key)

    async def remove(self,srv_id):
        async with self.lock: 
            if srv_id in self.proxy_table:
                await self.proxy_table[srv_id].next(STATUS.STOP)
                del self.proxy_table[srv_id]
    
    async def init(self, callback = None):
        self.init_updater(callback)
        await self.reload()

    async def reload(self):
        async with self.lock: 
            for srv in self.db.query('SELECT * FROM services;'):
                srv = Service.from_dict(srv)
                if srv.id in self.proxy_table:
                    continue

                self.proxy_table[srv.id] = ServiceManager(srv, self.db)
                await self.proxy_table[srv.id].next(srv.status)

    async def _stats_updater(self, callback):
        try:
            while True:
                try:
                    for key in list(self.proxy_table.keys()):
                        self.proxy_table[key].update_stats()
                except Exception:
                    traceback.print_exc()
                if callback:
                    if asyncio.iscoroutinefunction(callback): await callback()
                    else: callback()
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            self.updater_task = None
            return

    def get(self,srv_id):
        if srv_id in self.proxy_table:
            return self.proxy_table[srv_id]
        else:
            raise ServiceNotFoundException()
        
class ServiceNotFoundException(Exception): pass

class RegexFilter:
    def __init__(
        self, regex,
        is_case_sensitive=True,
        is_blacklist=True,
        input_mode=False,
        output_mode=False,
        blocked_packets=0,
        id=None
    ):
        self.regex = regex
        self.is_case_sensitive = is_case_sensitive
        self.is_blacklist = is_blacklist
        if input_mode == output_mode: input_mode = output_mode = True # (False, False) == (True, True)
        self.input_mode = input_mode
        self.output_mode = output_mode
        self.blocked = blocked_packets
        self.id = id
        self.compiled_regex = self.compile()
    
    @classmethod
    def from_regex(cls, regex:Regex):
        return cls(
            id=regex.id, regex=regex.regex, is_case_sensitive=regex.is_case_sensitive,
            is_blacklist=regex.is_blacklist, blocked_packets=regex.blocked_packets,
            input_mode = regex.mode in ["C","B"], output_mode=regex.mode in ["S","B"]
        )
    
    def compile(self):
        if isinstance(self.regex, str): self.regex = self.regex.encode()
        if not isinstance(self.regex, bytes): raise Exception("Invalid Regex Paramether")
        return pcre.compile(self.regex if self.is_case_sensitive else b"(?i)"+self.regex)

    def check(self, data):
        return True if self.compiled_regex.search(data) else False

class ServiceManager:
    def __init__(self, srv: Service, db):
        self.srv = srv
        self.db = db
        self.firegextable = FiregexTables(self.srv.ipv6)
        self.status = STATUS.STOP
        self.filters: Dict[int, FiregexFilter] = {}
        self._update_filters_from_db()
        self.lock = asyncio.Lock()
        self.interceptor = None
    
    # TODO I don't like so much this method
    def _update_filters_from_db(self):
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
                self.filters[f] = RegexFilter.from_regex(filter)
    
    def __update_status_db(self, status):
        self.db.query("UPDATE services SET status = ? WHERE service_id = ?;", status, self.srv.id)

    async def next(self,to):
        async with self.lock:
            if (self.status, to) == (STATUS.ACTIVE, STATUS.STOP):
                self.stop()
                self._set_status(to)
            # PAUSE -> ACTIVE
            elif (self.status, to) == (STATUS.STOP, STATUS.ACTIVE):
                self.restart()

    def _stats_updater(self,filter:RegexFilter):
        self.db.query("UPDATE regexes SET blocked_packets = ? WHERE regex_id = ?;", filter.blocked, filter.id)
    
    def update_stats(self):
        for ele in self.filters.values():
            self._stats_updater(ele)

    def _set_status(self,status):
        self.status = status
        self.__update_status_db(status)

    def start(self):
        if not self.interceptor:
            self.firegextable.delete_by_srv(self.srv)
            def regex_filter(pkt, by_client):
                try:
                    for filter in self.filters.values():
                        if (by_client and filter.input_mode) or (not by_client and filter.output_mode):
                            match = filter.check(pkt)
                            if (filter.is_blacklist and match) or (not filter.is_blacklist and not match):
                                filter.blocked+=1
                                return False
                except IndexError: pass
                return True
            self.interceptor = self.firegextable.add(FiregexFilter(self.srv.proto,self.srv.port, self.srv.ip_int, func=regex_filter))
            self._set_status(STATUS.ACTIVE)

    def stop(self):
        self.firegextable.delete_by_srv(self.srv)
        if self.interceptor:
            self.interceptor.stop()
            self.interceptor = None
    
    def restart(self):
        self.stop()
        self.start()

    async def update_filters(self):
        async with self.lock:
            self._update_filters_from_db()