import asyncio
from modules.porthijack.nftables import FiregexTables
from modules.porthijack.models import Service
from utils.sqlite import SQLite

nft = FiregexTables()

class ServiceNotFoundException(Exception): pass

class ServiceManager:
    def __init__(self, srv: Service, db):
        self.srv = srv
        self.db = db
        self.active = False
        self.lock = asyncio.Lock()

    async def enable(self):
        if not self.active:
            async with self.lock:
                nft.delete(self.srv)
                nft.add(self.srv)
                self._set_status(True)
                
    async def disable(self):
        if self.active:
            async with self.lock:
                nft.delete(self.srv)
                self._set_status(False)

    async def refresh(self, srv:Service):
        self.srv = srv
        if self.active: await self.restart()
    
    def _set_status(self,active):
        self.active = active
        self.db.query("UPDATE services SET active = ? WHERE service_id = ?;", active, self.srv.service_id)
    
    async def restart(self):
        await self.disable()
        await self.enable()

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
                await self.service_table[srv_id].disable()
                del self.service_table[srv_id]
    
    async def init(self):
        FiregexTables().init()
        await self.reload()

    async def reload(self):
        async with self.lock: 
            for srv in self.db.query('SELECT * FROM services;'):
                srv = Service.from_dict(srv)
                if srv.service_id in self.service_table:
                    continue
                self.service_table[srv.service_id] = ServiceManager(srv, self.db)
                if srv.active:
                    await self.service_table[srv.service_id].enable()

    def get(self,srv_id) -> ServiceManager:
        if srv_id in self.service_table:
            return self.service_table[srv_id]
        else:
            raise ServiceNotFoundException()
        
