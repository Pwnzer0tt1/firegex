import asyncio
from modules.firewall.nftables import FiregexTables
from modules.firewall.models import Rule
from utils.sqlite import SQLite

nft = FiregexTables()

class FirewallManager:
    def __init__(self, db:SQLite):
        self.db = db
        self.lock = asyncio.Lock()

    async def close(self):
        async with self.lock:
            nft.reset()
    
    async def init(self):
        nft.init()
        await self.reload()

    async def reload(self):
        async with self.lock:
            nft.set(map(Rule.from_dict, self.db.query('SELECT * FROM rules WHERE active = 1 ORDER BY rule_id;')), policy=self.db.get('POLICY', 'accept'))

