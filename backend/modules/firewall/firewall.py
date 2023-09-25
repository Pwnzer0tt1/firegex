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
            if self.db.get("ENABLED", "0") == "1":
                additional_rules = []
                if self.allow_loopback:
                    pass #TODO complete rule
                if self.allow_established:
                    pass #TODO complete rule
                rules = list(map(Rule.from_dict, self.db.query('SELECT * FROM rules WHERE active = 1 ORDER BY rule_id;')), policy=self.db.get('POLICY', 'accept'))
                nft.set(additional_rules + rules)
            else:
                nft.reset()
    
    @property
    def keep_rules(self):
        return self.db.get("keep_rules", "0") == "1"
    
    @keep_rules.setter
    def keep_rules(self, value):
        self.db.set("keep_rules", "1" if value else "0")

    @property
    def allow_loopback(self):
        return self.db.get("allow_loopback", "1") == "1"
    
    @allow_loopback.setter
    def allow_loopback(self, value):
        self.db.set("allow_loopback", "1" if value else "0")

    @property
    def allow_established(self):
        return self.db.get("allow_established", "1") == "1"
    
    @allow_established.setter
    def allow_established(self, value):
        self.db.set("allow_established", "1" if value else "0")
    

