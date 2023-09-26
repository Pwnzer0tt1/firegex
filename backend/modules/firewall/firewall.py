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
            if self.enabled:
                nft.set(
                    map(Rule.from_dict, self.db.query('SELECT * FROM rules WHERE active = 1 ORDER BY rule_id;')),
                    policy=self.policy,
                    allow_loopback=self.allow_loopback,
                    allow_established=self.allow_established
                )
            else:
                nft.reset()
    
    @property
    def policy(self):
        return self.db.get("POLICY", "accept")
    
    @policy.setter
    def policy(self, value):
        self.db.set("POLICY", value)
    
    @property
    def enabled(self):
        return self.db.get("ENABLED", "0") == "1"
    
    @enabled.setter
    def enabled(self, value):
        self.db.set("ENABLED", "1" if value else "0")
    
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
    

