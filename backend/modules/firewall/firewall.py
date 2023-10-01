import asyncio
from modules.firewall.nftables import FiregexTables
from modules.firewall.models import *
from utils.sqlite import SQLite
from modules.firewall.models import Action

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
                    opt=self.settings
                )
            else:
                nft.reset()
    
    @property
    def settings(self):
        return FirewallSettings(
                keep_rules=self.keep_rules,
                allow_loopback=self.allow_loopback,
                allow_established=self.allow_established,
                allow_icmp=self.allow_icmp,
                multicast_dns=self.multicast_dns,
                allow_upnp=self.allow_upnp,
                drop_invalid=self.drop_invalid
            )
    
    @settings.setter
    def settings(self, value:FirewallSettings):
        self.keep_rules = value.keep_rules
        self.allow_loopback=value.allow_loopback
        self.allow_established=value.allow_established
        self.allow_icmp=value.allow_icmp
        self.multicast_dns=value.multicast_dns
        self.allow_upnp=value.allow_upnp
        self.drop_invalid=value.drop_invalid

    @property
    def policy(self):
        return self.db.get("POLICY", Action.ACCEPT)
    
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
    def allow_icmp(self):
        return self.db.get("allow_icmp", "1") == "1"
    
    @allow_icmp.setter
    def allow_icmp(self, value):
        self.db.set("allow_icmp", "1" if value else "0")

    @property
    def allow_established(self):
        return self.db.get("allow_established", "1") == "1"
    
    @allow_established.setter
    def allow_established(self, value):
        self.db.set("allow_established", "1" if value else "0")
        
    @property
    def multicast_dns(self):
        return self.db.get("multicast_dns", "1") == "1"
    
    @multicast_dns.setter
    def multicast_dns(self, value):
        self.db.set("multicast_dns", "1" if value else "0")
    
    @property
    def allow_upnp(self):
        return self.db.get("allow_upnp", "1") == "1"
    
    @allow_upnp.setter
    def allow_upnp(self, value):
        self.db.set("allow_upnp", "1" if value else "0")
    
    @property
    def drop_invalid(self):
        return self.db.get("drop_invalid", "1") == "1"
    
    @drop_invalid.setter
    def drop_invalid(self, value):
        self.db.set("drop_invalid", "1" if value else "0")
    
