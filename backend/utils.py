import traceback
from typing import Dict
from proxy import Filter, Proxy
import os, sqlite3, socket, asyncio, re
import secrets
from base64 import b64decode

LOCALHOST_IP = socket.gethostbyname(os.getenv("LOCALHOST_IP","127.0.0.1"))

regex_ipv6 = r"^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$";
regex_ipv4 = r"^([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/([0-9]|[1-2][0-9]|3[0-2]))?$"

def checkIpv6(ip:str):
    return bool(re.match(regex_ipv6, ip))

def checkIpv4(ip:str):
    return bool(re.match(regex_ipv4, ip))

class SQLite():
    def __init__(self, db_name) -> None:
        self.conn = None
        self.cur = None
        self.db_name = db_name

    def connect(self) -> None:
        try:
            self.conn = sqlite3.connect(self.db_name, check_same_thread = False)
        except Exception:
            with open(self.db_name, 'x'):
                pass
            self.conn = sqlite3.connect(self.db_name, check_same_thread = False)
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d
        self.conn.row_factory = dict_factory

    def disconnect(self) -> None:
        self.conn.close()

    def create_schema(self, tables = {}) -> None:
        cur = self.conn.cursor()
        for t in tables:
            cur.execute('''CREATE TABLE IF NOT EXISTS main.{}({});'''.format(t, ''.join([(c + ' ' + tables[t][c] + ', ') for c in tables[t]])[:-2]))
        cur.close()
    
    def query(self, query, *values):
        cur = self.conn.cursor()
        try:
            cur.execute(query, values)
            return cur.fetchall()
        finally:
            cur.close()
            try: self.conn.commit()
            except Exception: pass
    
    def init(self):
        self.connect()
        self.create_schema({
            'services': {
                'service_id': 'VARCHAR(100) PRIMARY KEY',
                'status': 'VARCHAR(100) NOT NULL',
                'port': 'INT NOT NULL CHECK(port > 0 and port < 65536)',
                'name': 'VARCHAR(100) NOT NULL UNIQUE',
                'ipv6': 'BOOLEAN NOT NULL CHECK (ipv6 IN (0, 1)) DEFAULT 0',
            },
            'regexes': {
                'regex': 'TEXT NOT NULL',
                'mode': 'VARCHAR(1) NOT NULL',
                'service_id': 'VARCHAR(100) NOT NULL',
                'is_blacklist': 'BOOLEAN NOT NULL CHECK (is_blacklist IN (0, 1))',
                'blocked_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
                'regex_id': 'INTEGER PRIMARY KEY',
                'is_case_sensitive' : 'BOOLEAN NOT NULL CHECK (is_case_sensitive IN (0, 1))',
                'active' : 'BOOLEAN NOT NULL CHECK (active IN (0, 1)) DEFAULT 1',
                'FOREIGN KEY (service_id)':'REFERENCES services (service_id)',
            },
            'keys_values': {
                'key': 'VARCHAR(100) PRIMARY KEY',
                'value': 'VARCHAR(100) NOT NULL',
            },
        })
        self.query("CREATE UNIQUE INDEX IF NOT EXISTS unique_services ON services (ipv6,port);")
        self.query("CREATE UNIQUE INDEX IF NOT EXISTS unique_regex_service ON regexes (regex,service_id,is_blacklist,mode,is_case_sensitive);")

class KeyValueStorage:
    def __init__(self, db):
        self.db = db

    def get(self, key):
        q = self.db.query('SELECT value FROM keys_values WHERE key = ?', key)
        if len(q) == 0:
            return None
        else:
            return q[0]["value"]

    def put(self, key, value):
        if self.get(key) is None:
            self.db.query('INSERT INTO keys_values (key, value) VALUES (?, ?);', key, str(value))
        else:
            self.db.query('UPDATE keys_values SET value=? WHERE key = ?;', str(value), key)

class STATUS:
    STOP = "stop"
    ACTIVE = "active"

class ServiceNotFoundException(Exception): pass

class ServiceManager:
    def __init__(self, id, port, ipv6, db):
        self.id = id
        self.port = port
        self.db = db
        self.proxy = Proxy(port, ipv6)
        self.status = STATUS.STOP
        self.filters = {}
        self._update_filters_from_db()
        self.lock = asyncio.Lock()
        self.starter = None
        
    def _update_filters_from_db(self):
        res = self.db.query("""
            SELECT 
                regex, mode, regex_id `id`, is_blacklist,
                blocked_packets n_packets, is_case_sensitive
            FROM regexes WHERE service_id = ? AND active=1;
        """, self.id)

        #Filter check
        old_filters = set(self.filters.keys())
        new_filters = set([f["id"] for f in res])

        #remove old filters
        for f in old_filters:
            if not f in new_filters:
                del self.filters[f]
        
        for f in new_filters:
            if not f in old_filters:
                filter_info = [ele for ele in res if ele["id"] == f][0]
                self.filters[f] = Filter(
                    is_case_sensitive=filter_info["is_case_sensitive"],
                    c_to_s=filter_info["mode"] in ["C","B"],
                    s_to_c=filter_info["mode"] in ["S","B"],
                    is_blacklist=filter_info["is_blacklist"],
                    regex=b64decode(filter_info["regex"]),
                    blocked_packets=filter_info["n_packets"],
                    code=f
                )
        self.proxy.set_filters(self.filters.values())
    
    def __update_status_db(self, status):
        self.db.query("UPDATE services SET status = ? WHERE service_id = ?;", status, self.id)

    async def next(self,to):
        async with self.lock:
            return self._next(to)
    
    def _next(self, to):
        if self.status != to:
            # ACTIVE -> PAUSE
            if (self.status, to) in [(STATUS.ACTIVE, STATUS.STOP)]:
                self.proxy.stop()
                self._set_status(to)
            # PAUSE -> ACTIVE
            elif (self.status, to) in [(STATUS.STOP, STATUS.ACTIVE)]:
                self.proxy.restart()
                self._set_status(to)


    def _stats_updater(self,filter:Filter):
        self.db.query("UPDATE regexes SET blocked_packets = ? WHERE regex_id = ?;", filter.blocked, filter.code)
    
    def update_stats(self):
        for ele in self.proxy.filters:
            self._stats_updater(ele)

    def _set_status(self,status):
        self.status = status
        self.__update_status_db(status)

    async def update_filters(self):
        async with self.lock:
            self._update_filters_from_db()

class ProxyManager:
    def __init__(self, db:SQLite):
        self.db = db
        self.proxy_table: Dict[ServiceManager] = {}
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
            for srv in self.db.query('SELECT service_id, port, status, ipv6 FROM services;'):
                srv_id, srv_port, req_status, srv_ipv6 = srv["service_id"], srv["port"], srv["status"], srv["ipv6"]
                if srv_port in self.proxy_table:
                    continue

                self.proxy_table[srv_id] = ServiceManager(srv_id, srv_port, srv_ipv6, self.db)
                await self.proxy_table[srv_id].next(req_status)

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

def refactor_name(name:str):
    name = name.strip()
    while "  " in name: name = name.replace("  "," ")
    return name

def gen_service_id(db):
    while True:
        res = secrets.token_hex(8)
        if len(db.query('SELECT 1 FROM services WHERE service_id = ?;', res)) == 0:
            break
    return res