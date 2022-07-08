import traceback
from typing import Dict
from proxy import Filter, Proxy
import os, sqlite3, socket, asyncio
from base64 import b64decode

LOCALHOST_IP = socket.gethostbyname(os.getenv("LOCALHOST_IP","127.0.0.1"))

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
                'status': 'VARCHAR(100) NOT NULL',
                'port': 'INT NOT NULL CHECK(port > 0 and port < 65536) UNIQUE PRIMARY KEY',
                'name': 'VARCHAR(100) NOT NULL'
            },
            'regexes': {
                'regex': 'TEXT NOT NULL',
                'mode': 'VARCHAR(1) NOT NULL',
                'service_port': 'INT NOT NULL',
                'is_blacklist': 'BOOLEAN NOT NULL CHECK (is_blacklist IN (0, 1))',
                'blocked_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
                'regex_id': 'INTEGER PRIMARY KEY',
                'is_case_sensitive' : 'BOOLEAN NOT NULL CHECK (is_case_sensitive IN (0, 1))',
                'active' : 'BOOLEAN NOT NULL CHECK (is_case_sensitive IN (0, 1)) DEFAULT 1',
                'FOREIGN KEY (service_port)':'REFERENCES services (port)',
            },
            'keys_values': {
                'key': 'VARCHAR(100) PRIMARY KEY',
                'value': 'VARCHAR(100) NOT NULL',
            },
        })
        self.query("CREATE UNIQUE INDEX IF NOT EXISTS unique_regex_service ON regexes (regex,service_port,is_blacklist,mode,is_case_sensitive);")

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
    def __init__(self, port, db):
        self.port = port
        self.db = db
        self.proxy = Proxy(port)
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
            FROM regexes WHERE service_port = ? AND active=1;
        """, self.port)

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
        self.db.query("UPDATE services SET status = ? WHERE port = ?;", status, self.port)

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
    
    def init_updater(self):
        if not self.updater_task:
            self.updater_task = asyncio.create_task(self._stats_updater())
    
    def close_updater(self):
        if self.updater_task: self.updater_task.cancel()

    async def close(self):
        self.close_updater()
        if self.updater_task: self.updater_task.cancel()
        for key in list(self.proxy_table.keys()):
            await self.remove(key)

    async def remove(self,port):
        async with self.lock: 
            if port in self.proxy_table:
                await self.proxy_table[port].next(STATUS.STOP)
                del self.proxy_table[port]
    
    async def init(self):
        await self.reload()

    async def reload(self):
        self.init_updater()
        async with self.lock: 
            for srv in self.db.query('SELECT port, status FROM services;'):
                srv_port, req_status = srv["port"], srv["status"]
                if srv_port in self.proxy_table:
                    continue

                self.proxy_table[srv_port] = ServiceManager(srv_port,self.db)
                await self.proxy_table[srv_port].next(req_status)

    async def _stats_updater(self):
        try:
            while True:
                try:
                    for key in list(self.proxy_table.keys()):
                        self.proxy_table[key].update_stats()
                except Exception:
                    traceback.print_exc()
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            self.updater_task = None
            return



    def get(self,port):
        if port in self.proxy_table:
            return self.proxy_table[port]
        else:
            raise ServiceNotFoundException()