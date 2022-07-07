import secrets
import threading
from proxy import Filter, Proxy
import random, string, os, sqlite3, socket, asyncio
from base64 import b64decode

LOCALHOST_IP = socket.gethostbyname(os.getenv("LOCALHOST_IP","127.0.0.1"))

class SQLite():
    def __init__(self, db_name) -> None:
        self.conn = None
        self.cur = None
        self.db_name = db_name
        self.lock = threading.Lock()

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
        with self.lock:
            self.conn.close()

    def create_schema(self, tables = {}) -> None:
        cur = self.conn.cursor()
        for t in tables:
            cur.execute('''CREATE TABLE IF NOT EXISTS main.{}({});'''.format(t, ''.join([(c + ' ' + tables[t][c] + ', ') for c in tables[t]])[:-2]))
        cur.close()
    
    def query(self, query, *values):
        cur = self.conn.cursor()
        try:
            with self.lock:
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
                'service_id': 'VARCHAR(100) PRIMARY KEY',
                'internal_port': 'INT NOT NULL CHECK(internal_port > 0 and internal_port < 65536)',
                'public_port': 'INT NOT NULL CHECK(internal_port > 0 and internal_port < 65536) UNIQUE',
                'name': 'VARCHAR(100) NOT NULL'
            },
            'regexes': {
                'regex': 'TEXT NOT NULL',
                'mode': 'VARCHAR(1) NOT NULL',
                'service_id': 'VARCHAR(100) NOT NULL',
                'is_blacklist': 'BOOLEAN NOT NULL CHECK (is_blacklist IN (0, 1))',
                'blocked_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
                'regex_id': 'INTEGER PRIMARY KEY',
                'is_case_sensitive' : 'BOOLEAN NOT NULL CHECK (is_case_sensitive IN (0, 1))',
                'active' : 'BOOLEAN NOT NULL CHECK (is_case_sensitive IN (0, 1)) DEFAULT 1',
                'FOREIGN KEY (service_id)':'REFERENCES services (service_id)',
            },
            'keys_values': {
                'key': 'VARCHAR(100) PRIMARY KEY',
                'value': 'VARCHAR(100) NOT NULL',
            },
        })
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
    PAUSE = "pause"
    ACTIVE = "active"

class ServiceNotFoundException(Exception): pass

class ServiceManager:
    def __init__(self, id, db):
        self.id = id
        self.db = db
        self.proxy = Proxy(
            callback_blocked_update=self._stats_updater
        )
        self.status = STATUS.PAUSE
        self.filters = {}
        self._update_port_from_db()
        self._update_filters_from_db()
        self.lock = asyncio.Lock()
        self.starter = None
    
    def _update_port_from_db(self):
        res = self.db.query("""
            SELECT 
                public_port,
                internal_port
            FROM services WHERE service_id = ?;
        """, self.id)
        if len(res) == 0: raise ServiceNotFoundException()
        self.proxy.public_port = res[0]["public_port"]
        
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
        self.proxy.filters = list(self.filters.values())
    
    def __update_status_db(self, status):
        self.db.query("UPDATE services SET status = ? WHERE service_id = ?;", status, self.id)

    async def next(self,to):
        async with self.lock:
            return await self._next(to)
    
    async def _next(self, to):
        if self.status != to:
            # ACTIVE -> PAUSE
            if (self.status, to) in [(STATUS.ACTIVE, STATUS.PAUSE)]:
                await self.proxy.pause()
                self._set_status(to)
            # PAUSE -> ACTIVE
            elif (self.status, to) in [(STATUS.PAUSE, STATUS.ACTIVE)]:
                await self.proxy.reload()
                self._set_status(to)


    def _stats_updater(self,filter:Filter):
        self.db.query("UPDATE regexes SET blocked_packets = ? WHERE regex_id = ?;", filter.blocked, filter.code)

    async def update_port(self):
        async with self.lock:
            self._update_port_from_db()
            if self.status in [STATUS.ACTIVE]:
                await self.proxy.reload()

    def _set_status(self,status):
        self.status = status
        self.__update_status_db(status)


    async def update_filters(self):
        async with self.lock:
            self._update_filters_from_db()
            if self.status in [STATUS.PAUSE, STATUS.ACTIVE]:
                await self.proxy.reload()

class ProxyManager:
    def __init__(self, db:SQLite):
        self.db = db
        self.proxy_table = {}
        self.lock = asyncio.Lock()

    async def close(self):
        for key in list(self.proxy_table.keys()):
            await self.remove(key)

    async def remove(self,id):
        async with self.lock: 
            if id in self.proxy_table:
                await self.proxy_table[id].next(STATUS.PAUSE)
                del self.proxy_table[id]
    
    async def reload(self):
        async with self.lock: 
            for srv in self.db.query('SELECT service_id, status FROM services;'):
                srv_id, req_status = srv["service_id"], srv["status"]
                if srv_id in self.proxy_table:
                    continue

                self.proxy_table[srv_id] = ServiceManager(srv_id,self.db)
                await self.proxy_table[srv_id].next(req_status)

    def get(self,id):
        if id in self.proxy_table:
            return self.proxy_table[id]
        else:
            raise ServiceNotFoundException()

def check_port_is_open(port):
    try:
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0',port))
        sock.close()
        return True
    except Exception:
        return False

def gen_service_id(db):
    while True:
        res = secrets.token_hex(8)
        if len(db.query('SELECT 1 FROM services WHERE service_id = ?;', res)) == 0:
            break
    return res

def gen_internal_port(db):
    while True:
        res = random.randint(30000, 45000)
        if len(db.query('SELECT 1 FROM services WHERE internal_port = ?;', res)) == 0:
            break
    return res