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
    WAIT = "wait"
    STOP = "stop"
    PAUSE = "pause"
    ACTIVE = "active"

class ServiceNotFoundException(Exception):
    pass

class ServiceManager:
    def __init__(self, id, db):
        self.id = id
        self.db = db
        self.proxy = Proxy(
            internal_host=LOCALHOST_IP,
            callback_blocked_update=self._stats_updater
        )
        self.status = STATUS.STOP
        self.filters = {}
        self._proxy_update()
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
        self.proxy.internal_port = res[0]["internal_port"]
        self.proxy.public_port = res[0]["public_port"]

    def _proxy_update(self):
        self._update_port_from_db()
        self._update_filters_from_db()

    def _update_filters_from_db(self):
        res = self.db.query("""
            SELECT 
                regex, mode, regex_id `id`, is_blacklist,
                blocked_packets n_packets, is_case_sensitive
            FROM regexes WHERE service_id = ?;
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
    
    def __update_status_db(self, id, status):
        self.db.query("UPDATE services SET status = ? WHERE service_id = ?;", status, id)

    async def next(self,to):
        async with self.lock: 
            if self.status != to:
                # ACTIVE -> PAUSE or PAUSE -> ACTIVE
                if (self.status, to) in [(STATUS.ACTIVE, STATUS.PAUSE)]:
                    await self.proxy.pause()
                    self._set_status(to)

                elif (self.status, to) in [(STATUS.PAUSE, STATUS.ACTIVE)]:
                    await self.proxy.reload()
                    self._set_status(to)

                # ACTIVE -> STOP
                elif (self.status,to) in [(STATUS.ACTIVE, STATUS.STOP), (STATUS.WAIT, STATUS.STOP), (STATUS.PAUSE, STATUS.STOP)]: #Stop proxy
                    if self.starter: self.starter.cancel()
                    await self.proxy.stop()
                    self._set_status(to)

                # STOP -> ACTIVE or STOP -> PAUSE
                elif (self.status, to) in [(STATUS.STOP, STATUS.ACTIVE), (STATUS.STOP, STATUS.PAUSE)]:
                    self._set_status(STATUS.WAIT)
                    self.__proxy_starter(to)


    def _stats_updater(self,filter:Filter):
        self.db.query("UPDATE regexes SET blocked_packets = ? WHERE regex_id = ?;", filter.blocked, filter.code)

    async def update_port(self):
        async with self.lock:
            self._update_port_from_db()
            if self.status in [STATUS.PAUSE, STATUS.ACTIVE]:
                await self.proxy.restart(in_pause=(self.status == STATUS.PAUSE))

    def _set_status(self,status):
        self.status = status
        self.__update_status_db(self.id,status)


    async def update_filters(self):
        async with self.lock:
            self._update_filters_from_db()
            if self.status in [STATUS.PAUSE, STATUS.ACTIVE]:
                await self.proxy.reload()
    
    def __proxy_starter(self,to):
        async def func():
            while True:
                if check_port_is_open(self.proxy.public_port):
                    self._set_status(to)
                    await self.proxy.start(in_pause=(to==STATUS.PAUSE))
                    self._set_status(STATUS.STOP)
                    return
                else:
                    await asyncio.sleep(.5)
        self.starter = asyncio.create_task(func())

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
                await self.proxy_table[id].proxy.stop()
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
        return self.proxy_table[id]

def check_port_is_open(port):
    try:
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0',port))
        sock.close()
        return True
    except Exception:
        return False

def from_name_get_id(name):
    serv_id = name.strip().replace(" ","-")
    serv_id = "".join([c for c in serv_id if c in (string.ascii_uppercase + string.ascii_lowercase + string.digits + "-")])
    return serv_id.lower()

def gen_internal_port(db):
    while True:
        res = random.randint(30000, 45000)
        if len(db.query('SELECT 1 FROM services WHERE internal_port = ?;', res)) == 0:
            break
    return res