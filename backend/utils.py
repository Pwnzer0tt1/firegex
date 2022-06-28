from proxy import Filter, Proxy
import random, string, os, threading, sqlite3, time, atexit, socket
from kthread import KThread
from base64 import b64decode

LOCALHOST_IP = socket.gethostbyname(os.getenv("LOCALHOST_IP","127.0.0.1"))

class SQLite():
    def __init__(self, db_name) -> None:
        self.conn = None
        self.cur = None
        self.db_name = db_name
        self.lock = threading.Lock()

    def connect(self) -> None:
        if not os.path.exists("db"): os.mkdir("db")
        try:
            self.conn = sqlite3.connect("db/" + self.db_name + '.db', check_same_thread = False)
        except Exception:
            with open("db/" + self.db_name + '.db', 'x'):
                pass
            self.conn = sqlite3.connect("db/" + self.db_name + '.db', check_same_thread = False)
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d
        self.conn.row_factory = dict_factory

    def disconnect(self) -> None:
        self.conn.close()

    def check_integrity(self, tables = {}) -> None:
        cur = self.conn.cursor()
        for t in tables:
            cur.execute('''
                SELECT name FROM sqlite_master WHERE type='table' AND name='{}';
            '''.format(t))

            if len(cur.fetchall()) == 0:
                cur.execute('''CREATE TABLE main.{}({});'''.format(t, ''.join([(c + ' ' + tables[t][c] + ', ') for c in tables[t]])[:-2]))
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
 
class ProxyManager:
    def __init__(self, db:SQLite):
        self.db = db
        self.proxy_table = {}
        self.lock = threading.Lock()
        atexit.register(self.clear)

    def __clean_proxy_table(self):
        with self.lock:
            for key in list(self.proxy_table.keys()):
                if not self.proxy_table[key]["thread"].is_alive():
                    del self.proxy_table[key]

    def clear(self):
        with self.lock:
            for key in list(self.proxy_table.keys()):
                if self.proxy_table[key]["thread"].is_alive():
                    self.proxy_table[key]["thread"].kill()
                del self.proxy_table[key]

    def reload(self):
        self.__clean_proxy_table()
        with self.lock: 
            for srv in self.db.query('SELECT service_id, status FROM services;'):
                srv_id, n_status = srv["service_id"], srv["status"]
                if srv_id in self.proxy_table:
                    continue
                update_signal = threading.Event()
                callback_signal = threading.Event()
                req_status = [n_status]
                thread = KThread(target=self.service_manager, args=(srv_id, req_status, update_signal, callback_signal))
                self.proxy_table[srv_id] = {
                    "thread":thread,
                    "event":update_signal,
                    "callback":callback_signal,
                    "next_status":req_status
                }
                thread.start()
                callback_signal.wait()
                callback_signal.clear()

    def get_service_data(self, id):
        res = self.db.query("""
            SELECT 
                service_id `id`,
                status,
                public_port,
                internal_port
            FROM services WHERE service_id = ?;
        """, id)
        if len(res) == 0: return None
        else: res = res[0]
        res["filters"] = self.db.query("""
            SELECT 
                regex, mode, regex_id `id`, is_blacklist,
                blocked_packets n_packets, is_case_sensitive
            FROM regexes WHERE service_id = ?;
        """, id)
        return res

    def change_status(self, id, to):
        with self.lock:
            if id in self.proxy_table:
                if self.proxy_table[id]["thread"].is_alive():
                    self.proxy_table[id]["next_status"][0] = to
                    self.proxy_table[id]["event"].set()
                    self.proxy_table[id]["callback"].wait()
                    self.proxy_table[id]["callback"].clear()
                else:
                    del self.proxy_table[id]
    
    def fire_update(self, id):
        with self.lock:
            if id in self.proxy_table:
                if self.proxy_table[id]["thread"].is_alive():
                    self.proxy_table[id]["event"].set()
                    self.proxy_table[id]["callback"].wait()
                    self.proxy_table[id]["callback"].clear()
                else:
                    del self.proxy_table[id]
    
    def __update_status_db(self, id, status):
        self.db.query("UPDATE services SET status = ? WHERE service_id = ?;", status, id)

    def __proxy_starter(self, id, proxy:Proxy, next_status):
        def func():
            while True:
                if check_port_is_open(proxy.public_port):
                    self.__update_status_db(id, next_status)
                    proxy.start(in_pause=(next_status==STATUS.PAUSE))
                    self.__update_status_db(id, STATUS.STOP)
                    return
                else:
                    time.sleep(.5)
                    
        thread = KThread(target=func)
        thread.start()
        return thread

    def service_manager(self, id, next_status, signal:threading.Event, callback):
    
        proxy = None
        thr_starter:KThread = None
        filters = {}

        while True:
            restart_required = False
            reload_required = False
            
            data = self.get_service_data(id)

            #Close thread
            if data is None:
                if proxy and proxy.isactive():
                    proxy.stop()
                callback.set()
                return
            
            if data["status"] == STATUS.STOP:
                if thr_starter and thr_starter.is_alive(): thr_starter.kill()
            
            #Filter check
            old_filters = set(filters.keys())
            new_filters = set([f["id"] for f in data["filters"]])

            #remove old filters
            for f in old_filters:
                if not f in new_filters:
                    reload_required = True
                    del filters[f]
            
            for f in new_filters:
                if not f in old_filters:
                    reload_required = True
                    filter_info = [ele for ele in data['filters'] if ele["id"] == f][0]
                    filters[f] = Filter(
                        is_case_sensitive=filter_info["is_case_sensitive"],
                        c_to_s=filter_info["mode"] in ["C","B"],
                        s_to_c=filter_info["mode"] in ["S","B"],
                        is_blacklist=filter_info["is_blacklist"],
                        regex=b64decode(filter_info["regex"]),
                        blocked_packets=filter_info["n_packets"],
                        code=f
                    )
            

            def stats_updater(filter:Filter):
                self.db.query("UPDATE regexes SET blocked_packets = ? WHERE regex_id = ?;", filter.blocked, filter.code)

            if not proxy:
                proxy = Proxy(
                    internal_port=data['internal_port'],
                    public_port=data['public_port'],
                    filters=list(filters.values()),
                    internal_host=LOCALHOST_IP,
                    callback_blocked_update=stats_updater
                )
            
            #Port checks
            if proxy.internal_port != data['internal_port'] or proxy.public_port != data['public_port']:
                proxy.internal_port = data['internal_port']
                proxy.public_port = data['public_port']
                restart_required = True
            
            #Update filters
            if reload_required:
                proxy.filters = list(filters.values())
            
            #proxy status managment
            if data["status"] != next_status[0]:
                # ACTIVE -> PAUSE or PAUSE -> ACTIVE
                if (data["status"], next_status[0]) in [(STATUS.ACTIVE, STATUS.PAUSE), (STATUS.PAUSE, STATUS.ACTIVE)]:
                    if restart_required:
                        proxy.restart(in_pause=next_status[0])
                    else:
                        if next_status[0] == STATUS.ACTIVE: proxy.reload()
                        else: proxy.pause()
                    self.__update_status_db(id, next_status[0])
                    reload_required = restart_required = False

                # ACTIVE -> STOP
                elif (data["status"],next_status[0]) in [(STATUS.ACTIVE, STATUS.STOP), (STATUS.WAIT, STATUS.STOP), (STATUS.PAUSE, STATUS.STOP)]: #Stop proxy
                    if thr_starter and thr_starter.is_alive(): thr_starter.kill()
                    proxy.stop()
                    next_status[0] = STATUS.STOP
                    self.__update_status_db(id, STATUS.STOP)
                    reload_required = restart_required = False

                # STOP -> ACTIVE or STOP -> PAUSE
                elif (data["status"], next_status[0]) in [(STATUS.STOP, STATUS.ACTIVE), (STATUS.STOP, STATUS.PAUSE)]:
                    self.__update_status_db(id, STATUS.WAIT)
                    thr_starter = self.__proxy_starter(id, proxy, next_status[0])
                    reload_required = restart_required = False
            
            if data["status"] != STATUS.STOP:
                if restart_required: proxy.restart(in_pause=(data["status"] == STATUS.PAUSE))
                elif reload_required and data["status"] != STATUS.PAUSE: proxy.reload()

            callback.set()
            signal.wait()
            signal.clear()
        

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

