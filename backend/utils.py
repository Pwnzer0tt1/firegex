from asyncore import file_dispatcher
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
            with open("db/" + self.db_name + '.db', 'x') as f:
                pass
            self.conn = sqlite3.connect("db/" + self.db_name + '.db', check_same_thread = False)

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
    
    def query(self, query, values = ()):
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
        q = self.db.query('SELECT value FROM keys_values WHERE key = ?', (key,))
        if len(q) == 0:
            return None
        else:
            return q[0][0]

    def put(self, key, value):
        if self.get(key) is None:
            self.db.query('INSERT INTO keys_values (key, value) VALUES (?, ?);', (key,str(value)))
        else:
            self.db.query('UPDATE keys_values SET value=? WHERE key = ?;', (str(value), key))

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

    def __clear_proxy_table(self):
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
        self.__clear_proxy_table()
        with self.lock: 
            for srv_id in self.db.query('SELECT service_id, status FROM services;'):
                srv_id, n_status = srv_id
                if srv_id in self.proxy_table:
                    continue
                update_signal = threading.Event()
                req_status = [n_status]
                thread = KThread(target=self.service_manager, args=(srv_id, req_status, update_signal))
                self.proxy_table[srv_id] = {
                    "thread":thread,
                    "event":update_signal,
                    "next_status":req_status
                }
                thread.start()

    def get_service_data(self, id):
        q = self.db.query('SELECT * FROM services WHERE service_id=?;',(id,))
        if len(q) == 0: return None
        srv = q[0]
        filters = [{
            'id': row[5],
            'regex': row[0],
            'is_blacklist': True if row[3] == "1" else False,
            'is_case_sensitive' : True if row[6] == "1" else False,
            'mode': row[1],
            'n_packets': row[4],
        } for row in self.db.query('SELECT * FROM regexes WHERE service_id = ?;', (id,))]
        return {
            'id': srv[1],
            'status': srv[0],
            'public_port': srv[3],
            'internal_port': srv[2],
            'filters':filters
        }

    def change_status(self, id, to):
        with self.lock:
            if id in self.proxy_table:
                if self.proxy_table[id]["thread"].is_alive():
                    self.proxy_table[id]["next_status"][0] = to
                    self.proxy_table[id]["event"].set()
                else:
                    del self.proxy_table[id]
    
    def fire_update(self, id):
        with self.lock:
            if id in self.proxy_table:
                if self.proxy_table[id]["thread"].is_alive():
                    self.proxy_table[id]["event"].set()
                else:
                    del self.proxy_table[id]
    
    def __update_status_db(self, id, status):
        self.db.query("UPDATE services SET status = ? WHERE service_id = ?;", (status, id))

    def __proxy_starter(self, id, proxy:Proxy, next_status, saved_status):
        def stats_updater(filter:Filter):
            self.db.query("UPDATE regexes SET blocked_packets = ? WHERE regex_id = ?;", (filter.blocked, filter.code))
        def func():
            while True:
                if check_port_is_open(proxy.public_port):
                    self.__update_status_db(id, next_status)
                    if saved_status[0] == "wait": saved_status[0] = next_status
                    proxy_status = proxy.start(callback=stats_updater)
                    if proxy_status == 1:
                        self.__update_status_db(id, STATUS.STOP)
                    return
                else:
                    time.sleep(.5)
                    
        thread = KThread(target=func)
        thread.start()
        return thread

    def service_manager(self, id, next_status, signal:threading.Event):
    
        proxy = None
        thr_starter:KThread = None
        previous_status = "stop"
        filters = {}

        while True:
            data = self.get_service_data(id)

            #Close thread
            if data is None:
                if proxy and proxy.isactive():
                    proxy.stop()
                return

            restart_required = False

            #Port checks
            if proxy and (proxy.internal_port != data['internal_port'] or proxy.public_port != data['public_port']):
                restart_required = True


            #Filter check
            old_filters = set(filters.keys())
            new_filters = set([f["id"] for f in data["filters"]])

            #remove old filters
            for f in old_filters:
                if not f in new_filters:
                    restart_required = False
                    del filters[f]
            
            for f in new_filters:
                if not f in old_filters:
                    restart_required = False
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

            #proxy status managment
            if previous_status != next_status[0] or restart_required:
                if (previous_status, next_status[0]) in [(STATUS.ACTIVE, STATUS.PAUSE), (STATUS.STOP, STATUS.PAUSE), (STATUS.PAUSE, STATUS.PAUSE)]:
                    if proxy: proxy.stop()
                    proxy = Proxy(
                        internal_port=data['internal_port'],
                        public_port=data['public_port'],
                        filters=[],
                        internal_host=LOCALHOST_IP,
                    )
                    previous_status = next_status[0] = STATUS.PAUSE
                    self.__update_status_db(id, STATUS.WAIT)
                    thr_starter = self.__proxy_starter(id, proxy, STATUS.PAUSE, [previous_status])
                    restart_required = False

                # ACTIVE -> STOP
                elif (previous_status,next_status[0]) in [(STATUS.ACTIVE, STATUS.STOP), (STATUS.WAIT, STATUS.STOP), (STATUS.PAUSE, STATUS.STOP)]: #Stop proxy
                    if thr_starter and thr_starter.is_alive(): thr_starter.kill()
                    proxy.stop()
                    previous_status = next_status[0] = STATUS.STOP
                    self.__update_status_db(id, STATUS.STOP)
                    restart_required = False
                
                elif (previous_status, next_status[0]) in [(STATUS.PAUSE, STATUS.ACTIVE), (STATUS.STOP, STATUS.ACTIVE), (STATUS.ACTIVE, STATUS.ACTIVE)]:    
                    if proxy: proxy.stop()
                    proxy = Proxy(
                        internal_port=data['internal_port'],
                        public_port=data['public_port'],
                        filters=list(filters.values()),
                        internal_host=LOCALHOST_IP,
                    )
                    previous_status = next_status[0] = STATUS.ACTIVE
                    self.__update_status_db(id, STATUS.WAIT)
                    thr_starter = self.__proxy_starter(id, proxy, STATUS.ACTIVE, [previous_status])
                    restart_required = False
                else:
                    self.__update_status_db(id, previous_status)
            
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
        if len(db.query('SELECT 1 FROM services WHERE internal_port = ?;', (res,))) == 0:
            break
    return res

