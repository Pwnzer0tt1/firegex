from typing import Union
import json, sqlite3, os
from hashlib import md5
import base64

class SQLite():
    def __init__(self, db_name: str, schema:dict = None) -> None:
        self.conn: Union[None, sqlite3.Connection] = None
        self.cur = None
        self.db_name = db_name
        self.__backup = None
        self.schema = {} if schema is None else schema
        self.DB_VER = md5(json.dumps(self.schema).encode()).hexdigest()

    def connect(self) -> None:
        try:
            self.conn = sqlite3.connect(self.db_name, check_same_thread = False)
        except Exception:
            path_name = os.path.dirname(self.db_name)
            if not os.path.exists(path_name): os.makedirs(path_name)
            with open(self.db_name, 'x'): pass
            self.conn = sqlite3.connect(self.db_name, check_same_thread = False)
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d
        self.conn.row_factory = dict_factory

    def backup(self):
        with open(self.db_name, "rb") as f:
            self.__backup = f.read()
    
    def restore(self):
        were_active = True if self.conn else False
        self.disconnect()
        if self.__backup:
            with open(self.db_name, "wb") as f:
                f.write(self.__backup)
            self.__backup = None
        if were_active: self.connect()
            
    def delete_backup(self):
        self.__backup = None
    
    def disconnect(self) -> None:
        if self.conn: self.conn.close()
        self.conn = None

    def create_schema(self, tables = {}) -> None:
        if self.conn:
            cur = self.conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS main.keys_values(key VARCHAR(100) PRIMARY KEY, value VARCHAR(100) NOT NULL);")
            for t in tables:
                if t == "QUERY": continue
                cur.execute('CREATE TABLE IF NOT EXISTS main.{}({});'.format(t, ''.join([(c + ' ' + tables[t][c] + ', ') for c in tables[t]])[:-2]))
            if "QUERY" in tables: [cur.execute(qry) for qry in tables["QUERY"]]
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
    
    def delete(self):
        self.disconnect()
        os.remove(self.db_name)
    
    def init(self):
        self.connect()
        try:
            if self.get('DB_VERSION') != self.DB_VER: raise Exception("DB_VERSION is not correct")
        except Exception:
            self.delete()
            self.connect()
            self.create_schema(self.schema)
            self.put('DB_VERSION', self.DB_VER)

    def get(self, key):
        q = self.query('SELECT value FROM keys_values WHERE key = ?', key)
        if len(q) == 0:
            return None
        else:
            return q[0]["value"]

    def put(self, key, value):
        if self.get(key) is None:
            self.query('INSERT INTO keys_values (key, value) VALUES (?, ?);', key, str(value))
        else:
            self.query('UPDATE keys_values SET value=? WHERE key = ?;', str(value), key)


class Service:
    def __init__(self, id: str, status: str, port: int, name: str, proto: str, ip_int: str):
        self.id = id
        self.status = status
        self.port = port
        self.name = name
        self.proto = proto
        self.ip_int = ip_int
    
    @classmethod
    def from_dict(cls, var: dict):
        return cls(id=var["service_id"], status=var["status"], port=var["port"], name=var["name"], proto=var["proto"], ip_int=var["ip_int"])


class Regex:
    def __init__(self, id: int, regex: bytes, mode: str, service_id: str, is_blacklist: bool, blocked_packets: int, is_case_sensitive: bool, active: bool):
        self.regex = regex
        self.mode = mode
        self.service_id = service_id
        self.is_blacklist = is_blacklist
        self.blocked_packets = blocked_packets
        self.id = id
        self.is_case_sensitive = is_case_sensitive
        self.active = active
        
    @classmethod
    def from_dict(cls, var: dict):
        return cls(id=var["regex_id"], regex=base64.b64decode(var["regex"]), mode=var["mode"], service_id=var["service_id"], is_blacklist=var["is_blacklist"], blocked_packets=var["blocked_packets"], is_case_sensitive=var["is_case_sensitive"], active=var["active"])