import json, sqlite3, os
from hashlib import md5

class SQLite():
    def __init__(self, db_name: str, schema:dict = None) -> None:
        self.conn: sqlite3.Connection|None = None
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
        return self.queries([(query, *values)])[0]

    def queries(self, queries: list[tuple[str, ...]]):
        return list(self.queries_iter(queries))

    def queries_iter(self, queries: list[tuple[str, ...]]):
        cur = self.conn.cursor()
        try:
            cur.execute("BEGIN")
            for query_data in queries:
                values = []
                str_query = None
                if isinstance(query_data, str):
                    str_query = query_data
                elif (isinstance(query_data, tuple) or isinstance(query_data, list)) and len(query_data) > 0 and isinstance(query_data[0], str):
                    str_query = query_data[0]
                    values = query_data[1:]
                if str_query:
                    cur.execute(str_query, values)
                yield cur.fetchall()
            cur.execute("COMMIT")
        except Exception as e:
            cur.execute("ROLLBACK")
            raise e
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

    def get(self, key, default = None):
        q = self.query('SELECT value FROM keys_values WHERE key = ?', key)
        if len(q) == 0:
            return default
        else:
            return q[0]["value"]

    def put(self, key, value):
        if self.get(key) is None:
            self.query('INSERT INTO keys_values (key, value) VALUES (?, ?);', key, str(value))
        else:
            self.query('UPDATE keys_values SET value=? WHERE key = ?;', str(value), key)
    
    def set(self, key, value):
        return self.put(key, value)
