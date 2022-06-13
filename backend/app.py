import sqlite3, random, string, subprocess, sys, threading, os, bcrypt, secrets, time
from flask import Flask, jsonify, request, abort, session
from functools import wraps
from flask_cors import CORS
from kthread import KThread


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
            with open(self.db_name + '.db', 'x') as f:
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
            self.conn.commit()

def from_name_get_id(name):
    serv_id = name.strip().replace(" ","-")
    serv_id = "".join([c for c in serv_id if c in (string.ascii_uppercase + string.ascii_lowercase + string.digits + "-")])
    return serv_id.lower()

def gen_internal_port():
    while True:
        res = random.randint(30000, 45000)
        if len(db.query('SELECT 1 FROM services WHERE internal_port = ?;', (res,))) == 0:
            break
    return res




# DB init
db = SQLite('firegex')
db.connect()


class KeyValueStorage:
    def __init__(self):
        pass

    def get(self, key):
        q = db.query('SELECT value FROM keys_values WHERE key = ?', (key,))
        if len(q) == 0:
            return None
        else:
            return q[0][0]

    def put(self, key, value):
        if self.get(key) is None:
            db.query('INSERT INTO keys_values (key, value) VALUES (?, ?);', (key,str(value)))
        else:
            db.query('UPDATE keys_values SET value=? WHERE key = ?;', (str(value), key))



app = Flask(__name__)
conf = KeyValueStorage()
proxy_table = {}

DEBUG = len(sys.argv) > 1 and sys.argv[1] == "DEBUG"

def is_loggined():
    if DEBUG: return True
    return True if session.get("loggined") else False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_loggined() or DEBUG:
            return f(*args, **kwargs)
        else:
            return abort(401)
        
    return decorated_function

def get_service_data(id):
    q = db.query('SELECT * FROM services WHERE service_id=?;',(id,))
    if len(q) == 0: return None
    srv = q[0]
    return {
        'id': srv[1],
        'status': srv[0],
        'public_port': srv[3],
        'internal_port': srv[2]
    }

def service_manager(id):
    data = get_service_data(id)
    if data is None: return



@app.before_first_request
def before_first_request():
    
    
    services = [
        
    ]

    for srv in services:




    app.config['SECRET_KEY'] = secrets.token_hex(32)
    if DEBUG:
        app.config["STATUS"] = "run"
    elif conf.get("password") is None:
        app.config["STATUS"] = "init"
    else:
        app.config["STATUS"] = "run"

@app.route("/api/status")
def get_status():
    return { 
        "status":app.config["STATUS"],
        "loggined": is_loggined()
    }

@app.route("/api/login", methods = ['POST'])
def login():
    if not conf.get("password"): return abort(404)
    req = request.get_json(force = True)
    if not "password" in req or not isinstance(req["password"],str):
        return abort(400)
    if req["password"] == "":
        return {"status":"Cannot insert an empty password!"}
    time.sleep(.3) # No bruteforce :)
    if bcrypt.checkpw(req["password"].encode(), conf.get("password").encode()):
        session["loggined"] = True
        return { "status":"ok" }
    return {"status":"Wrong password!"}

@app.route("/api/logout")
def logout():
    session["loggined"] = False
    return { "status":"ok" }

@app.route('/api/change-password', methods = ['POST'])
@login_required
def change_password():
    req = request.get_json(force = True)
    if not "password" in req or not isinstance(req["password"],str):
        return abort(400)
    if req["password"] == "":
        return {"status":"Cannot insert an empty password!"}
    if req["expire"]:
        app.config['SECRET_KEY'] = secrets.token_hex(32)
        session["loggined"] = True
    hash_psw = bcrypt.hashpw(req["password"].encode(), bcrypt.gensalt())
    conf.put("password",hash_psw.decode())
    return {"status":"ok"}


@app.route('/api/set-password', methods = ['POST'])
def set_password():
    if conf.get("password"): return abort(404)
    req = request.get_json(force = True)
    if not "password" in req or not isinstance(req["password"],str):
        return abort(400)
    if req["password"] == "":
        return {"status":"Cannot insert an empty password!"}
    
    hash_psw = bcrypt.hashpw(req["password"].encode(), bcrypt.gensalt())
    conf.put("password",hash_psw.decode())
    app.config["STATUS"] = "run"
    session["loggined"] = True
    return {"status":"ok"}

@app.route('/api/general-stats')
@login_required
def get_general_stats():
    n_services = db.query('''
        SELECT COUNT (*) FROM services;
    ''')[0][0]
    n_regexes = db.query('''
        SELECT COUNT (*) FROM regexes;
    ''')[0][0]
    n_packets = db.query('''
        SELECT SUM(blocked_packets) FROM regexes;
    ''')[0][0]

    return {
        'services': n_services,
        'regexes': n_regexes,
        'closed': n_packets if n_packets else 0
    }

@app.route('/api/services')
@login_required
def get_services():
    res = []
    for i in db.query('SELECT * FROM services;'):
        n_regex = db.query('SELECT COUNT (*) FROM regexes WHERE service_id = ?;', (i[1],))[0][0]
        n_packets = db.query('SELECT SUM(blocked_packets) FROM regexes WHERE service_id = ?;', (i[1],))[0][0]

        res.append({
            'id': i[1],
            'status': i[0],
            'public_port': i[3],
            'internal_port': i[2],
            'n_regex': n_regex,
            'n_packets': n_packets if n_packets else 0,
            'name': i[4]
        })

    return jsonify(res)


@app.route('/api/service/<serv>')
@login_required
def get_service(serv):
    q = db.query('SELECT * FROM services WHERE service_id = ?;', (serv,))
    if len(q) != 0:
        n_regex = db.query('SELECT COUNT (*) FROM regexes WHERE service_id = ?;', (serv,))[0][0]
        n_packets = db.query('SELECT SUM(blocked_packets) FROM regexes WHERE service_id = ?;', (serv,))[0][0]
        return {
            'id': q[0][1],
            'status': q[0][0],
            'public_port': q[0][3],
            'internal_port': q[0][2],
            'n_packets': n_packets if n_packets else 0,
            'n_regex': n_regex,
            'name': q[0][4]
        }
    else:
        return abort(404)

@app.route('/api/service/<serv>/stop')
@login_required
def get_service_stop(serv):
    db.query('''
        UPDATE services SET status = 'stop' WHERE service_id = ?;
    ''', (serv,))

    return {
        'status': 'ok'
    }

@app.route('/api/service/<serv>/pause')
@login_required
def get_service_pause(serv):
    db.query('''
        UPDATE services SET status = 'pause' WHERE service_id = ?;
    ''', (serv,))

    return {
        'status': 'ok'
    }

@app.route('/api/service/<serv>/start')
@login_required
def get_service_start(serv):
    db.query('''
        UPDATE services SET status = 'wait' WHERE service_id = ?;
    ''', (serv,))

    return {
        'status': 'ok'
    }

@app.route('/api/service/<serv>/delete')
@login_required
def get_service_delete(serv):
    db.query('DELETE FROM services WHERE service_id = ?;', (serv,))
    db.query('DELETE FROM regexes WHERE service_id = ?;', (serv,))

    return {
        'status': 'ok'
    }


@app.route('/api/service/<serv>/regen-port')
@login_required
def get_regen_port(serv):
    db.query('UPDATE services SET internal_port = ? WHERE service_id = ?;', (gen_internal_port(), serv))
    return {
        'status': 'ok'
    }


@app.route('/api/service/<serv>/regexes')
@login_required
def get_service_regexes(serv):
    return jsonify([
        {
            'id': row[5],
            'service_id': row[2],
            'regex': row[0],
            'is_blacklist': True if row[3] == "1" else False,
            'mode': row[1],
            'n_packets': row[4],
        } for row in db.query('SELECT * FROM regexes WHERE service_id = ?;', (serv,))
    ])


@app.route('/api/regex/<int:regex_id>')
@login_required
def get_regex_id(regex_id):
    q = db.query('SELECT * FROM regexes WHERE regex_id = ?;', (regex_id,))
    if len(q) != 0:
        return {
            'id': regex_id,
            'service_id': q[0][2],
            'regex': q[0][0],
            'is_blacklist': True if q[0][3] == "1" else False,
            'mode': q[0][1],
            'n_packets': q[0][4],
        }
    else:
        return abort(404)


@app.route('/api/regex/<int:regex_id>/delete')
@login_required
def get_regex_delete(regex_id):
    db.query('DELETE FROM regexes WHERE regex_id = ?;', (regex_id,))

    return {
        'status': 'ok'
    }


@app.route('/api/regexes/add', methods = ['POST'])
@login_required
def post_regexes_add():
    req = request.get_json(force = True)

    db.query('''
        INSERT INTO regexes (service_id, regex, is_blacklist, mode) VALUES (?, ?, ?, ?);
    ''', (req['service_id'], req['regex'], req['is_blacklist'], req['mode']))

    return {
        'status': 'ok'
    }


@app.route('/api/services/add', methods = ['POST'])
@login_required
def post_services_add():
    req = request.get_json(force = True)
    serv_id = from_name_get_id(req['name'])

    try:
        db.query('''
            INSERT INTO services (name, service_id, internal_port, public_port, status) VALUES (?, ?, ?, ?, ?)
        ''', (req['name'], serv_id, gen_internal_port(), req['port'], 'stop'))
    except sqlite3.IntegrityError:
        return {'status': 'Name or/and port of the service has been already assigned to another service'}
    
    return {'status': 'ok'}

if DEBUG:
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True )

if __name__ == '__main__':
    db.check_integrity({
        'services': {
            'status': 'VARCHAR(100)',
            'service_id': 'VARCHAR(100) PRIMARY KEY',
            'internal_port': 'INT NOT NULL UNIQUE',
            'public_port': 'INT NOT NULL UNIQUE',
            'name': 'VARCHAR(100) NOT NULL'
        },
        'regexes': {
            'regex': 'TEXT NOT NULL',
            'mode': 'VARCHAR(1)',
            'service_id': 'VARCHAR(100) NOT NULL',
            'is_blacklist': 'VARCHAR(1) NOT NULL',
            'blocked_packets': 'INTEGER NOT NULL DEFAULT 0',
            'regex_id': 'INTEGER PRIMARY KEY',
            'FOREIGN KEY (service_id)':'REFERENCES services (service_id)'
        },
        'keys_values': {
            'key': 'VARCHAR(100) PRIMARY KEY',
            'value': 'VARCHAR(100) NOT NULL',
        },
    })

    if DEBUG:
        app.run(host="0.0.0.0", port=8080 ,debug=True)
    else:
        subprocess.run(["uwsgi","--socket","./uwsgi.sock","--master","--module","app:app", "--enable-threads"])

