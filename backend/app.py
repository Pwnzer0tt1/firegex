from base64 import b64decode
import sqlite3, subprocess, sys, threading, bcrypt, secrets, time, re
from flask import Flask, jsonify, request, abort, session
from functools import wraps
from flask_cors import CORS
from jsonschema import validate
from utils import SQLite, KeyValueStorage, gen_internal_port, ProxyManager, from_name_get_id, STATUS

# DB init
db = SQLite('firegex')
db.connect()
conf = KeyValueStorage(db)
firewall = ProxyManager(db)

try:
    import uwsgi
    IN_UWSGI = True
except ImportError:
    IN_UWSGI = False

app = Flask(__name__)

DEBUG = not ((len(sys.argv) > 1 and sys.argv[1] == "UWSGI") or IN_UWSGI)

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


@app.before_first_request
def before_first_request():
    firewall.reload()
    app.config['SECRET_KEY'] = secrets.token_hex(32)
    if DEBUG:
        app.config["STATUS"] = "run"
    elif conf.get("password") is None:
        app.config["STATUS"] = "init"
    else:
        app.config["STATUS"] = "run"

@app.route("/api/status")
def get_status():
    if DEBUG:
        return { 
            "status":app.config["STATUS"],
            "loggined": is_loggined(),
            "debug":True
        }
    else:
        return { 
            "status":app.config["STATUS"],
            "loggined": is_loggined()
        }

@app.route("/api/login", methods = ['POST'])
def login():
    if app.config["STATUS"] != "run": return abort(404)
    req = request.get_json(force = True)

    try:
        validate(
            instance=req,
            schema={
                "type" : "object",
                "properties" : {
                    "password" : {"type" : "string"}
                },
            })
    except Exception:
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
    if app.config["STATUS"] != "run": return abort(404)
    req = request.get_json(force = True)

    try:
        validate(
            instance=req,
            schema={
                "type" : "object",
                "properties" : {
                    "password" : {"type" : "string"},
                    "expire": {"type" : "boolean"},
                },
            })
    except Exception:
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
    if app.config["STATUS"] != "init": return abort(404)
    req = request.get_json(force = True)
    try:
        validate(
            instance=req,
            schema={
                "type" : "object",
                "properties" : {
                    "password" : {"type" : "string"}
                },
            })
    except Exception:
        return abort(400)

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
    n_packets = db.query("SELECT SUM(blocked_packets) FROM regexes;")[0][0]
    return {
        'services': db.query("SELECT COUNT (*) FROM services;")[0][0],
        'regexes': db.query("SELECT COUNT (*) FROM regexes;")[0][0],
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
    firewall.change_status(serv,STATUS.STOP)
    return {'status': 'ok'}

@app.route('/api/service/<serv>/pause')
@login_required
def get_service_pause(serv):
    firewall.change_status(serv,STATUS.PAUSE)
    return {'status': 'ok'}

@app.route('/api/service/<serv>/start')
@login_required
def get_service_start(serv):
    firewall.change_status(serv,STATUS.ACTIVE)
    return {'status': 'ok'}

@app.route('/api/service/<serv>/delete')
@login_required
def get_service_delete(serv):
    db.query('DELETE FROM services WHERE service_id = ?;', (serv,))
    db.query('DELETE FROM regexes WHERE service_id = ?;', (serv,))
    firewall.fire_update(serv)
    return {'status': 'ok'}


@app.route('/api/service/<serv>/regen-port')
@login_required
def get_regen_port(serv):
    db.query('UPDATE services SET internal_port = ? WHERE service_id = ?;', (gen_internal_port(db), serv))
    firewall.fire_update(serv)
    return {'status': 'ok'}


@app.route('/api/service/<serv>/regexes')
@login_required
def get_service_regexes(serv):
    return jsonify([
        {
            'id': row[5],
            'service_id': row[2],
            'regex': row[0],
            'is_blacklist': True if row[3] == "1" else False,
            'is_case_sensitive' : True if row[6] == "1" else False,
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
            'is_case_sensitive' : True if q[0][7] == "1" else False,
            'mode': q[0][1],
            'n_packets': q[0][4],
        }
    else:
        return abort(404)


@app.route('/api/regex/<int:regex_id>/delete')
@login_required
def get_regex_delete(regex_id):
    q = db.query('SELECT * FROM regexes WHERE regex_id = ?;', (regex_id,))
    
    if len(q) != 0:
        db.query('DELETE FROM regexes WHERE regex_id = ?;', (regex_id,))
        firewall.fire_update(q[0][2])
    
    return {'status': 'ok'}

@app.route('/api/regexes/add', methods = ['POST'])
@login_required
def post_regexes_add():
    req = request.get_json(force = True)
    try:
        validate(
            instance=req,
            schema={
                "type" : "object",
                "properties" : {
                    "service_id" : {"type" : "string"},
                    "regex" : {"type" : "string"},
                    "is_blacklist" : {"type" : "boolean"},
                    "mode" : {"type" : "string"},
                    "is_case_sensitive" : {"type" : "boolean"}
                },
        })
    except Exception:
        return abort(400)
    try:
        re.compile(b64decode(req["regex"]))
    except Exception:
        return {"status":"Invalid regex"}
    try:
        db.query("INSERT INTO regexes (service_id, regex, is_blacklist, mode, is_case_sensitive ) VALUES (?, ?, ?, ?, ?);", 
                (req['service_id'], req['regex'], req['is_blacklist'], req['mode'], req['is_case_sensitive']))
    except sqlite3.IntegrityError:
        return {'status': 'An identical regex already exists'}

    firewall.fire_update(req['service_id'])
    return {'status': 'ok'}


@app.route('/api/services/add', methods = ['POST'])
@login_required
def post_services_add():
    req = request.get_json(force = True)

    try:
        validate(
            instance=req,
            schema={
                "type" : "object",
                "properties" : {
                    "name" : {"type" : "string"},
                    "port" : {"type" : "number"}
                },
            })
    except Exception:
        return abort(400)

    serv_id = from_name_get_id(req['name'])

    try:
        db.query("INSERT INTO services (name, service_id, internal_port, public_port, status) VALUES (?, ?, ?, ?, ?)",
                    (req['name'], serv_id, gen_internal_port(db), req['port'], 'stop'))
        firewall.reload()
    except sqlite3.IntegrityError:
        return {'status': 'Name or/and port of the service has been already assigned to another service'}
    
    return {'status': 'ok'}

if DEBUG:
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True )

if __name__ == '__main__':
    db.check_integrity({
        'services': {
            'status': 'VARCHAR(100) NOT NULL',
            'service_id': 'VARCHAR(100) PRIMARY KEY',
            'internal_port': 'INT NOT NULL CHECK(internal_port > 0 and internal_port < 65536) UNIQUE',
            'public_port': 'INT NOT NULL CHECK(internal_port > 0 and internal_port < 65536) UNIQUE',
            'name': 'VARCHAR(100) NOT NULL'
        },
        'regexes': {
            'regex': 'TEXT NOT NULL',
            'mode': 'VARCHAR(1) NOT NULL',
            'service_id': 'VARCHAR(100) NOT NULL',
            'is_blacklist': 'VARCHAR(1) NOT NULL',
            'blocked_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
            'regex_id': 'INTEGER PRIMARY KEY',
            'is_case_sensitive' : 'VARCHAR(1) NOT NULL',
            'FOREIGN KEY (service_id)':'REFERENCES services (service_id)',
        },
        'keys_values': {
            'key': 'VARCHAR(100) PRIMARY KEY',
            'value': 'VARCHAR(100) NOT NULL',
        },
    })
    db.query("CREATE UNIQUE INDEX IF NOT EXISTS unique_regex_service ON regexes (regex,service_id,is_blacklist,mode,is_case_sensitive);")
    if DEBUG: 
        app.run(host="0.0.0.0", port=8080 ,debug=True)
    else:
        subprocess.run(["uwsgi","--socket","./uwsgi.sock","--master","--module","app:app", "--enable-threads"])
