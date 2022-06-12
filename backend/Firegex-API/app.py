import sqlite3
from flask import Flask, jsonify, request
import random
from markupsafe import escape


class SQLite():
    def __init__(self, db_name) -> None:
        self.conn = None
        self.cur = None
        self.db_name = db_name

    def connect(self) -> None:
        try:
            self.conn = sqlite3.connect(self.db_name + '.db', check_same_thread = False)
        except:
            with open(self.db_name + '.db', 'x') as f:
                pass

            self.conn = sqlite3.connect(self.db_name + '.db', check_same_thread = False)

        self.cur = self.conn.cursor()

    def disconnect(self) -> None:
        self.conn.close()

    def check_integrity(self, tables = {}) -> None:
        for t in tables:
            self.cur.execute('''
                SELECT name FROM sqlite_master WHERE type='table' AND name='{}';
            '''.format(t))

            if len(self.cur.fetchall()) == 0:
                self.cur.execute('''CREATE TABLE main.{}({});'''.format(t, ''.join([(c + ' ' + tables[t][c] + ', ') for c in tables[t]])[:-2]))

    def query(self, query, values = ()):
        self.cur.execute(query, values)
        return self.cur.fetchall()

# DB init
db = SQLite('firegex')
db.connect()
db.check_integrity({
    'regexes': {
        'regex': 'TEXT NOT NULL',
        'mode': 'CHAR(1)',
        'service_id': 'TEXT NOT NULL',
        'is_blacklist': 'CHAR(50) NOT NULL',
        'blocked_packets': 'INTEGER DEFAULT 0',
        'regex_id': 'INTEGER NOT NULL'
    },
    'services': {
        'status': 'CHAR(50)',
        'service_id': 'TEXT NOT NULL',
        'internal_port': 'INT NOT NULL',
        'public_port': 'INT NOT NULL'
    }
})


app = Flask(__name__)

@app.route('/api/general-stats')
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

    res = {
        'services': n_services,
        'regexes': n_regexes,
        'closed': n_packets if n_packets else 0
    }

    return res


@app.route('/api/services')
def get_services():
    res = []
    for i in db.query('''SELECT * FROM services;'''):
        n_regex = db.query('''SELECT COUNT (*) FROM regexes WHERE service_id = '{}';'''.format(i[1]))[0][0]
        n_pacchetti = db.query('''SELECT SUM(blocked_packets) FROM regexes WHERE service_id = '{}';'''.format(i[1]))[0][0]

        res.append({
            'id': i[1],
            'status': i[0],
            'public_port': i[3],
            'internal_port': i[2],
            'n_regex': n_regex,
            'n_pacchetti': n_pacchetti if n_pacchetti else 0
        })

    return jsonify(res)


@app.route('/api/service/<serv>')
def get_service(serv):
    q = db.query('''
        SELECT * FROM services WHERE service_id = '{}';
    '''.format(escape(serv)))

    res = {}
    if len(q) != 0:
        n_regex = db.query('''SELECT COUNT (*) FROM regexes WHERE service_id = '{}';'''.format(escape(serv)))[0][0]
        n_pacchetti = db.query('''SELECT SUM(blocked_packets) FROM regexes WHERE service_id = '{}';'''.format(escape(serv)))[0][0]

        res = {
            'id': q[0][1],
            'status': q[0][0],
            'public_port': q[0][3],
            'internal_port': q[0][2],
            'n_packets': n_pacchetti if n_pacchetti else 0,
            'n_regex': n_regex
        }

    return res


@app.route('/api/service/<serv>/stop')
def get_service_stop(serv):
    db.query('''
        UPDATE services SET status = 'stop' WHERE service_id = '{}';
    '''.format(escape(serv)))

    res = {
        'status': 'ok'
    }

    return res


@app.route('/api/service/<serv>/start')
def get_service_start(serv):
    db.query('''
        UPDATE services SET status = 'active' WHERE service_id = '{}';
    '''.format(escape(serv)))

    res = {
        'status': 'ok'
    }

    return res


@app.route('/api/service/<serv>/delete')
def get_service_delete(serv):
    db.query('''
        DELETE FROM services WHERE service_id = '{}';
    '''.format(escape(serv)))

    res = {
        'status': 'ok'
    }

    return res


@app.route('/api/service/<serv>/terminate')
def get_service_termite(serv):
    db.query('''
        UPDATE services SET status = 'stop' WHERE service_id = '{}';
    '''.format(escape(serv)))

    res = {
        'status': 'ok'
    }

    return res


@app.route('/api/service/<serv>/regen-port')
def get_regen_port(serv):
    db.query('''
        UPDATE services SET public_port = {} WHERE service_id = '{}';
    '''.format(random.randint(30000, 45000), escape(serv)))

    res = {
        'status': 'ok'
    }

    return res


@app.route('/api/service/<serv>/regexes')
def get_service_regexes(serv):
    res = []
    for i in db.query('''SELECT * FROM regexes WHERE service_id = '{}';'''.format(escape(serv))):
        res.append({
            'id': i[5],
            'service_id': i[2],
            'regex': i[0],
            'is_blacklist': i[3],
            'mode': i[1]
        })

    return jsonify(res)


@app.route('/api/regex/<int:regex_id>')
def get_regex_id(regex_id):
    q = db.query('''
        SELECT * FROM regexes WHERE regex_id = {};
    '''.format(regex_id))

    res = {}
    if len(q) != 0:
        res = {
            'id': regex_id,
            'service_id': q[0][2],
            'regex': q[0][0],
            'is_blacklist': q[0][3],
            'mode': q[0][1]
        }

    return res


@app.route('/api/regex/<int:regex_id>/delete')
def get_regex_delete(regex_id):
    db.query('''
        DELETE FROM regexes WHERE regex_id = {};
    '''.format(regex_id))

    res = {
        'status': 'ok'
    }

    return res


@app.route('/api/regexes/add', methods = ['POST'])
def post_regexes_add():
    req = request.get_json(force = True)

    db.query('''
        INSERT INTO regexes (regex_id, service_id, regex, is_blacklist, mode) VALUES ({}, '{}', '{}', '{}', '{}');
    '''.format(random.randint(1, 1 << 32), req['service_id'], req['regex'], req['is_blacklist'], req['mode']))

    res = {
        'status': 'ok'
    }

    return res


@app.route('/api/services/add', methods = ['POST'])
def post_services_add():
    req = request.get_json(force = True)

    db.query('''
        INSERT INTO services (service_id, internal_port, public_port, status) VALUES ('{}', {}, {}, '{}')
    '''.format(req['name'], req['port'], random.randint(30000, 45000), 'stopped'))

    res = {
        'status': 'ok'
    }

    return res