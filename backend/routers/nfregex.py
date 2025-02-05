from base64 import b64decode
import re
import secrets
import sqlite3
from fastapi import APIRouter, Response, HTTPException
from pydantic import BaseModel
from modules.nfregex.nftables import FiregexTables
from modules.nfregex.firewall import STATUS, FirewallManager
from utils.sqlite import SQLite
from utils import ip_parse, refactor_name, socketio_emit, PortType
from utils.models import ResetRequest, StatusMessageModel

class ServiceModel(BaseModel):
    status: str
    service_id: str
    port: PortType
    name: str
    proto: str
    ip_int: str
    n_regex: int
    n_packets: int

class RenameForm(BaseModel):
    name:str

class RegexModel(BaseModel):
    regex:str
    mode:str
    id:int
    service_id:str
    n_packets:int
    is_case_sensitive:bool
    active:bool

class RegexAddForm(BaseModel):
    service_id: str
    regex: str
    mode: str
    active: bool|None = None
    is_case_sensitive: bool

class ServiceAddForm(BaseModel):
    name: str
    port: PortType
    proto: str
    ip_int: str

class ServiceAddResponse(BaseModel):
    status:str
    service_id: str|None = None

app = APIRouter()

db = SQLite('db/nft-regex.db', {
    'services': {
        'service_id': 'VARCHAR(100) PRIMARY KEY',
        'status': 'VARCHAR(100) NOT NULL',
        'port': 'INT NOT NULL CHECK(port > 0 and port < 65536)',
        'name': 'VARCHAR(100) NOT NULL UNIQUE',
        'proto': 'VARCHAR(3) NOT NULL CHECK (proto IN ("tcp", "udp"))',
        'ip_int': 'VARCHAR(100) NOT NULL',
    },
    'regexes': {
        'regex': 'TEXT NOT NULL',
        'mode': 'VARCHAR(1) NOT NULL CHECK (mode IN ("C", "S", "B"))', # C = to the client, S = to the server, B = both
        'service_id': 'VARCHAR(100) NOT NULL',
        'blocked_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
        'regex_id': 'INTEGER PRIMARY KEY',
        'is_case_sensitive' : 'BOOLEAN NOT NULL CHECK (is_case_sensitive IN (0, 1))',
        'active' : 'BOOLEAN NOT NULL CHECK (active IN (0, 1)) DEFAULT 1',
        'FOREIGN KEY (service_id)':'REFERENCES services (service_id)',
    },
    'QUERY':[
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_services ON services (port, ip_int, proto);",
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_regex_service ON regexes (regex,service_id,mode,is_case_sensitive);"   
    ]
})

async def refresh_frontend(additional:list[str]=[]):
    await socketio_emit(["nfregex"]+additional)

async def reset(params: ResetRequest):
    if not params.delete: 
        db.backup()
    await firewall.close()
    FiregexTables().reset()
    if params.delete:
        db.delete()
        db.init()
    else:
        db.restore()
    try:
        await firewall.init()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

async def startup():
    db.init()
    try:
        await firewall.init()
    except Exception as e:
        print("WARNING cannot start firewall:", e)

async def shutdown():
    db.backup()
    await firewall.close()
    db.disconnect()
    db.restore()

def gen_service_id():
    while True:
        res = secrets.token_hex(8)
        if len(db.query('SELECT 1 FROM services WHERE service_id = ?;', res)) == 0:
            break
    return res

firewall = FirewallManager(db)

@app.get('/services', response_model=list[ServiceModel])
async def get_service_list():
    """Get the list of existent firegex services"""
    return db.query("""
        SELECT
            s.service_id service_id,
            s.status status,
            s.port port,
            s.name name,
            s.proto proto,
            s.ip_int ip_int,
            COUNT(r.regex_id) n_regex,
            COALESCE(SUM(r.blocked_packets),0) n_packets
        FROM services s LEFT JOIN regexes r ON s.service_id = r.service_id
        GROUP BY s.service_id;
    """)

@app.get('/service/{service_id}', response_model=ServiceModel)
async def get_service_by_id(service_id: str):
    """Get info about a specific service using his id"""
    res = db.query("""
        SELECT 
            s.service_id service_id,
            s.status status,
            s.port port,
            s.name name,
            s.proto proto,
            s.ip_int ip_int,
            COUNT(r.regex_id) n_regex,
            COALESCE(SUM(r.blocked_packets),0) n_packets
        FROM services s LEFT JOIN regexes r ON s.service_id = r.service_id
        WHERE s.service_id = ? GROUP BY s.service_id;
    """, service_id)
    if len(res) == 0:
        raise HTTPException(status_code=400, detail="This service does not exists!")
    return res[0]

@app.get('/service/{service_id}/stop', response_model=StatusMessageModel)
async def service_stop(service_id: str):
    """Request the stop of a specific service"""
    await firewall.get(service_id).next(STATUS.STOP)
    await refresh_frontend()
    return {'status': 'ok'}

@app.get('/service/{service_id}/start', response_model=StatusMessageModel)
async def service_start(service_id: str):
    """Request the start of a specific service"""
    await firewall.get(service_id).next(STATUS.ACTIVE)
    await refresh_frontend()
    return {'status': 'ok'}

@app.get('/service/{service_id}/delete', response_model=StatusMessageModel)
async def service_delete(service_id: str):
    """Request the deletion of a specific service"""
    db.query('DELETE FROM services WHERE service_id = ?;', service_id)
    db.query('DELETE FROM regexes WHERE service_id = ?;', service_id)
    await firewall.remove(service_id)
    await refresh_frontend()
    return {'status': 'ok'}

@app.post('/service/{service_id}/rename', response_model=StatusMessageModel)
async def service_rename(service_id: str, form: RenameForm):
    """Request to change the name of a specific service"""
    form.name = refactor_name(form.name)
    if not form.name:
        raise HTTPException(status_code=400, detail="The name cannot be empty!") 
    try:
        db.query('UPDATE services SET name=? WHERE service_id = ?;', form.name, service_id)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="This name is already used")
    await refresh_frontend()
    return {'status': 'ok'}

@app.get('/service/{service_id}/regexes', response_model=list[RegexModel])
async def get_service_regexe_list(service_id: str):
    """Get the list of the regexes of a service"""
    if not db.query("SELECT 1 FROM services s WHERE s.service_id = ?;", service_id):
        raise HTTPException(status_code=400, detail="This service does not exists!")
    return db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_id,
            blocked_packets n_packets, is_case_sensitive, active
        FROM regexes WHERE service_id = ?;
    """, service_id)

@app.get('/regex/{regex_id}', response_model=RegexModel)
async def get_regex_by_id(regex_id: int):
    """Get regex info using his id"""
    res = db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_id,
            blocked_packets n_packets, is_case_sensitive, active
        FROM regexes WHERE `id` = ?;
    """, regex_id)
    if len(res) == 0:
        raise HTTPException(status_code=400, detail="This regex does not exists!")
    return res[0]

@app.get('/regex/{regex_id}/delete', response_model=StatusMessageModel)
async def regex_delete(regex_id: int):
    """Delete a regex using his id"""
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('DELETE FROM regexes WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_id"]).update_filters()
        await refresh_frontend()
    
    return {'status': 'ok'}

@app.get('/regex/{regex_id}/enable', response_model=StatusMessageModel)
async def regex_enable(regex_id: int):
    """Request the enabling of a regex"""
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('UPDATE regexes SET active=1 WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_id"]).update_filters()
        await refresh_frontend()
    return {'status': 'ok'}

@app.get('/regex/{regex_id}/disable', response_model=StatusMessageModel)
async def regex_disable(regex_id: int):
    """Request the deactivation of a regex"""
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('UPDATE regexes SET active=0 WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_id"]).update_filters()
        await refresh_frontend()
    return {'status': 'ok'}

@app.post('/regexes/add', response_model=StatusMessageModel)
async def add_new_regex(form: RegexAddForm):
    """Add a new regex"""
    try:
        re.compile(b64decode(form.regex))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid regex")
    try:
        db.query("INSERT INTO regexes (service_id, regex, mode, is_case_sensitive, active ) VALUES (?, ?, ?, ?, ?);", 
                form.service_id, form.regex, form.mode, form.is_case_sensitive, True if form.active is None else form.active )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="An identical regex already exists")

    await firewall.get(form.service_id).update_filters()
    await refresh_frontend()
    return {'status': 'ok'}

@app.post('/services/add', response_model=ServiceAddResponse)
async def add_new_service(form: ServiceAddForm):
    """Add a new service"""
    try:
        form.ip_int = ip_parse(form.ip_int)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid address")
    if form.proto not in ["tcp", "udp"]:
        raise HTTPException(status_code=400, detail="Invalid protocol")
    srv_id = None
    try:
        srv_id = gen_service_id()
        db.query("INSERT INTO services (service_id ,name, port, status, proto, ip_int) VALUES (?, ?, ?, ?, ?, ?)",
                    srv_id, refactor_name(form.name), form.port, STATUS.STOP, form.proto, form.ip_int)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="This type of service already exists")
    await firewall.reload()
    await refresh_frontend()
    return {'status': 'ok', 'service_id': srv_id}

@app.get('/metrics', response_class = Response)
async def metrics():
    """Aggregate metrics"""
    stats = db.query("""
        SELECT
            s.name,
            s.status,
            r.regex,
            r.is_blacklist,
            r.mode,
            r.is_case_sensitive,
            r.blocked_packets,
            r.active
        FROM regexes r LEFT JOIN services s ON s.service_id = r.service_id;
    """)
    metrics = []
    sanitize = lambda s : s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
    for stat in stats:
        props = f'service_name="{sanitize(stat["name"])}",regex="{sanitize(b64decode(stat["regex"]).decode())}",mode="{stat["mode"]}",is_case_sensitive="{stat["is_case_sensitive"]}"'
        metrics.append(f'firegex_blocked_packets{{{props}}} {stat["blocked_packets"]}')
        metrics.append(f'firegex_active{{{props}}} {int(stat["active"] and stat["status"] == "active")}')
    return "\n".join(metrics)
