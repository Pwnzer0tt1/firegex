from base64 import b64decode
import sqlite3, re
from typing import List, Union
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.regexproxy.utils import STATUS, ProxyManager, gen_internal_port, gen_service_id
from utils.sqlite import SQLite
from utils.models import ResetRequest, StatusMessageModel
from utils.firegextables import FiregexTables

app = APIRouter()
db = SQLite("regextcpproxy.db",{
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
    'QUERY':[
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_regex_service ON regexes (regex,service_id,is_blacklist,mode,is_case_sensitive);"
    ]
    })

firewall = ProxyManager(db)

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
    await firewall.reload()
    

async def startup():
    db.init()
    await firewall.reload()

async def shutdown():
    db.backup()
    await firewall.close()
    db.disconnect()
    db.restore()
    
    

class GeneralStatModel(BaseModel):
    closed:int
    regexes: int
    services: int

@app.get('/stats', response_model=GeneralStatModel)
async def get_general_stats():
    """Get firegex general status about services"""
    return db.query("""
    SELECT
        (SELECT COALESCE(SUM(blocked_packets),0) FROM regexes) closed,
        (SELECT COUNT(*) FROM regexes) regexes,
        (SELECT COUNT(*) FROM services) services
    """)[0]

class ServiceModel(BaseModel):
    id:str
    status: str
    public_port: int
    internal_port: int
    name: str
    n_regex: int
    n_packets: int

@app.get('/services', response_model=List[ServiceModel])
async def get_service_list():
    """Get the list of existent firegex services"""
    return db.query("""
        SELECT 
            s.service_id `id`,
            s.status status,
            s.public_port public_port,
            s.internal_port internal_port,
            s.name name,
            COUNT(r.regex_id) n_regex,
            COALESCE(SUM(r.blocked_packets),0) n_packets
        FROM services s LEFT JOIN regexes r ON r.service_id = s.service_id
        GROUP BY s.service_id;
    """)

@app.get('/service/{service_id}', response_model=ServiceModel)
async def get_service_by_id(service_id: str, ):
    """Get info about a specific service using his id"""
    res = db.query("""
        SELECT 
            s.service_id `id`,
            s.status status,
            s.public_port public_port,
            s.internal_port internal_port,
            s.name name,
            COUNT(r.regex_id) n_regex,
            COALESCE(SUM(r.blocked_packets),0) n_packets
        FROM services s LEFT JOIN regexes r ON r.service_id = s.service_id WHERE s.service_id = ?
        GROUP BY s.service_id;
    """, service_id)
    if len(res) == 0: raise HTTPException(status_code=400, detail="This service does not exists!")
    return res[0]

@app.get('/service/{service_id}/stop', response_model=StatusMessageModel)
async def service_stop(service_id: str, ):
    """Request the stop of a specific service"""
    await firewall.get(service_id).next(STATUS.STOP)
    return {'status': 'ok'}

@app.get('/service/{service_id}/pause', response_model=StatusMessageModel)
async def service_pause(service_id: str, ):
    """Request the pause of a specific service"""
    await firewall.get(service_id).next(STATUS.PAUSE)
    return {'status': 'ok'}

@app.get('/service/{service_id}/start', response_model=StatusMessageModel)
async def service_start(service_id: str, ):
    """Request the start of a specific service"""
    await firewall.get(service_id).next(STATUS.ACTIVE)
    return {'status': 'ok'}

@app.get('/service/{service_id}/delete', response_model=StatusMessageModel)
async def service_delete(service_id: str, ):
    """Request the deletion of a specific service"""
    db.query('DELETE FROM services WHERE service_id = ?;', service_id)
    db.query('DELETE FROM regexes WHERE service_id = ?;', service_id)
    await firewall.remove(service_id)
    return {'status': 'ok'}


@app.get('/service/{service_id}/regen-port', response_model=StatusMessageModel)
async def regen_service_port(service_id: str, ):
    """Request the regeneration of a the internal proxy port of a specific service"""
    db.query('UPDATE services SET internal_port = ? WHERE service_id = ?;', gen_internal_port(db), service_id)
    await firewall.get(service_id).update_port()
    return {'status': 'ok'}

class ChangePortForm(BaseModel):
    port: Union[int, None]
    internalPort: Union[int, None]

@app.post('/service/{service_id}/change-ports', response_model=StatusMessageModel)
async def change_service_ports(service_id: str, change_port:ChangePortForm ):
    """Choose and change the ports of the service"""
    if change_port.port is None and change_port.internalPort is None:
        return {'status': 'Invalid Request!'}
    try:
        sql_inj = ""
        query:List[Union[str,int]] = []
        if not change_port.port is None:
            sql_inj+=" public_port = ? "
            query.append(change_port.port)
        if not change_port.port is None and not change_port.internalPort is None:
            sql_inj += ","
        if not change_port.internalPort is None:
            sql_inj+=" internal_port = ? "
            query.append(change_port.internalPort)
        query.append(service_id)
        db.query(f'UPDATE services SET {sql_inj} WHERE service_id = ?;', *query)
    except sqlite3.IntegrityError:
        return {'status': 'Name or/and port of the service has been already assigned to another service'}
    await firewall.get(service_id).update_port()
    return {'status': 'ok'}

class RegexModel(BaseModel):
    regex:str
    mode:str
    id:int
    service_id:str
    is_blacklist: bool
    n_packets:int
    is_case_sensitive:bool
    active:bool

@app.get('/service/{service_id}/regexes', response_model=List[RegexModel])
async def get_service_regexe_list(service_id: str, ):
    """Get the list of the regexes of a service"""
    return db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_id, is_blacklist,
            blocked_packets n_packets, is_case_sensitive, active
        FROM regexes WHERE service_id = ?;
    """, service_id)

@app.get('/regex/{regex_id}', response_model=RegexModel)
async def get_regex_by_id(regex_id: int, ):
    """Get regex info using his id"""
    res = db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_id, is_blacklist,
            blocked_packets n_packets, is_case_sensitive, active
        FROM regexes WHERE `id` = ?;
    """, regex_id)
    if len(res) == 0: raise HTTPException(status_code=400, detail="This regex does not exists!")
    return res[0]

@app.get('/regex/{regex_id}/delete', response_model=StatusMessageModel)
async def regex_delete(regex_id: int, ):
    """Delete a regex using his id"""
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('DELETE FROM regexes WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_id"]).update_filters()
    
    return {'status': 'ok'}

@app.get('/regex/{regex_id}/enable', response_model=StatusMessageModel)
async def regex_enable(regex_id: int, ):
    """Request the enabling of a regex"""
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('UPDATE regexes SET active=1 WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_id"]).update_filters()
    return {'status': 'ok'}

@app.get('/regex/{regex_id}/disable', response_model=StatusMessageModel)
async def regex_disable(regex_id: int, ):
    """Request the deactivation of a regex"""
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('UPDATE regexes SET active=0 WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_id"]).update_filters()
    return {'status': 'ok'}

class RegexAddForm(BaseModel):
    service_id: str
    regex: str
    mode: str
    active: Union[bool,None]
    is_blacklist: bool
    is_case_sensitive: bool

@app.post('/regexes/add', response_model=StatusMessageModel)
async def add_new_regex(form: RegexAddForm, ):
    """Add a new regex"""
    try:
        re.compile(b64decode(form.regex))
    except Exception:
        return {"status":"Invalid regex"}
    try:
        db.query("INSERT INTO regexes (service_id, regex, is_blacklist, mode, is_case_sensitive, active ) VALUES (?, ?, ?, ?, ?, ?);", 
                form.service_id, form.regex, form.is_blacklist, form.mode, form.is_case_sensitive, True if form.active is None else form.active )
    except sqlite3.IntegrityError:
        return {'status': 'An identical regex already exists'}

    await firewall.get(form.service_id).update_filters()
    return {'status': 'ok'}

class ServiceAddForm(BaseModel):
    name: str
    port: int
    internalPort: Union[int, None]

class ServiceAddStatus(BaseModel):
    status:str
    id: Union[str,None]

class RenameForm(BaseModel):
    name:str

@app.post('/service/{service_id}/rename', response_model=StatusMessageModel)
async def service_rename(service_id: str, form: RenameForm, ):
    """Request to change the name of a specific service"""
    if not form.name: return {'status': 'The name cannot be empty!'} 
    db.query('UPDATE services SET name=? WHERE service_id = ?;', form.name, service_id)
    return {'status': 'ok'}

@app.post('/services/add', response_model=ServiceAddStatus)
async def add_new_service(form: ServiceAddForm, ):
    """Add a new service"""
    serv_id = gen_service_id(db)
    try:
        internal_port = form.internalPort if form.internalPort else gen_internal_port(db)
        db.query("INSERT INTO services (name, service_id, internal_port, public_port, status) VALUES (?, ?, ?, ?, ?)",
                    form.name, serv_id, internal_port, form.port, 'stop')
    except sqlite3.IntegrityError:
        return {'status': 'Name or/and ports of the service has been already assigned to another service'}
    await firewall.reload()

    return {'status': 'ok', "id": serv_id }