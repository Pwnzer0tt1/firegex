import secrets
import sqlite3
from typing import List, Union
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from utils.sqlite import SQLite
from utils import ip_parse, refactor_name, refresh_frontend
from utils.models import ResetRequest, StatusMessageModel
from modules.porthijack.nftables import FiregexTables
from modules.porthijack.firewall import FirewallManager

class ServiceModel(BaseModel):
    service_id: str
    active: bool
    public_port: int
    proxy_port: int
    name: str
    proto: str
    ip_int: str

class RenameForm(BaseModel):
    name:str

class ServiceAddForm(BaseModel):
    name: str
    public_port: int
    proxy_port: int
    proto: str
    ip_int: str

class ServiceAddResponse(BaseModel):
    status:str
    service_id: Union[None,str]

class GeneralStatModel(BaseModel):
    services: int

app = APIRouter()

db = SQLite('db/port-hijacking.db', {
    'services': {
        'service_id': 'VARCHAR(100) PRIMARY KEY',
        'active' : 'BOOLEAN NOT NULL CHECK (active IN (0, 1))',
        'public_port': 'INT NOT NULL CHECK(public_port > 0 and public_port < 65536) UNIQUE',
        'proxy_port': 'INT NOT NULL CHECK(proxy_port > 0 and proxy_port < 65536 and proxy_port != public_port)',
        'name': 'VARCHAR(100) NOT NULL UNIQUE',
        'proto': 'VARCHAR(3) NOT NULL CHECK (proto IN ("tcp", "udp"))',
        'ip_int': 'VARCHAR(100) NOT NULL',
    },
    'QUERY':[
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_services ON services (public_port, ip_int, proto);",
        ""
    ]
})

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
    await firewall.init()
    

async def startup():
    db.init()
    await firewall.init()

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

@app.get('/stats', response_model=GeneralStatModel)
async def get_general_stats():
    """Get firegex general status about services"""
    return db.query("""
    SELECT
        (SELECT COUNT(*) FROM services) services
    """)[0]

@app.get('/services', response_model=List[ServiceModel])
async def get_service_list():
    """Get the list of existent firegex services"""
    return db.query("SELECT service_id, active, public_port, proxy_port, name, proto, ip_int FROM services;")

@app.get('/service/{service_id}', response_model=ServiceModel)
async def get_service_by_id(service_id: str):
    """Get info about a specific service using his id"""
    res = db.query("SELECT service_id, active, public_port, proxy_port, name, proto, ip_int FROM services WHERE service_id = ?;", service_id)
    if len(res) == 0: raise HTTPException(status_code=400, detail="This service does not exists!")
    return res[0]

@app.get('/service/{service_id}/stop', response_model=StatusMessageModel)
async def service_stop(service_id: str):
    """Request the stop of a specific service"""
    await firewall.get(service_id).disable()
    await refresh_frontend()
    return {'status': 'ok'}

@app.get('/service/{service_id}/start', response_model=StatusMessageModel)
async def service_start(service_id: str):
    """Request the start of a specific service"""
    await firewall.get(service_id).enable()
    await refresh_frontend()
    return {'status': 'ok'}

@app.get('/service/{service_id}/delete', response_model=StatusMessageModel)
async def service_delete(service_id: str):
    """Request the deletion of a specific service"""
    db.query('DELETE FROM services WHERE service_id = ?;', service_id)
    await firewall.remove(service_id)
    await refresh_frontend()
    return {'status': 'ok'}

@app.post('/service/{service_id}/rename', response_model=StatusMessageModel)
async def service_rename(service_id: str, form: RenameForm):
    """Request to change the name of a specific service"""
    form.name = refactor_name(form.name)
    if not form.name: return {'status': 'The name cannot be empty!'} 
    try:
        db.query('UPDATE services SET name=? WHERE service_id = ?;', form.name, service_id)
    except sqlite3.IntegrityError:
        return {'status': 'This name is already used'}
    await refresh_frontend()
    return {'status': 'ok'}

class ChangePortRequest(BaseModel):
    proxy_port: int

@app.post('/service/{service_id}/changeport', response_model=StatusMessageModel)
async def service_changeport(service_id: str, form: ChangePortRequest):
    """Request to change the proxy port of a specific service"""
    try:
        db.query('UPDATE services SET proxy_port=? WHERE service_id = ?;', form.proxy_port, service_id)
    except sqlite3.IntegrityError:
        return {'status': 'Invalid proxy port or service'}
    await firewall.get(service_id).change_port(form.proxy_port)
    await refresh_frontend()
    return {'status': 'ok'}

@app.post('/services/add', response_model=ServiceAddResponse)
async def add_new_service(form: ServiceAddForm):
    """Add a new service"""
    try:
        form.ip_int = ip_parse(form.ip_int)
    except ValueError:
        return {"status":"Invalid address"}
    if form.proto not in ["tcp", "udp"]:
        return {"status":"Invalid protocol"}
    srv_id = None
    try:
        srv_id = gen_service_id()
        db.query("INSERT INTO services (service_id, active, public_port, proxy_port, name, proto, ip_int) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    srv_id, False, form.public_port, form.proxy_port , form.name, form.proto, form.ip_int)
    except sqlite3.IntegrityError:
        return {'status': 'This type of service already exists'}
    await firewall.reload()
    await refresh_frontend()
    return {'status': 'ok', 'service_id': srv_id}
