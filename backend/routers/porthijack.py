import secrets
import sqlite3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.porthijack.models import Service
from utils.sqlite import SQLite
from utils import addr_parse, ip_family, refactor_name, socketio_emit, PortType
from utils.models import ResetRequest, StatusMessageModel
from modules.porthijack.nftables import FiregexTables
from modules.porthijack.firewall import FirewallManager

class ServiceModel(BaseModel):
    service_id: str
    active: bool
    public_port: PortType
    proxy_port: PortType
    name: str
    proto: str
    ip_src: str
    ip_dst: str

class RenameForm(BaseModel):
    name:str

class ServiceAddForm(BaseModel):
    name: str
    public_port: PortType
    proxy_port: PortType
    proto: str
    ip_src: str
    ip_dst: str

class ServiceAddResponse(BaseModel):
    status:str
    service_id: str|None = None

app = APIRouter()

db = SQLite('db/port-hijacking.db', {
    'services': {
        'service_id': 'VARCHAR(100) PRIMARY KEY',
        'active' : 'BOOLEAN NOT NULL CHECK (active IN (0, 1))',
        'public_port': 'INT NOT NULL CHECK(public_port > 0 and public_port < 65536)',
        'proxy_port': 'INT NOT NULL CHECK(proxy_port > 0 and proxy_port < 65536 and proxy_port != public_port)',
        'name': 'VARCHAR(100) NOT NULL UNIQUE',
        'proto': 'VARCHAR(3) NOT NULL CHECK (proto IN ("tcp", "udp"))',
        'ip_src': 'VARCHAR(100) NOT NULL',
        'ip_dst': 'VARCHAR(100) NOT NULL',
    },
    'QUERY':[
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_services ON services (public_port, ip_src, proto);"
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

async def refresh_frontend(additional:list[str]=[]):
    await socketio_emit(["porthijack"]+additional)

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
    return db.query("SELECT service_id, active, public_port, proxy_port, name, proto, ip_src, ip_dst FROM services;")

@app.get('/service/{service_id}', response_model=ServiceModel)
async def get_service_by_id(service_id: str):
    """Get info about a specific service using his id"""
    res = db.query("SELECT service_id, active, public_port, proxy_port, name, proto, ip_src, ip_dst FROM services WHERE service_id = ?;", service_id)
    if len(res) == 0:
        raise HTTPException(status_code=400, detail="This service does not exists!")
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
    if not form.name:
        raise HTTPException(status_code=400, detail="The name cannot be empty!") 
    try:
        db.query('UPDATE services SET name=? WHERE service_id = ?;', form.name, service_id)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="This name is already used")
    await refresh_frontend()
    return {'status': 'ok'}

class ChangeDestination(BaseModel):
    ip_dst: str
    proxy_port: PortType

@app.post('/service/{service_id}/change-destination', response_model=StatusMessageModel)
async def service_change_destination(service_id: str, form: ChangeDestination):
    """Request to change the proxy destination of the service"""
    
    try:
        form.ip_dst = addr_parse(form.ip_dst)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid address")
    srv = Service.from_dict(db.query('SELECT * FROM services WHERE service_id = ?;', service_id)[0])
    if ip_family(form.ip_dst) != ip_family(srv.ip_src):
        raise HTTPException(status_code=400, detail="The destination ip is not of the same family as the source ip")
    try:
        db.query('UPDATE services SET proxy_port=?, ip_dst=? WHERE service_id = ?;', form.proxy_port, form.ip_dst, service_id)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Invalid proxy port or service")
    
    srv.ip_dst = form.ip_dst
    srv.proxy_port = form.proxy_port
    await firewall.get(service_id).refresh(srv)
    
    await refresh_frontend()
    return {'status': 'ok'}

@app.post('/services/add', response_model=ServiceAddResponse)
async def add_new_service(form: ServiceAddForm):
    """Add a new service"""
    try:
        form.ip_src = addr_parse(form.ip_src)
        form.ip_dst = addr_parse(form.ip_dst)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid address")
    
    if ip_family(form.ip_dst) != ip_family(form.ip_src):
        raise HTTPException(status_code=400, detail="Destination and source addresses must be of the same family")
    if form.proto not in ["tcp", "udp"]:
        raise HTTPException(status_code=400, detail="Invalid protocol")
    
    srv_id = None
    try:
        srv_id = gen_service_id()
        db.query("INSERT INTO services (service_id, active, public_port, proxy_port, name, proto, ip_src, ip_dst) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    srv_id, False, form.public_port, form.proxy_port , form.name, form.proto, form.ip_src, form.ip_dst)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="This type of service already exists")

    await firewall.reload()
    await refresh_frontend()
    return {'status': 'ok', 'service_id': srv_id}
