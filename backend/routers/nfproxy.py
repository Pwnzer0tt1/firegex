import secrets
import sqlite3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.nfproxy.nftables import FiregexTables
from modules.nfproxy.firewall import STATUS, FirewallManager
from utils.sqlite import SQLite
from utils import ip_parse, refactor_name, socketio_emit, PortType
from utils.models import ResetRequest, StatusMessageModel
import os
from firegex.nfproxy.internals import get_filter_names
from fastapi.responses import PlainTextResponse

class ServiceModel(BaseModel):
    service_id: str
    status: str
    port: PortType
    name: str
    proto: str
    ip_int: str
    n_filters: int
    edited_packets: int
    blocked_packets: int
    fail_open: bool

class RenameForm(BaseModel):
    name:str

class SettingsForm(BaseModel):
    port: PortType|None = None
    proto: str|None = None
    ip_int: str|None = None
    fail_open: bool|None = None

class PyFilterModel(BaseModel):
    filter_id: int
    name: str
    blocked_packets: int
    edited_packets: int
    active: bool

class ServiceAddForm(BaseModel):
    name: str
    port: PortType
    proto: str
    ip_int: str
    fail_open: bool = True

class ServiceAddResponse(BaseModel):
    status:str
    service_id: str|None = None

class SetPyFilterForm(BaseModel):
    code: str

app = APIRouter()

db = SQLite('db/nft-pyfilters.db', {
    'services': {
        'service_id': 'VARCHAR(100) PRIMARY KEY',
        'status': 'VARCHAR(100) NOT NULL',
        'port': 'INT NOT NULL CHECK(port > 0 and port < 65536)',
        'name': 'VARCHAR(100) NOT NULL UNIQUE',
        'proto': 'VARCHAR(3) NOT NULL CHECK (proto IN ("tcp", "http"))',
        'ip_int': 'VARCHAR(100) NOT NULL',
        'fail_open': 'BOOLEAN NOT NULL CHECK (fail_open IN (0, 1)) DEFAULT 1',
    },
    'pyfilter': {
        'filter_id': 'INTEGER PRIMARY KEY',
        'name': 'VARCHAR(100) NOT NULL',
        'blocked_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
        'edited_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
        'service_id': 'VARCHAR(100) NOT NULL',
        'active' : 'BOOLEAN NOT NULL CHECK (active IN (0, 1)) DEFAULT 1',
        'FOREIGN KEY (service_id)':'REFERENCES services (service_id)',
    },
    'QUERY':[
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_services ON services (port, ip_int, proto);",
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_pyfilter_service ON pyfilter (name, service_id);"
    ]
})

async def refresh_frontend(additional:list[str]=[]):
    await socketio_emit(["nfproxy"]+additional)

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
            s.fail_open fail_open,
            COUNT(f.filter_id) n_filters,
            COALESCE(SUM(f.blocked_packets),0) blocked_packets,
            COALESCE(SUM(f.edited_packets),0) edited_packets
        FROM services s LEFT JOIN pyfilter f ON s.service_id = f.service_id
        GROUP BY s.service_id;
    """)

@app.get('/services/{service_id}', response_model=ServiceModel)
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
            s.fail_open fail_open,
            COUNT(f.filter_id) n_filters,
            COALESCE(SUM(f.blocked_packets),0) blocked_packets,
            COALESCE(SUM(f.edited_packets),0) edited_packets
        FROM services s LEFT JOIN pyfilter f ON s.service_id = f.service_id
        WHERE s.service_id = ? GROUP BY s.service_id;
    """, service_id)
    if len(res) == 0:
        raise HTTPException(status_code=400, detail="This service does not exists!")
    return res[0]

@app.post('/services/{service_id}/stop', response_model=StatusMessageModel)
async def service_stop(service_id: str):
    """Request the stop of a specific service"""
    await firewall.get(service_id).next(STATUS.STOP)
    await refresh_frontend()
    return {'status': 'ok'}

@app.post('/services/{service_id}/start', response_model=StatusMessageModel)
async def service_start(service_id: str):
    """Request the start of a specific service"""
    await firewall.get(service_id).next(STATUS.ACTIVE)
    await refresh_frontend()
    return {'status': 'ok'}

@app.delete('/services/{service_id}', response_model=StatusMessageModel)
async def service_delete(service_id: str):
    """Request the deletion of a specific service"""
    db.query('DELETE FROM services WHERE service_id = ?;', service_id)
    db.query('DELETE FROM pyfilter WHERE service_id = ?;', service_id)
    if os.path.exists(f"db/nfproxy_filters/{service_id}.py"):
        os.remove(f"db/nfproxy_filters/{service_id}.py")
    await firewall.remove(service_id)
    await refresh_frontend()
    return {'status': 'ok'}

@app.put('/services/{service_id}/rename', response_model=StatusMessageModel)
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

@app.put('/services/{service_id}/settings', response_model=StatusMessageModel)
async def service_settings(service_id: str, form: SettingsForm):
    """Request to change the settings of a specific service (will cause a restart)"""
        
    if form.proto is not None and form.proto not in ["tcp", "udp"]:
        raise HTTPException(status_code=400, detail="Invalid protocol")
    
    if form.port is not None and (form.port < 1 or form.port > 65535):
        raise HTTPException(status_code=400, detail="Invalid port")
    
    if form.ip_int is not None:
        try:
            form.ip_int = ip_parse(form.ip_int)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid address")
    
    keys = []
    values = []
    
    for key, value in form.model_dump(exclude_none=True).items():
        keys.append(key)
        values.append(value)
        
    if len(keys) == 0:
        raise HTTPException(status_code=400, detail="No settings to change provided")
    
    try:
        db.query(f'UPDATE services SET {", ".join([f"{key}=?" for key in keys])} WHERE service_id = ?;', *values, service_id)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="A service with these settings already exists")
    
    old_status = firewall.get(service_id).status
    await firewall.remove(service_id)
    await firewall.reload()
    await firewall.get(service_id).next(old_status)
    
    await refresh_frontend()
    return {'status': 'ok'}

@app.get('/services/{service_id}/pyfilters', response_model=list[PyFilterModel])
async def get_service_pyfilter_list(service_id: str):
    """Get the list of the pyfilters of a service"""
    if not db.query("SELECT 1 FROM services s WHERE s.service_id = ?;", service_id):
        raise HTTPException(status_code=400, detail="This service does not exists!")
    return db.query("""
        SELECT 
            filter_id, name, blocked_packets, edited_packets, active
        FROM pyfilter WHERE service_id = ?;
    """, service_id)

@app.get('/pyfilters/{filter_id}', response_model=PyFilterModel)
async def get_pyfilter_by_id(filter_id: int):
    """Get pyfilter info using his id"""
    res = db.query("""
        SELECT 
            filter_id, name, blocked_packets, edited_packets, active
        FROM pyfilter WHERE filter_id = ?;
    """, filter_id)
    if len(res) == 0:
        raise HTTPException(status_code=400, detail="This filter does not exists!")
    return res[0]

@app.post('/pyfilters/{filter_id}/enable', response_model=StatusMessageModel)
async def pyfilter_enable(filter_id: int):
    """Request the enabling of a pyfilter"""
    res = db.query('SELECT * FROM pyfilter WHERE filter_id = ?;', filter_id)
    if len(res) != 0:
        db.query('UPDATE pyfilter SET active=1 WHERE filter_id = ?;', filter_id)
        await firewall.get(res[0]["service_id"]).update_filters()
        await refresh_frontend()
    return {'status': 'ok'}

@app.post('/pyfilters/{filter_id}/disable', response_model=StatusMessageModel)
async def pyfilter_disable(filter_id: int):
    """Request the deactivation of a pyfilter"""
    res = db.query('SELECT * FROM pyfilter WHERE filter_id = ?;', filter_id)
    if len(res) != 0:
        db.query('UPDATE pyfilter SET active=0 WHERE filter_id = ?;', filter_id)
        await firewall.get(res[0]["service_id"]).update_filters()
        await refresh_frontend()
    return {'status': 'ok'}

@app.post('/services', response_model=ServiceAddResponse)
async def add_new_service(form: ServiceAddForm):
    """Add a new service"""
    try:
        form.ip_int = ip_parse(form.ip_int)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid address")
    if form.proto not in ["tcp", "http"]:
        raise HTTPException(status_code=400, detail="Invalid protocol")
    srv_id = None
    try:
        srv_id = gen_service_id()
        db.query("INSERT INTO services (service_id ,name, port, status, proto, ip_int, fail_open) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    srv_id, refactor_name(form.name), form.port, STATUS.STOP, form.proto, form.ip_int, form.fail_open)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="This type of service already exists")
    await firewall.reload()
    await refresh_frontend()
    return {'status': 'ok', 'service_id': srv_id}

@app.put('/services/{service_id}/pyfilters/code', response_model=StatusMessageModel)
async def set_pyfilters(service_id: str, form: SetPyFilterForm):
    """Set the python filter for a service"""
    service = db.query("SELECT service_id, proto FROM services WHERE service_id = ?;", service_id)
    if len(service) == 0:
        raise HTTPException(status_code=400, detail="This service does not exists!")
    service = service[0]
    srv_proto = service["proto"]
    try:
        found_filters = get_filter_names(form.code, srv_proto)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Remove filters that are not in the new code
    existing_filters = db.query("SELECT filter_id FROM pyfilter WHERE service_id = ?;", service_id)
    for filter in existing_filters:
        if filter["name"] not in found_filters:
            db.query("DELETE FROM pyfilter WHERE filter_id = ?;", filter["filter_id"])
    
    # Add filters that are in the new code but not in the database
    for filter in found_filters:
        if not db.query("SELECT 1 FROM pyfilter WHERE service_id = ? AND name = ?;", service_id, filter):
            db.query("INSERT INTO pyfilter (name, service_id) VALUES (?, ?);", filter, service["service_id"])
    
    # Eventually edited filters will be reloaded
    os.makedirs("db/nfproxy_filters", exist_ok=True)
    with open(f"db/nfproxy_filters/{service_id}.py", "w") as f:
        f.write(form.code)
    await firewall.get(service_id).update_filters()
    await refresh_frontend()
    return {'status': 'ok'}

@app.get('/services/{service_id}/pyfilters/code', response_class=PlainTextResponse)
async def get_pyfilters(service_id: str):
    """Get the python filter for a service"""
    if not db.query("SELECT 1 FROM services s WHERE s.service_id = ?;", service_id):
        raise HTTPException(status_code=400, detail="This service does not exists!")
    try:
        with open(f"db/nfproxy_filters/{service_id}.py") as f:
            return f.read()
    except FileNotFoundError:
        return ""

#TODO check all the APIs and add
# 1. API to change the python filter file (DONE)
# 2. a socketio mechanism to lock the previous feature