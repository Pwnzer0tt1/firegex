import secrets
import sqlite3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.nfproxy.nftables import FiregexTables
from modules.nfproxy.firewall import STATUS, FirewallManager, ServiceNotFoundException
from utils.sqlite import SQLite
from utils import ip_parse, refactor_name, socketio_emit, PortType
from modules.tls.service import activate_stream
from utils.models import ResetRequest, StatusMessageModel
import os
from firegex.nfproxy.internals import get_filter_names
from fastapi.responses import PlainTextResponse
from modules.nfproxy.nftables import convert_protocol_to_l4
import asyncio
import traceback
from utils import DEBUG
import utils

class ServiceModel(BaseModel):
    service_id: str
    status: str
    port: PortType|None = None
    name: str
    proto: str
    ip_int: str|None = None
    n_filters: int
    edited_packets: int
    blocked_packets: int
    fail_open: bool
    target_type: str
    tls_stream_id: str|None = None

class RenameForm(BaseModel):
    name:str

class SettingsForm(BaseModel):
    port: PortType|None = None
    proto: str|None = None
    ip_int: str|None = None
    fail_open: bool|None = None
    target_type: str|None = None
    tls_stream_id: str|None = None

class PyFilterModel(BaseModel):
    name: str
    service_id: str
    blocked_packets: int
    edited_packets: int
    active: bool

class ServiceAddForm(BaseModel):
    name: str
    port: PortType|None = None
    proto: str
    ip_int: str|None = None
    fail_open: bool = True
    target_type: str = "flow"
    tls_stream_id: str|None = None

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
        'target_type': 'VARCHAR(10) NOT NULL CHECK(target_type IN ("flow", "tls")) DEFAULT "flow"',
        'tls_stream_id': 'VARCHAR(100)',
        'port': 'INT CHECK(port > 0 and port < 65536)',
        'name': 'VARCHAR(100) NOT NULL UNIQUE',
        'proto': 'VARCHAR(3) NOT NULL CHECK (proto IN ("tcp", "http"))',
        'l4_proto': 'VARCHAR(3) NOT NULL CHECK (l4_proto IN ("tcp", "udp"))',
        'ip_int': 'VARCHAR(100)',
        'fail_open': 'BOOLEAN NOT NULL CHECK (fail_open IN (0, 1)) DEFAULT 1',
    },
    'pyfilter': {
        'name': 'VARCHAR(100) NOT NULL',
        'service_id': 'VARCHAR(100) NOT NULL',
        'blocked_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
        'edited_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
        'active' : 'BOOLEAN NOT NULL CHECK (active IN (0, 1)) DEFAULT 1',
        'FOREIGN KEY (service_id)':'REFERENCES services (service_id)',
        'PRIMARY KEY': '(name, service_id)'
    },
    'QUERY':[
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_services ON services (port, ip_int, l4_proto);",
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
    utils.socketio.on("nfproxy-outstream-join", join_outstream)
    utils.socketio.on("nfproxy-outstream-leave", leave_outstream)
    utils.socketio.on("nfproxy-exception-join", join_exception)
    utils.socketio.on("nfproxy-exception-leave", leave_exception)

async def shutdown():
    await firewall.close()
    db.disconnect()

def gen_service_id():
    while True:
        res = secrets.token_hex(8)
        if len(db.query('SELECT 1 FROM services WHERE service_id = ?;', res)) == 0:
            break
    return res

async def outstream_func(service_id, data):
    await utils.socketio.emit(f"nfproxy-outstream-{service_id}", data, room=f"nfproxy-outstream-{service_id}")
    
async def exception_func(service_id, timestamp):
    await utils.socketio.emit(f"nfproxy-exception-{service_id}", timestamp, room=f"nfproxy-exception-{service_id}")

firewall = FirewallManager(db, outstream_func=outstream_func, exception_func=exception_func)

@app.get('/services', response_model=list[ServiceModel])
async def get_service_list():
    """Get the list of existent firegex services"""
    res = db.query("""
        SELECT
            s.service_id service_id,
            s.status status,
            s.port port,
            s.name name,
            s.proto proto,
            s.ip_int ip_int,
            s.fail_open fail_open,
            s.target_type target_type,
            s.tls_stream_id tls_stream_id,
            COUNT(f.name) n_filters,
            COALESCE(SUM(f.blocked_packets),0) blocked_packets,
            COALESCE(SUM(f.edited_packets),0) edited_packets
        FROM services s LEFT JOIN pyfilter f ON s.service_id = f.service_id
        GROUP BY s.service_id;
    """)
    return res

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
            s.target_type target_type,
            s.tls_stream_id tls_stream_id,
            COUNT(f.name) n_filters,
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
    srv = db.query("SELECT target_type, tls_stream_id FROM services WHERE service_id = ?;", service_id)
    if srv and srv[0]["target_type"] == "tls":
        if not await activate_stream(srv[0]["tls_stream_id"]):
            raise HTTPException(status_code=400, detail="Linked TLS stream not found")
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
    
    srv_check = db.query("SELECT ip_int, port, target_type, tls_stream_id FROM services WHERE service_id = ?;", service_id)
    if len(srv_check) == 0:
        raise HTTPException(status_code=404, detail="Service not found")
    old_srv = srv_check[0]
    
    if form.port is not None and (form.port < 1 or form.port > 65535):
        raise HTTPException(status_code=400, detail="Invalid port")
    
    if form.ip_int is not None:
        try:
            form.ip_int = ip_parse(form.ip_int)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid address")

    new_ip = form.ip_int if form.ip_int is not None else old_srv["ip_int"]
    new_port = form.port if form.port is not None else old_srv["port"]
    
    new_target_type = form.target_type if form.target_type is not None else old_srv["target_type"]
    new_tls_stream_id = form.tls_stream_id if form.tls_stream_id is not None else old_srv["tls_stream_id"]
    
    if new_target_type == "tls" and not new_tls_stream_id:
        raise HTTPException(status_code=400, detail="TLS stream ID is required when target type is tls")
    if new_target_type == "flow" and (new_ip is None or new_port is None):
        raise HTTPException(status_code=400, detail="IP and Port are required when target type is flow")
    
    keys = []
    values = []
    
    for key, value in form.model_dump(exclude_none=True).items():
        keys.append(key)
        values.append(value)
        if key == "proto":
            keys.append("l4_proto")
            values.append(convert_protocol_to_l4(value))
        
    if len(keys) == 0:
        raise HTTPException(status_code=400, detail="No settings to change provided")
            
    try:
        db.query(f'UPDATE services SET {", ".join([f"{key}=?" for key in keys])} WHERE service_id = ?;', *values, service_id)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="A service with these settings already exists")
    
    old_status = firewall.get(service_id).status
    await firewall.remove(service_id)
    if old_status == STATUS.ACTIVE and new_target_type == "tls":
        await activate_stream(new_tls_stream_id)
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
            name, blocked_packets, edited_packets, active, service_id
        FROM pyfilter WHERE service_id = ?;
    """, service_id)

@app.get('/services/{service_id}/pyfilters/{filter_name}', response_model=PyFilterModel)
async def get_pyfilter_by_id(service_id: str, filter_name: str):
    """Get pyfilter info using his id"""
    res = db.query("""
        SELECT 
            name, blocked_packets, edited_packets, active, service_id
        FROM pyfilter WHERE name = ? AND service_id = ?;
    """, filter_name, service_id)
    if len(res) == 0:
        raise HTTPException(status_code=400, detail="This filter does not exists!")
    return res[0]

@app.post('/services/{service_id}/pyfilters/{filter_name}/enable', response_model=StatusMessageModel)
async def pyfilter_enable(service_id: str, filter_name: str):
    """Request the enabling of a pyfilter"""
    res = db.query('SELECT * FROM pyfilter WHERE name = ? AND service_id = ?;', filter_name, service_id)
    if len(res) != 0:
        db.query('UPDATE pyfilter SET active=1 WHERE name = ? AND service_id = ?;', filter_name, service_id)
        await firewall.get(res[0]["service_id"]).update_filters()
        await refresh_frontend()
    return {'status': 'ok'}

@app.post('/services/{service_id}/pyfilters/{filter_name}/disable', response_model=StatusMessageModel)
async def pyfilter_disable(service_id: str, filter_name: str):
    """Request the deactivation of a pyfilter"""
    res = db.query('SELECT * FROM pyfilter WHERE name = ? AND service_id = ?;', filter_name, service_id)
    if len(res) != 0:
        db.query('UPDATE pyfilter SET active=0 WHERE name = ? AND service_id = ?;', filter_name, service_id)
        await firewall.get(res[0]["service_id"]).update_filters()
        await refresh_frontend()
    return {'status': 'ok'}

@app.post('/services', response_model=ServiceAddResponse)
async def add_new_service(form: ServiceAddForm):
    """Add a new service"""
    if form.target_type == "flow":
        if form.ip_int is None or form.port is None:
            raise HTTPException(status_code=400, detail="IP and Port are required when target type is flow")
        try:
            form.ip_int = ip_parse(form.ip_int)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid address")
    elif form.target_type == "tls":
        if not form.tls_stream_id:
            raise HTTPException(status_code=400, detail="TLS stream ID is required when target type is tls")
            
    if form.proto not in ["tcp", "http"]:
        raise HTTPException(status_code=400, detail="Invalid protocol")
            
    srv_id = None
    try:
        srv_id = gen_service_id()
        db.query("INSERT INTO services (service_id, name, port, status, proto, ip_int, fail_open, l4_proto, target_type, tls_stream_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    srv_id, refactor_name(form.name), form.port, STATUS.STOP, form.proto, form.ip_int, form.fail_open, convert_protocol_to_l4(form.proto), form.target_type, form.tls_stream_id)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="This type of service already exists")
    await firewall.reload()
    await refresh_frontend()
    return {'status': 'ok', 'service_id': srv_id}

@app.put('/services/{service_id}/code', response_model=StatusMessageModel)
async def set_pyfilters_code(service_id: str, form: SetPyFilterForm):
    """Set the python filter for a service"""
    service = db.query("SELECT service_id, proto FROM services WHERE service_id = ?;", service_id)
    if len(service) == 0:
        raise HTTPException(status_code=400, detail="This service does not exists!")
    service = service[0]
    service_id = service["service_id"]
    srv_proto = service["proto"]
    
    try:
        async with asyncio.timeout(8):
            try:
                found_filters = get_filter_names(form.code, srv_proto)
            except Exception as e:
                if DEBUG:
                    traceback.print_exc()
                raise HTTPException(status_code=400, detail="Compile error: "+str(e))
            
            # Remove filters that are not in the new code
            existing_filters = db.query("SELECT name FROM pyfilter WHERE service_id = ?;", service_id)
            existing_filters = [ele["name"] for ele in existing_filters]
            for filter in existing_filters:
                if filter not in found_filters:
                    db.query("DELETE FROM pyfilter WHERE name = ?;", filter)
            
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
    except asyncio.TimeoutError:
        if DEBUG:
            traceback.print_exc()
        raise HTTPException(status_code=400, detail="The operation took too long")
    
    return {'status': 'ok'}

@app.get('/services/{service_id}/code', response_class=PlainTextResponse)
async def get_pyfilters_code(service_id: str):
    """Get the python filter for a service"""
    if not db.query("SELECT 1 FROM services WHERE service_id = ?;", service_id):
        raise HTTPException(status_code=400, detail="This service does not exists!")
    try:
        with open(f"db/nfproxy_filters/{service_id}.py") as f:
            return f.read()
    except FileNotFoundError:
        return ""

#Socket io events
async def join_outstream(sid, data):
    """Client joins a room."""
    srv = data.get("service")
    if srv:
        try:
            srv_manager = firewall.get(srv)
            room = f"nfproxy-outstream-{srv}"
            await utils.socketio.enter_room(sid, room)
            await utils.socketio.emit(room, srv_manager.read_outstrem_buffer(), room=sid)
        except ServiceNotFoundException:
            pass

async def leave_outstream(sid, data):
    """Client leaves a room."""
    srv = data.get("service")
    if srv:
        await utils.socketio.leave_room(sid, f"nfproxy-outstream-{srv}")

async def join_exception(sid, data):
    """Client joins a room."""
    srv = data.get("service")
    if srv:
        try:
            srv_manager = firewall.get(srv)
            room = f"nfproxy-exception-{srv}"
            await utils.socketio.enter_room(sid, room)
            await utils.socketio.emit(room, srv_manager.last_exception_time, room=sid)
        except ServiceNotFoundException:
            pass

async def leave_exception(sid, data):
    """Client leaves a room."""
    srv = data.get("service")
    if srv:
        await utils.socketio.leave_room(sid, f"nfproxy-exception-{srv}")

