from fastapi import APIRouter, HTTPException
import subprocess
from pydantic import BaseModel
from modules.tls.manager import TLSManager, ip_parse
from modules.tls.service import reload_tls
from utils.models import StatusMessageModel
import secrets
import routers.nfproxy as nfproxy_router
import routers.nfregex as nfregex_router

def gen_service_id():
    while True:
        res = secrets.token_hex(8)
        if not manager.get_stream(res):
            break
    return res

class TLSStreamAddForm(BaseModel):
    name: str
    ip_int: str
    port: int
    cert: str
    key: str
    enabled: bool = True

class TLSStreamEditForm(BaseModel):
    name: str | None = None
    ip_int: str | None = None
    port: int | None = None
    cert: str | None = None
    key: str | None = None

class TLSStreamResponse(BaseModel):
    status: str
    stream_id: str | None = None

app = APIRouter()
manager = TLSManager()

# (module, human name) pairs of the routers that can depend on a TLS stream
DEPENDENT_ROUTERS = (("nfproxy", nfproxy_router), ("nfregex", nfregex_router))

def get_dependent_services(stream_id: str) -> list[tuple[str, "object", str, str]]:
    """Returns (module_name, router_module, service_id, status) for every nfproxy/nfregex service linked to a TLS stream."""
    deps = []
    for module_name, router_mod in DEPENDENT_ROUTERS:
        rows = router_mod.db.query(
            "SELECT service_id, status FROM services WHERE target_type = 'tls' AND tls_stream_id = ?;", stream_id
        )
        for row in rows:
            deps.append((module_name, router_mod, row["service_id"], row["status"]))
    return deps

async def sync_dependent_services_address(stream_id: str, new_ip: str, new_port: int):
    """After a stream's ip/port changed, mirror it onto dependent services and rebind their live nft rules."""
    touched_modules = set()
    for module_name, router_mod, srv_id, status in get_dependent_services(stream_id):
        router_mod.db.query("UPDATE services SET ip_int = ?, port = ? WHERE service_id = ?;", new_ip, new_port, srv_id)
        await router_mod.firewall.remove(srv_id)
        await router_mod.firewall.reload()
        await router_mod.firewall.get(srv_id).next(status)
        touched_modules.add(module_name)
    for module_name, router_mod in DEPENDENT_ROUTERS:
        if module_name in touched_modules:
            await router_mod.refresh_frontend()

async def cascade_stop_dependents(stream_id: str):
    """When a TLS stream is stopped, stop every active service that depends on it."""
    touched_modules = set()
    for module_name, router_mod, srv_id, status in get_dependent_services(stream_id):
        if status == "active":
            await router_mod.firewall.get(srv_id).next("stop")
            touched_modules.add(module_name)
    for module_name, router_mod in DEPENDENT_ROUTERS:
        if module_name in touched_modules:
            await router_mod.refresh_frontend()

async def startup():
    await reload_tls()

async def shutdown():
    subprocess.run(["nginx", "-c", "/tmp/firegex_nginx.conf", "-s", "stop", "-e", "/tmp/firegex_nginx_error.log"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

async def reset(form):
    if form.delete:
        manager.db.delete()
        manager.db.init()
    await reload_tls()

@app.get('/streams')
async def get_streams():
    return manager.get_streams()

@app.post('/streams', response_model=TLSStreamResponse)
async def add_stream(form: TLSStreamAddForm):
    try:
        ip_int = ip_parse(form.ip_int)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid address")

    if manager.get_stream_by_ip_port(ip_int, form.port):
        raise HTTPException(status_code=400, detail="A TLS stream for this IP and Port already exists")

    stream_id = gen_service_id()
    try:
        manager.add_stream(stream_id, form.name, ip_int, form.port, form.cert, form.key, status="active" if form.enabled else "stop")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    await reload_tls()
    return {"status": "ok", "stream_id": stream_id}

@app.put('/streams/{stream_id}', response_model=StatusMessageModel)
async def edit_stream(stream_id: str, form: TLSStreamEditForm):
    stream = manager.get_stream(stream_id)
    if not stream:
        raise HTTPException(status_code=404, detail="TLS stream not found")

    new_ip_int = None
    if form.ip_int is not None:
        try:
            new_ip_int = ip_parse(form.ip_int)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid address")

    if form.port is not None and (form.port < 1 or form.port > 65535):
        raise HTTPException(status_code=400, detail="Invalid port")

    check_ip = new_ip_int if new_ip_int is not None else stream["ip_int"]
    check_port = form.port if form.port is not None else stream["port"]
    address_changed = check_ip != stream["ip_int"] or check_port != stream["port"]

    if address_changed:
        existing = manager.get_stream_by_ip_port(check_ip, check_port)
        if existing and existing["id"] != stream_id:
            raise HTTPException(status_code=400, detail="A TLS stream for this IP and Port already exists")

    try:
        manager.update_stream(stream_id, name=form.name, ip_int=new_ip_int, port=form.port, cert=form.cert, key=form.key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if address_changed:
        await sync_dependent_services_address(stream_id, check_ip, check_port)

    await reload_tls()
    return {"status": "ok"}

@app.delete('/streams/{stream_id}', response_model=StatusMessageModel)
async def delete_stream(stream_id: str):
    stream = manager.get_stream(stream_id)
    if not stream:
        raise HTTPException(status_code=404, detail="TLS stream not found")

    if get_dependent_services(stream_id):
        raise HTTPException(status_code=400, detail="Cannot delete this TLS stream because it is actively used by NFProxy or NFRegex services.")

    manager.delete_stream(stream_id)
    await reload_tls()
    return {"status": "ok"}

@app.post('/streams/{stream_id}/start', response_model=StatusMessageModel)
async def start_stream(stream_id: str):
    if not manager.get_stream(stream_id):
        raise HTTPException(status_code=404, detail="TLS stream not found")
    manager.update_status(stream_id, "active")
    await reload_tls()
    return {"status": "ok"}

@app.post('/streams/{stream_id}/stop', response_model=StatusMessageModel)
async def stop_stream(stream_id: str):
    if not manager.get_stream(stream_id):
        raise HTTPException(status_code=404, detail="TLS stream not found")
    manager.update_status(stream_id, "stop")
    await reload_tls()
    await cascade_stop_dependents(stream_id)
    return {"status": "ok"}
