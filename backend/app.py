from base64 import b64decode
import sqlite3, uvicorn, sys, bcrypt, secrets, re, os, asyncio, httpx, urllib, websockets
from fastapi import FastAPI, Request, HTTPException, WebSocket
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from fastapi.responses import FileResponse, StreamingResponse
from utils import SQLite, KeyValueStorage, gen_internal_port, ProxyManager, from_name_get_id, STATUS

ON_DOCKER = len(sys.argv) > 1 and sys.argv[1] == "DOCKER"
DEBUG = len(sys.argv) > 1 and sys.argv[1] == "DEBUG"

# DB init
db = SQLite('firegex')
db.connect()
conf = KeyValueStorage(db)
firewall = ProxyManager(db)

app = FastAPI(debug=DEBUG)

app.add_middleware(SessionMiddleware, secret_key=os.urandom(32))
SESSION_TOKEN = secrets.token_hex(8)
APP_STATUS = "init"
REACT_BUILD_DIR = "../frontend/build/" if not ON_DOCKER else "../frontend/"
REACT_HTML_PATH = os.path.join(REACT_BUILD_DIR,"index.html")



def is_loggined(request: Request):
    return request.session.get("token", "") == SESSION_TOKEN

def login_check(request: Request):
    if is_loggined(request): return True
    raise HTTPException(status_code=401, detail="Invalid login session!")

@app.get("/api/status")
async def get_status(request: Request):
    global APP_STATUS
    return { 
        "status":APP_STATUS,
        "loggined": is_loggined(request)
    }

class PasswordForm(BaseModel):
    password: str

class PasswordChangeForm(BaseModel):
    password: str
    expire: bool

@app.post("/api/login")
async def login_api(request: Request, form: PasswordForm):
    global APP_STATUS
    if APP_STATUS != "run": raise HTTPException(status_code=400)

    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    await asyncio.sleep(0.3) # No bruteforce :)

    if bcrypt.checkpw(form.password.encode(), conf.get("password").encode()):
        request.session["token"] = SESSION_TOKEN
        return { "status":"ok" }
    
    return {"status":"Wrong password!"}

@app.get("/api/logout")
async def logout(request: Request):
    request.session["token"] = False
    return { "status":"ok" }

@app.post('/api/change-password')
async def change_password(request: Request, form: PasswordChangeForm):
    login_check(request)
    global APP_STATUS
    if APP_STATUS != "run": raise HTTPException(status_code=400)

    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    if form.expire:
        SESSION_TOKEN = secrets.token_hex(8)
        request.session["token"] = SESSION_TOKEN
    
    hash_psw = bcrypt.hashpw(form.password.encode(), bcrypt.gensalt())
    conf.put("password",hash_psw.decode())
    return {"status":"ok"}


@app.post('/api/set-password')
async def set_password(request: Request, form: PasswordForm):
    global APP_STATUS
    if APP_STATUS != "init": raise HTTPException(status_code=400)
    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    
    hash_psw = bcrypt.hashpw(form.password.encode(), bcrypt.gensalt())
    conf.put("password",hash_psw.decode())
    APP_STATUS = "run"
    request.session["token"] = SESSION_TOKEN
    return {"status":"ok"}

@app.get('/api/general-stats')
async def get_general_stats(request: Request):
    login_check(request)
    return db.query("""
    SELECT
        (SELECT COALESCE(SUM(blocked_packets),0) FROM regexes) closed,
        (SELECT COUNT(*) FROM regexes) regexes,
        (SELECT COUNT(*) FROM services) services
    """)[0]

@app.get('/api/services')
async def get_services(request: Request):
    login_check(request)
    return db.query("""
        SELECT 
            s.service_id `id`,
            s.status status,
            s.public_port public_port,
            s.internal_port internal_port,
            s.name name,
            COUNT(*) n_regex,
            COALESCE(SUM(r.blocked_packets),0) n_packets
        FROM services s LEFT JOIN regexes r ON r.service_id = s.service_id
        GROUP BY s.service_id;
    """)

@app.get('/api/service/{service_id}')
async def get_service(request: Request, service_id: str):
    login_check(request)
    res = db.query("""
        SELECT 
            s.service_id `id`,
            s.status status,
            s.public_port public_port,
            s.internal_port internal_port,
            s.name name,
            COUNT(*) n_regex,
            COALESCE(SUM(r.blocked_packets),0) n_packets
        FROM services s LEFT JOIN regexes r ON r.service_id = s.service_id WHERE s.service_id = ?
        GROUP BY s.service_id;
    """, service_id)
    if len(res) == 0: raise HTTPException(status_code=400, detail="This service does not exists!")
    return res[0]

@app.get('/api/service/{service_id}/stop')
async def get_service_stop(request: Request, service_id: str):
    login_check(request)
    firewall.change_status(service_id,STATUS.STOP)
    return {'status': 'ok'}

@app.get('/api/service/{service_id}/pause')
async def get_service_pause(request: Request, service_id: str):
    login_check(request)
    firewall.change_status(service_id,STATUS.PAUSE)
    return {'status': 'ok'}

@app.get('/api/service/{service_id}/start')
async def get_service_start(request: Request, service_id: str):
    login_check(request)
    firewall.change_status(service_id,STATUS.ACTIVE)
    return {'status': 'ok'}

@app.get('/api/service/{service_id}/delete')
async def get_service_delete(request: Request, service_id: str):
    login_check(request)
    db.query('DELETE FROM services WHERE service_id = ?;', service_id)
    db.query('DELETE FROM regexes WHERE service_id = ?;', service_id)
    firewall.fire_update(service_id)
    return {'status': 'ok'}


@app.get('/api/service/{service_id}/regen-port')
async def get_regen_port(request: Request, service_id: str):
    login_check(request)
    db.query('UPDATE services SET internal_port = ? WHERE service_id = ?;', gen_internal_port(db), service_id)
    firewall.fire_update(service_id)
    return {'status': 'ok'}


@app.get('/api/service/{service_id}/regexes')
async def get_service_regexes(request: Request, service_id: str):
    login_check(request)
    return db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_id, is_blacklist,
            blocked_packets n_packets, is_case_sensitive
        FROM regexes WHERE service_id = ?;
    """, service_id)

@app.get('/api/regex/{regex_id}')
async def get_regex_id(request: Request, regex_id: int):
    login_check(request)
    res = db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_id, is_blacklist,
            blocked_packets n_packets, is_case_sensitive
        FROM regexes WHERE `id` = ?;
    """, regex_id)
    if len(res) == 0: raise HTTPException(status_code=400, detail="This regex does not exists!")
    return res[0]

@app.get('/api/regex/{regex_id}/delete')
async def get_regex_delete(request: Request, regex_id: int):
    login_check(request)
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    
    if len(res) != 0:
        db.query('DELETE FROM regexes WHERE regex_id = ?;', regex_id)
        firewall.fire_update(res[0]["service_id"])
    
    return {'status': 'ok'}

class RegexAddForm(BaseModel):
    service_id: str
    regex: str
    mode: str
    is_blacklist: bool
    is_case_sensitive: bool

@app.post('/api/regexes/add')
async def post_regexes_add(request: Request, form: RegexAddForm):
    login_check(request)
    try:
        re.compile(b64decode(form.regex))
    except Exception:
        return {"status":"Invalid regex"}
    try:
        db.query("INSERT INTO regexes (service_id, regex, is_blacklist, mode, is_case_sensitive ) VALUES (?, ?, ?, ?, ?);", 
                form.service_id, form.regex, form.is_blacklist, form.mode, form.is_case_sensitive)
    except sqlite3.IntegrityError:
        return {'status': 'An identical regex already exists'}

    firewall.fire_update(form.service_id)
    return {'status': 'ok'}

class ServiceAddForm(BaseModel):
    name: str
    port: int

@app.post('/api/services/add')
async def post_services_add(request: Request, form: ServiceAddForm):
    login_check(request)
    serv_id = from_name_get_id(form.name)
    try:
        db.query("INSERT INTO services (name, service_id, internal_port, public_port, status) VALUES (?, ?, ?, ?, ?)",
                    form.name, serv_id, gen_internal_port(db), form.port, 'stop')
        firewall.reload()
    except sqlite3.IntegrityError:
        return {'status': 'Name or/and port of the service has been already assigned to another service'}
    
    return {'status': 'ok'}

async def frontend_debug_proxy(path):
    httpc = httpx.AsyncClient()
    req = httpc.build_request("GET",urllib.parse.urljoin(f"http://0.0.0.0:{os.getenv('F_PORT','3000')}", path))
    resp = await httpc.send(req, stream=True)
    return StreamingResponse(resp.aiter_bytes(),status_code=resp.status_code)

async def react_deploy(path):
    file_request = os.path.join(REACT_BUILD_DIR, path)
    if not os.path.isfile(file_request):
        return FileResponse(REACT_HTML_PATH, media_type='text/html')
    else:
        return FileResponse(file_request)

if DEBUG:
    async def forward_websocket(ws_a: WebSocket, ws_b: websockets.WebSocketClientProtocol):
        while True:
            data = await ws_a.receive_bytes()
            await ws_b.send(data)


    async def reverse_websocket(ws_a: WebSocket, ws_b: websockets.WebSocketClientProtocol):
        while True:
            data = await ws_b.recv()
            await ws_a.send_text(data)
    
    @app.websocket("/ws")
    async def websocket_debug_proxy(ws: WebSocket):
        await ws.accept()
        async with websockets.connect(f"ws://0.0.0.0:{os.getenv('F_PORT','3000')}/ws") as ws_b_client:
            fwd_task = asyncio.create_task(forward_websocket(ws, ws_b_client))
            rev_task = asyncio.create_task(reverse_websocket(ws, ws_b_client))
            await asyncio.gather(fwd_task, rev_task)

@app.get("/{full_path:path}")
async def catch_all(request: Request, full_path:str):
    if DEBUG:
        try:
            return await frontend_debug_proxy(full_path)
        except Exception:
            return {"details":"Frontend not started at "+f"http://0.0.0.0:{os.getenv('F_PORT','3000')}"}
    else: return await react_deploy(full_path)


if __name__ == '__main__':
    db.create_schema({
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
            'is_blacklist': 'BOOLEAN NOT NULL CHECK (is_blacklist IN (0, 1))',
            'blocked_packets': 'INTEGER UNSIGNED NOT NULL DEFAULT 0',
            'regex_id': 'INTEGER PRIMARY KEY',
            'is_case_sensitive' : 'BOOLEAN NOT NULL CHECK (is_case_sensitive IN (0, 1))',
            'FOREIGN KEY (service_id)':'REFERENCES services (service_id)',
        },
        'keys_values': {
            'key': 'VARCHAR(100) PRIMARY KEY',
            'value': 'VARCHAR(100) NOT NULL',
        },
    })
    db.query("CREATE UNIQUE INDEX IF NOT EXISTS unique_regex_service ON regexes (regex,service_id,is_blacklist,mode,is_case_sensitive);")
    
    if not conf.get("password") is None:
        APP_STATUS = "run"
    
    firewall.reload()
    # os.environ {PORT = Backend Port (Main Port), F_PORT = Frontend Port}
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT","4444")),
        reload=DEBUG,
        access_log=DEBUG,
    )
