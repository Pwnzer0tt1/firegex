from base64 import b64decode
import sqlite3, uvicorn, sys, secrets, re, os, asyncio, httpx, urllib, websockets
from typing import List, Union
from fastapi import FastAPI, HTTPException, WebSocket, Depends
from pydantic import BaseModel, BaseSettings
from fastapi.responses import FileResponse, StreamingResponse
from utils import *
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

ON_DOCKER = len(sys.argv) > 1 and sys.argv[1] == "DOCKER"
DEBUG = len(sys.argv) > 1 and sys.argv[1] == "DEBUG"

# DB init
if not os.path.exists("db"): os.mkdir("db")
db = SQLite('db/firegex.db')
conf = KeyValueStorage(db)
firewall = ProxyManager(db)


class Settings(BaseSettings):
    JWT_ALGORITHM: str = "HS256"
    REACT_BUILD_DIR: str = "../frontend/build/" if not ON_DOCKER else "frontend/"
    REACT_HTML_PATH: str = os.path.join(REACT_BUILD_DIR,"index.html")
    VERSION = "1.3.0"

settings = Settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)
crypto = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(debug=DEBUG, redoc_url=None)

def APP_STATUS(): return "init" if conf.get("password") is None else "run"
def JWT_SECRET(): return conf.get("secret")

@app.on_event("startup")
async def startup_event():
    db.init()
    if not JWT_SECRET(): conf.put("secret", secrets.token_hex(32))
    await firewall.reload()


def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET(), algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

async def check_login(token: str = Depends(oauth2_scheme)):
    if not token:
        return False
    try:
        payload = jwt.decode(token, JWT_SECRET(), algorithms=[settings.JWT_ALGORITHM])
        logged_in: bool = payload.get("logged_in")
    except JWTError:
        return False
    return logged_in

async def is_loggined(auth: bool = Depends(check_login)):
    if not auth:
        raise HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return True

class StatusModel(BaseModel):
    status: str
    loggined: bool
    version: str

@app.get("/api/status", response_model=StatusModel)
async def get_app_status(auth: bool = Depends(check_login)):
    """Get the general status of firegex and your session with firegex"""
    return { 
        "status": APP_STATUS(),
        "loggined": auth,
        "version": settings.VERSION
    }

class PasswordForm(BaseModel):
    password: str

class PasswordChangeForm(BaseModel):
    password: str
    expire: bool

@app.post("/api/login")
async def login_api(form: OAuth2PasswordRequestForm = Depends()):
    """Get a login token to use the firegex api"""
    if APP_STATUS() != "run": raise HTTPException(status_code=400)
    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    await asyncio.sleep(0.3) # No bruteforce :)
    if crypto.verify(form.password, conf.get("password")):
        return {"access_token": create_access_token({"logged_in": True}), "token_type": "bearer"}
    raise HTTPException(406,"Wrong password!")

class ChangePasswordModel(BaseModel):
    status: str
    access_token: Union[str,None]

@app.post('/api/change-password', response_model=ChangePasswordModel)
async def change_password(form: PasswordChangeForm, auth: bool = Depends(is_loggined)):
    """Change the password of firegex"""
    if APP_STATUS() != "run": raise HTTPException(status_code=400)

    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    if form.expire:
        conf.put("secret", secrets.token_hex(32))
    
    hash_psw = crypto.hash(form.password)
    conf.put("password",hash_psw)
    return {"status":"ok", "access_token": create_access_token({"logged_in": True})}


@app.post('/api/set-password', response_model=ChangePasswordModel)
async def set_password(form: PasswordForm):
    """Set the password of firegex"""
    if APP_STATUS() != "init": raise HTTPException(status_code=400)
    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    hash_psw = crypto.hash(form.password)
    conf.put("password",hash_psw)
    return {"status":"ok", "access_token": create_access_token({"logged_in": True})}

class GeneralStatModel(BaseModel):
    closed:int
    regexes: int
    services: int

@app.get('/api/general-stats', response_model=GeneralStatModel)
async def get_general_stats(auth: bool = Depends(is_loggined)):
    """Get firegex general status about services"""
    return db.query("""
    SELECT
        (SELECT COALESCE(SUM(blocked_packets),0) FROM regexes) closed,
        (SELECT COUNT(*) FROM regexes) regexes,
        (SELECT COUNT(*) FROM services) services
    """)[0]

class ServiceModel(BaseModel):
    status: str
    port: int
    name: str
    n_regex: int
    n_packets: int

@app.get('/api/services', response_model=List[ServiceModel])
async def get_service_list(auth: bool = Depends(is_loggined)):
    """Get the list of existent firegex services"""
    return db.query("""
        SELECT 
            s.status status,
            s.port port,
            s.name name,
            COUNT(r.regex_id) n_regex,
            COALESCE(SUM(r.blocked_packets),0) n_packets
        FROM services s LEFT JOIN regexes r ON r.service_port = s.port
        GROUP BY s.port;
    """)

@app.get('/api/service/{service_port}', response_model=ServiceModel)
async def get_service_by_id(service_port: int, auth: bool = Depends(is_loggined)):
    """Get info about a specific service using his id"""
    res = db.query("""
        SELECT 
            s.status status,
            s.port port,
            s.name name,
            COUNT(r.regex_id) n_regex,
            COALESCE(SUM(r.blocked_packets),0) n_packets
        FROM services s LEFT JOIN regexes r ON r.service_port = s.port WHERE s.port = ?
        GROUP BY s.port;
    """, service_port)
    if len(res) == 0: raise HTTPException(status_code=400, detail="This service does not exists!")
    return res[0]

class StatusMessageModel(BaseModel):
    status:str

@app.get('/api/service/{service_port}/stop', response_model=StatusMessageModel)
async def service_stop(service_port: int, auth: bool = Depends(is_loggined)):
    """Request the stop of a specific service"""
    await firewall.get(service_port).next(STATUS.STOP)
    return {'status': 'ok'}

@app.get('/api/service/{service_port}/start', response_model=StatusMessageModel)
async def service_start(service_port: int, auth: bool = Depends(is_loggined)):
    """Request the start of a specific service"""
    await firewall.get(service_port).next(STATUS.ACTIVE)
    return {'status': 'ok'}

@app.get('/api/service/{service_port}/delete', response_model=StatusMessageModel)
async def service_delete(service_port: int, auth: bool = Depends(is_loggined)):
    """Request the deletion of a specific service"""
    db.query('DELETE FROM services WHERE port = ?;', service_port)
    db.query('DELETE FROM regexes WHERE service_port = ?;', service_port)
    await firewall.remove(service_port)
    return {'status': 'ok'}

class RegexModel(BaseModel):
    regex:str
    mode:str
    id:int
    service_port:int
    is_blacklist: bool
    n_packets:int
    is_case_sensitive:bool
    active:bool

@app.get('/api/service/{service_port}/regexes', response_model=List[RegexModel])
async def get_service_regexe_list(service_port: int, auth: bool = Depends(is_loggined)):
    """Get the list of the regexes of a service"""
    return db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_port, is_blacklist,
            blocked_packets n_packets, is_case_sensitive, active
        FROM regexes WHERE service_port = ?;
    """, service_port)

@app.get('/api/regex/{regex_id}', response_model=RegexModel)
async def get_regex_by_id(regex_id: int, auth: bool = Depends(is_loggined)):
    """Get regex info using his id"""
    res = db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_port, is_blacklist,
            blocked_packets n_packets, is_case_sensitive, active
        FROM regexes WHERE `id` = ?;
    """, regex_id)
    if len(res) == 0: raise HTTPException(status_code=400, detail="This regex does not exists!")
    return res[0]

@app.get('/api/regex/{regex_id}/delete', response_model=StatusMessageModel)
async def regex_delete(regex_id: int, auth: bool = Depends(is_loggined)):
    """Delete a regex using his id"""
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('DELETE FROM regexes WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_port"]).update_filters()
    
    return {'status': 'ok'}

@app.get('/api/regex/{regex_id}/enable', response_model=StatusMessageModel)
async def regex_enable(regex_id: int, auth: bool = Depends(is_loggined)):
    """Request the enabling of a regex"""
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('UPDATE regexes SET active=1 WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_port"]).update_filters()
    return {'status': 'ok'}

@app.get('/api/regex/{regex_id}/disable', response_model=StatusMessageModel)
async def regex_disable(regex_id: int, auth: bool = Depends(is_loggined)):
    """Request the deactivation of a regex"""
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('UPDATE regexes SET active=0 WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_port"]).update_filters()
    return {'status': 'ok'}

class RegexAddForm(BaseModel):
    service_port: int
    regex: str
    mode: str
    active: Union[bool,None]
    is_blacklist: bool
    is_case_sensitive: bool

@app.post('/api/regexes/add', response_model=StatusMessageModel)
async def add_new_regex(form: RegexAddForm, auth: bool = Depends(is_loggined)):
    """Add a new regex"""
    try:
        re.compile(b64decode(form.regex))
    except Exception:
        return {"status":"Invalid regex"}
    try:
        db.query("INSERT INTO regexes (service_port, regex, is_blacklist, mode, is_case_sensitive, active ) VALUES (?, ?, ?, ?, ?, ?);", 
                form.service_port, form.regex, form.is_blacklist, form.mode, form.is_case_sensitive, True if form.active is None else form.active )
    except sqlite3.IntegrityError:
        return {'status': 'An identical regex already exists'}

    await firewall.get(form.service_port).update_filters()
    return {'status': 'ok'}

class ServiceAddForm(BaseModel):
    name: str
    port: int

@app.post('/api/services/add', response_model=StatusMessageModel)
async def add_new_service(form: ServiceAddForm, auth: bool = Depends(is_loggined)):
    """Add a new service"""
    try:
        db.query("INSERT INTO services (name, port, status) VALUES (?, ?, ?)",
                    form.name, form.port, STATUS.STOP)
    except sqlite3.IntegrityError:
        return {'status': 'Name or/and ports of the service has been already assigned to another service'}
    await firewall.reload()

    return {'status': 'ok'}

async def frontend_debug_proxy(path):
    httpc = httpx.AsyncClient()
    req = httpc.build_request("GET",urllib.parse.urljoin(f"http://127.0.0.1:{os.getenv('F_PORT','3000')}", path))
    resp = await httpc.send(req, stream=True)
    return StreamingResponse(resp.aiter_bytes(),status_code=resp.status_code)

async def react_deploy(path):
    file_request = os.path.join(settings.REACT_BUILD_DIR, path)
    if not os.path.isfile(file_request):
        return FileResponse(settings.REACT_HTML_PATH, media_type='text/html')
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
        async with websockets.connect(f"ws://127.0.0.1:{os.getenv('F_PORT','3000')}/ws") as ws_b_client:
            fwd_task = asyncio.create_task(forward_websocket(ws, ws_b_client))
            rev_task = asyncio.create_task(reverse_websocket(ws, ws_b_client))
            await asyncio.gather(fwd_task, rev_task)

@app.get("/{full_path:path}", include_in_schema=False)
async def catch_all(full_path:str):
    if DEBUG:
        try:
            return await frontend_debug_proxy(full_path)
        except Exception:
            return {"details":"Frontend not started at "+f"http://127.0.0.1:{os.getenv('F_PORT','3000')}"}
    else: return await react_deploy(full_path)


if __name__ == '__main__':
    # os.environ {PORT = Backend Port (Main Port), F_PORT = Frontend Port}
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT","4444")),
        reload=DEBUG,
        access_log=DEBUG,
        workers=1
    )
