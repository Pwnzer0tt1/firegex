from base64 import b64decode
import sqlite3, uvicorn, sys, secrets, re, os, asyncio, httpx, urllib, websockets
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
    VERSION = "2.0.0"


settings = Settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)
crypto = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(debug=DEBUG)

def APP_STATUS(): return "init" if conf.get("password") is None else "run"
def JWT_SECRET(): return conf.get("secret")

@app.on_event("shutdown")
async def shutdown_event():
    await firewall.close()
    db.disconnect()

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

@app.get("/api/status")
async def get_status(auth: bool = Depends(check_login)):
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
    if APP_STATUS() != "run": raise HTTPException(status_code=400)
    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    await asyncio.sleep(0.3) # No bruteforce :)
    if crypto.verify(form.password, conf.get("password")):
        return {"access_token": create_access_token({"logged_in": True}), "token_type": "bearer"}
    raise HTTPException(406,"Wrong password!")


@app.post('/api/change-password')
async def change_password(form: PasswordChangeForm, auth: bool = Depends(is_loggined)):
    if APP_STATUS() != "run": raise HTTPException(status_code=400)

    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    if form.expire:
        conf.put("secret", secrets.token_hex(32))
    
    hash_psw = crypto.hash(form.password)
    conf.put("password",hash_psw)
    return {"status":"ok", "access_token": create_access_token({"logged_in": True})}


@app.post('/api/set-password')
async def set_password(form: PasswordForm):
    if APP_STATUS() != "init": raise HTTPException(status_code=400)
    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    hash_psw = crypto.hash(form.password)
    conf.put("password",hash_psw)
    return {"status":"ok", "access_token": create_access_token({"logged_in": True})}

@app.get('/api/general-stats')
async def get_general_stats(auth: bool = Depends(is_loggined)):
    
    return db.query("""
    SELECT
        (SELECT COALESCE(SUM(blocked_packets),0) FROM regexes) closed,
        (SELECT COUNT(*) FROM regexes) regexes,
        (SELECT COUNT(*) FROM services) services
    """)[0]

@app.get('/api/services')
async def get_services(auth: bool = Depends(is_loggined)):
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

@app.get('/api/service/{service_id}')
async def get_service(service_id: str, auth: bool = Depends(is_loggined)):
    
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

@app.get('/api/service/{service_id}/stop')
async def get_service_stop(service_id: str, auth: bool = Depends(is_loggined)):
    await firewall.get(service_id).next(STATUS.STOP)
    return {'status': 'ok'}

@app.get('/api/service/{service_id}/pause')
async def get_service_pause(service_id: str, auth: bool = Depends(is_loggined)):
    await firewall.get(service_id).next(STATUS.PAUSE)
    return {'status': 'ok'}

@app.get('/api/service/{service_id}/start')
async def get_service_start(service_id: str, auth: bool = Depends(is_loggined)):
    await firewall.get(service_id).next(STATUS.ACTIVE)
    return {'status': 'ok'}

@app.get('/api/service/{service_id}/delete')
async def get_service_delete(service_id: str, auth: bool = Depends(is_loggined)):
    db.query('DELETE FROM services WHERE service_id = ?;', service_id)
    db.query('DELETE FROM regexes WHERE service_id = ?;', service_id)
    await firewall.remove(service_id)
    return {'status': 'ok'}


@app.get('/api/service/{service_id}/regen-port')
async def get_regen_port(service_id: str, auth: bool = Depends(is_loggined)):
    db.query('UPDATE services SET internal_port = ? WHERE service_id = ?;', gen_internal_port(db), service_id)
    await firewall.get(service_id).update_port()
    return {'status': 'ok'}


@app.get('/api/service/{service_id}/regexes')
async def get_service_regexes(service_id: str, auth: bool = Depends(is_loggined)):
    return db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_id, is_blacklist,
            blocked_packets n_packets, is_case_sensitive
        FROM regexes WHERE service_id = ?;
    """, service_id)

@app.get('/api/regex/{regex_id}')
async def get_regex_id(regex_id: int, auth: bool = Depends(is_loggined)):
    res = db.query("""
        SELECT 
            regex, mode, regex_id `id`, service_id, is_blacklist,
            blocked_packets n_packets, is_case_sensitive
        FROM regexes WHERE `id` = ?;
    """, regex_id)
    if len(res) == 0: raise HTTPException(status_code=400, detail="This regex does not exists!")
    return res[0]

@app.get('/api/regex/{regex_id}/delete')
async def get_regex_delete(regex_id: int, auth: bool = Depends(is_loggined)):
    res = db.query('SELECT * FROM regexes WHERE regex_id = ?;', regex_id)
    if len(res) != 0:
        db.query('DELETE FROM regexes WHERE regex_id = ?;', regex_id)
        await firewall.get(res[0]["service_id"]).update_filters()
    
    return {'status': 'ok'}

class RegexAddForm(BaseModel):
    service_id: str
    regex: str
    mode: str
    is_blacklist: bool
    is_case_sensitive: bool

@app.post('/api/regexes/add')
async def post_regexes_add(form: RegexAddForm, auth: bool = Depends(is_loggined)):
    try:
        re.compile(b64decode(form.regex))
    except Exception:
        return {"status":"Invalid regex"}
    try:
        db.query("INSERT INTO regexes (service_id, regex, is_blacklist, mode, is_case_sensitive ) VALUES (?, ?, ?, ?, ?);", 
                form.service_id, form.regex, form.is_blacklist, form.mode, form.is_case_sensitive)
    except sqlite3.IntegrityError:
        return {'status': 'An identical regex already exists'}

    await firewall.get(form.service_id).update_filters()
    return {'status': 'ok'}

class ServiceAddForm(BaseModel):
    name: str
    port: int

@app.post('/api/services/add')
async def post_services_add(form: ServiceAddForm, auth: bool = Depends(is_loggined)):
    serv_id = gen_service_id(db)
    try:
        db.query("INSERT INTO services (name, service_id, internal_port, public_port, status) VALUES (?, ?, ?, ?, ?)",
                    form.name, serv_id, gen_internal_port(db), form.port, 'stop')
        await firewall.reload()
    except sqlite3.IntegrityError:
        return {'status': 'Name or/and port of the service has been already assigned to another service'}
    
    return {'status': 'ok', "id": serv_id }

async def frontend_debug_proxy(path):
    httpc = httpx.AsyncClient()
    req = httpc.build_request("GET",urllib.parse.urljoin(f"http://0.0.0.0:{os.getenv('F_PORT','3000')}", path))
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
        async with websockets.connect(f"ws://0.0.0.0:{os.getenv('F_PORT','3000')}/ws") as ws_b_client:
            fwd_task = asyncio.create_task(forward_websocket(ws, ws_b_client))
            rev_task = asyncio.create_task(reverse_websocket(ws, ws_b_client))
            await asyncio.gather(fwd_task, rev_task)

@app.get("/{full_path:path}")
async def catch_all(full_path:str):
    if DEBUG:
        try:
            return await frontend_debug_proxy(full_path)
        except Exception:
            return {"details":"Frontend not started at "+f"http://0.0.0.0:{os.getenv('F_PORT','3000')}"}
    else: return await react_deploy(full_path)


if __name__ == '__main__':
    # os.environ {PORT = Backend Port (Main Port), F_PORT = Frontend Port}
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT","4444")),
        reload=DEBUG,
        access_log=DEBUG,
        workers=1
    )
