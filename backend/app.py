import uvicorn
import secrets
import utils
import os
import asyncio
import logging
from fastapi import FastAPI, HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from utils.sqlite import SQLite
from utils import API_VERSION, FIREGEX_PORT, FIREGEX_HOST, JWT_ALGORITHM, get_interfaces, socketio_emit, DEBUG, SysctlManager, NORELOAD
from utils.loader import frontend_deploy, load_routers
from utils.models import ChangePasswordModel, IpInterface, PasswordChangeForm, PasswordForm, ResetRequest, StatusModel, StatusMessageModel
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
import socketio
from socketio.exceptions import ConnectionRefusedError
import hashlib

# DB init
db = SQLite('db/firegex.db')
sysctl = SysctlManager({
    "net.ipv4.conf.all.forwarding": True,
    "net.ipv6.conf.all.forwarding": True,
    "net.ipv4.conf.all.route_localnet": True,
    "net.ipv4.ip_forward": True
})

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)

@asynccontextmanager
async def lifespan(app):
    await startup_main()
    yield
    await shutdown_main()

app = FastAPI(
    debug=DEBUG,
    redoc_url=None,
    lifespan=lifespan,
    docs_url="/api/docs",
    title="Firegex API",
    version=API_VERSION,
)

if DEBUG:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

utils.socketio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=[],
    transports=["websocket"]
)

sio_app = socketio.ASGIApp(utils.socketio, socketio_path="/sock/socket.io", other_asgi_app=app)
app.mount("/sock", sio_app)

def APP_STATUS(): return "init" if db.get("password") is None else "run"
def JWT_SECRET(): return db.get("secret")

def hash_psw(psw: str):
    salt = db.get("salt")
    if not salt:
        salt = secrets.token_hex(32)
        db.put("salt", salt)
    return hashlib.pbkdf2_hmac("sha256", psw.encode(), salt.encode(), 500_000).hex()

def set_psw(psw: str):
    db.put("password", hash_psw(psw))

def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET(), algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def refresh_frontend(additional:list[str]=[]):
    await socketio_emit([]+additional)

async def check_login(token: str = Depends(oauth2_scheme)):
    if not token:
        return False
    try:
        payload = jwt.decode(token, JWT_SECRET(), algorithms=[JWT_ALGORITHM])
        logged_in: bool = payload.get("logged_in")
    except Exception:
        return False
    return logged_in

@utils.socketio.on("connect")
async def sio_connect(sid, environ, auth):
    if not auth or not await check_login(auth.get("token")):
        raise ConnectionRefusedError("Unauthorized")
    utils.sid_list.add(sid)

@utils.socketio.on("disconnect")
async def sio_disconnect(sid):
    try:
        utils.sid_list.remove(sid)
    except KeyError:
        pass

async def disconnect_all():
    while True:
        if len(utils.sid_list) == 0:
            break
        await utils.socketio.disconnect(utils.sid_list.pop())

@utils.socketio.on("update")
async def updater(): pass

async def is_loggined(auth: bool = Depends(check_login)):
    if not auth:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True

api = APIRouter(prefix="/api", dependencies=[Depends(is_loggined)])

@app.get("/api/status", response_model=StatusModel)
async def get_app_status(auth: bool = Depends(check_login)):
    """Get the general status of firegex and your session with firegex"""
    return { 
        "status": APP_STATUS(),
        "loggined": auth,
        "version": API_VERSION
    }

@app.post("/api/login")
async def login_api(form: OAuth2PasswordRequestForm = Depends()):
    """Get a login token to use the firegex api"""
    if APP_STATUS() != "run":
        raise HTTPException(status_code=400)
    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    await asyncio.sleep(0.3) # No bruteforce :)
    if db.get("password") == hash_psw(form.password):
        return {"access_token": create_access_token({"logged_in": True}), "token_type": "bearer"}
    raise HTTPException(406,"Wrong password!")


@app.post('/api/set-password', response_model=ChangePasswordModel)
async def set_password(form: PasswordForm):
    """Set the password of firegex"""
    if APP_STATUS() != "init":
        raise HTTPException(status_code=400)
    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    set_psw(form.password)
    await refresh_frontend()
    return {"status":"ok", "access_token": create_access_token({"logged_in": True})}

@api.post('/change-password', response_model=ChangePasswordModel)
async def change_password(form: PasswordChangeForm):
    """Change the password of firegex"""
    if APP_STATUS() != "run":
        raise HTTPException(status_code=400)

    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    if form.expire:
        db.put("secret", secrets.token_hex(32))
        await disconnect_all()
    
    set_psw(form.password)
    await refresh_frontend()
    return {"status":"ok", "access_token": create_access_token({"logged_in": True})}


@api.get('/interfaces', response_model=list[IpInterface])
async def get_ip_interfaces():
    """Get a list of ip and ip6 interfaces"""
    return get_interfaces()

#Routers Loader
reset, startup, shutdown = load_routers(api)

async def startup_main():
    db.init()
    if os.getenv("HEX_SET_PSW"):
        set_psw(bytes.fromhex(os.getenv("HEX_SET_PSW")).decode())
    try:
        sysctl.set()
    except Exception as e:
        logging.error(f"Error setting sysctls: {e}")
    await startup()
    if not JWT_SECRET():
        db.put("secret", secrets.token_hex(32))
    await refresh_frontend()

async def shutdown_main():
    await shutdown()
    sysctl.reset()
    db.disconnect()

@api.post('/reset', response_model=StatusMessageModel)
async def reset_firegex(form: ResetRequest):
    """Reset firegex nftables rules and optionally all the database"""
    if form.delete:
        db.delete()
        db.init()
        db.put("secret", secrets.token_hex(32))
    try:
        sysctl.set()
    except Exception as e:
        logging.error(f"Error setting sysctls: {e}")
    await reset(form)
    await refresh_frontend()
    return {'status': 'ok'}

app.include_router(api)
frontend_deploy(app)

if __name__ == '__main__':
    # os.environ {PORT = Backend Port (Main Port), F_PORT = Frontend Port}
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    uvicorn.run(
        "app:app",
        # None allows to bind also on ipv6, and is selected if FIREGEX_HOST is any
        host=None if FIREGEX_HOST == "any" else FIREGEX_HOST,
        port=FIREGEX_PORT,
        reload=DEBUG and not NORELOAD,
        access_log=True,
        workers=1, # Firewall module can't be replicated in multiple workers
                   # Later the firewall module will be moved to a separate process
                   # The webserver will communicate using redis (redis is also needed for websockets)
    )
