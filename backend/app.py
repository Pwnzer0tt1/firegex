import uvicorn
import secrets
import utils
import os
import asyncio
import logging
import base64
from fastapi import FastAPI, HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from utils.sqlite import SQLite
from utils import boot_auth_mode, SAFE_DB_NAME, SAFE_PY_NAME, API_VERSION, FIREGEX_PORT, FIREGEX_HOST, FIREGEX_SOCKET, JWT_ALGORITHM, get_interfaces, socketio_emit, DEBUG, SysctlManager, NORELOAD, safe_join
from utils.loader import frontend_deploy, load_routers
from utils.models import AuthModeForm, ChangePasswordModel, IpInterface, PasswordChangeForm, PasswordForm, ResetRequest, StatusModel, StatusMessageModel
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
import socketio
from socketio.exceptions import ConnectionRefusedError
import hashlib
import hmac
from ipaddress import ip_network, ip_address
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

ALLOWED_NETWORKS = [ip_network(ip.strip(), strict=False) for ip in os.getenv("ALLOWED_IPS", "").split(",") if ip.strip()]
PROXY_IP_HEADER = os.getenv("PROXY_IP_HEADER", "")
#: What the environment asked for at boot. Only the seed: the answer lives in the
#: database from here on, so that turning authentication off — or handing the running
#: instance a password — takes effect on the next request instead of on the next restart.
#: A flag that could only be read at startup meant `run.py config --password` printing
#: "it will take effect immediately" while the process it was talking to had already
#: decided that every caller was an administrator.
UNSAFE_DISABLE_AUTH_ENV = os.getenv("UNSAFE_DISABLE_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}

#: Whether this boot's environment was written just now, from the host's configuration:
#: set by `docker-entrypoint.sh` on the first boot of a container, and by `run.py` for
#: every standalone start. Absent means the container is being started **again** by
#: Docker — after a reboot, a restart of the daemon, a crash under `restart:
#: unless-stopped` — with the environment it was created with, which is older than
#: anything `run.py config` has said since.
FRESH_BOOT = os.getenv("FIREGEX_FRESH_BOOT", "") == "1"

#: What the host last decided about authentication with `run.py config`, kept where a
#: restart can read it. See `seed_auth_mode`.
AUTH_HOST_KEY = "auth_disabled_host"


def auth_disabled() -> bool:
    """Is authentication off right now?

    Read per request rather than cached. It is one indexed lookup in a SQLite file the
    process already holds open, on a path that is about to do a PBKDF2 or a JWT decode,
    and the alternative is a copy in memory that can disagree with the one on disk —
    which is the whole bug this replaced.
    """
    stored = db.get("auth_disabled")
    if stored is None:
        return UNSAFE_DISABLE_AUTH_ENV
    return stored == "1"


# With authentication off every request is already a full administrator, so the password
# endpoints would let an anonymous caller plant a credential that keeps working once it
# is turned back on. Both are set out of band, from the host, with "python3 run.py
# config --password" and "--no-unsafe-disable-auth".
AUTH_DISABLED_DETAIL = ("Firegex authentication is disabled: the password can only be changed from "
                        "the host with 'python3 run.py config --password'")

class IPFilterMiddleware:
    def __init__(self, app):
        self.app = app
        
    async def __call__(self, scope, receive, send):
        if scope["type"] in ["http", "websocket"] and ALLOWED_NETWORKS:
            client_ip = None
            if PROXY_IP_HEADER:
                headers = dict(scope.get("headers", []))
                header_val = headers.get(PROXY_IP_HEADER.lower().encode())
                if header_val:
                    client_ip = header_val.decode().split(",")[0].strip()

            if not client_ip and scope.get("client"):
                client_ip = scope["client"][0]

            # Fail closed: an allowlist must deny whenever a client IP can't be
            # positively determined and matched (missing IP, unparseable IP, or an
            # IP that just isn't in the list all get denied the same way) - a
            # malformed/missing value must never be treated as an implicit pass.
            allowed = False
            if client_ip:
                try:
                    ip_obj = ip_address(client_ip)
                    allowed = any(ip_obj in net for net in ALLOWED_NETWORKS)
                except ValueError:
                    allowed = False

            if not allowed:
                if scope["type"] == "http":
                    await send({
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [(b"content-type", b"text/plain")],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": b"Forbidden",
                    })
                elif scope["type"] == "websocket":
                    await send({
                        "type": "websocket.close",
                        "code": 1008
                    })
                return

        await self.app(scope, receive, send)

app = FastAPI(
    debug=DEBUG,
    redoc_url=None,
    lifespan=lifespan,
    docs_url="/api/docs",
    title="Firegex API",
    version=API_VERSION,
)
app.add_middleware(IPFilterMiddleware)

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

def APP_STATUS(): return "run" if auth_disabled() or db.get("password") is not None else "init"
def JWT_SECRET(): return db.get("secret")

def _hash_psw_sync(psw: str) -> str:
    salt = secrets.token_hex(32)
    return hashlib.pbkdf2_hmac("sha256", psw.encode(), salt.encode(), 500_000).hex()+"-"+salt

async def hash_psw(psw: str) -> str:
    return await asyncio.to_thread(_hash_psw_sync, psw)

def _verify_psw_sync(psw: str, hashed: str) -> bool:
    try:
        psw_hash, salt = hashed.split("-")
    except (ValueError, AttributeError):
        return False
    new_hashed = hashlib.pbkdf2_hmac("sha256", psw.encode(), salt.encode(), 500_000).hex()
    # Constant-time comparison to avoid leaking hash-match progress via timing.
    return hmac.compare_digest(new_hashed, psw_hash)

async def verify_psw(psw: str, hashed: str) -> bool:
    return await asyncio.to_thread(_verify_psw_sync, psw, hashed)

async def set_psw(psw: str):
    db.put("password", await hash_psw(psw))

def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET(), algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def refresh_frontend(additional:list[str]=[]):
    await socketio_emit([]+additional)

def token_is_valid(token: str | None) -> bool:
    """Was this token issued by this instance to somebody who logged in?

    Separate from `check_login` because one caller needs the question without the
    "authentication is off, so yes" that `check_login` answers first: turning
    authentication back on has to be asked by somebody who was an administrator *before*
    it was turned off, and while it is off nothing new is signed — `/api/login` and
    `/api/set-password` both refuse — so a valid token is exactly that proof.
    """
    if not token:
        return False
    try:
        payload = jwt.decode(token, JWT_SECRET(), algorithms=[JWT_ALGORITHM])
    except Exception:
        return False
    return bool(payload.get("logged_in"))


async def check_login(token: str = Depends(oauth2_scheme)):
    if auth_disabled():
        return True
    return token_is_valid(token)

@utils.socketio.on("connect")
async def sio_connect(sid, environ, auth):
    if not auth_disabled() and (not auth or not await check_login(auth.get("token"))):
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
        "version": API_VERSION,
        "auth_disabled": auth_disabled()
    }

@app.post("/api/login")
async def login_api(form: OAuth2PasswordRequestForm = Depends()):
    """Get a login token to use the firegex api"""
    if auth_disabled():
        raise HTTPException(status_code=403, detail=AUTH_DISABLED_DETAIL)
    if APP_STATUS() != "run":
        raise HTTPException(status_code=400)
    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    await asyncio.sleep(0.3) # No bruteforce :)
    if await verify_psw(form.password, db.get("password")):
        return {"access_token": create_access_token({"logged_in": True}), "token_type": "bearer"}
    raise HTTPException(406,"Wrong password!")


@app.post('/api/set-password', response_model=ChangePasswordModel)
async def set_password(form: PasswordForm):
    """Set the password of firegex"""
    if auth_disabled():
        raise HTTPException(status_code=403, detail=AUTH_DISABLED_DETAIL)
    if APP_STATUS() != "init":
        raise HTTPException(status_code=400)
    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    await set_psw(form.password)
    await refresh_frontend()
    return {"status":"ok", "access_token": create_access_token({"logged_in": True})}

@api.post('/change-password', response_model=ChangePasswordModel)
async def change_password(form: PasswordChangeForm):
    """Change the password of firegex"""
    if auth_disabled():
        raise HTTPException(status_code=403, detail=AUTH_DISABLED_DETAIL)
    if APP_STATUS() != "run":
        raise HTTPException(status_code=400)

    if form.password == "":
        return {"status":"Cannot insert an empty password!"}
    if form.expire:
        db.put("secret", secrets.token_hex(32))
        await disconnect_all()
    
    await set_psw(form.password)
    await refresh_frontend()
    return {"status":"ok", "access_token": create_access_token({"logged_in": True})}


@api.post('/auth-mode', response_model=StatusMessageModel)
async def set_auth_mode(form: AuthModeForm, token: str = Depends(oauth2_scheme)):
    """Turn authentication off on a running instance, and back on.

    **Off** is a thing an administrator can decide: it hands access control to whatever
    sits in front of firegex, which is a deployment choice rather than an escalation, and
    the caller has just proved they are the administrator.

    **On** is asked for differently, because while authentication is off every request
    reaching firegex is already a full administrator — an anonymous caller could turn it
    back on with a password of their own and keep the real operator out for good, which
    is a lasting foothold and not merely the vandalism the mode already allows. So it
    takes a token this instance signed *before* it was turned off. Nothing new is signed
    while it is off (`/api/login` and `/api/set-password` both refuse), so holding one is
    exactly the proof that is wanted, and the operator who turned it off still has theirs.
    Whoever does not can do it from the host, where being able to ask is its own proof:
    `run.py config --no-unsafe-disable-auth`.

    Either way it lasts as long as the process, because the environment is what firegex
    comes up with. `run.py config --[no-]unsafe-disable-auth` writes here *and* persists
    the choice, which is how it survives a restart.
    """
    if form.disabled == auth_disabled():
        return {"status": "ok"}
    if not form.disabled and not token_is_valid(token):
        raise HTTPException(
            status_code=403,
            detail="Turning authentication back on takes a session from before it was "
                   "turned off, or the host: 'python3 run.py config --no-unsafe-disable-auth'",
        )
    if not form.disabled and db.get("password") is None:
        # Otherwise the instance comes back up asking any passer-by to choose the password.
        raise HTTPException(
            status_code=400,
            detail="There is no password to ask for. Set one first, from the host, with "
                   "'python3 run.py config --password'",
        )
    db.put("auth_disabled", "1" if form.disabled else "0")
    # The sockets were authorised under the rule that has just changed. Dropping them is
    # what makes every browser ask again, which is the only way they find out.
    await disconnect_all()
    await refresh_frontend()
    return {"status": "ok"}


@api.get('/interfaces', response_model=list[IpInterface])
async def get_ip_interfaces():
    """Get a list of ip and ip6 interfaces"""
    return get_interfaces()

#Routers Loader
reset, startup, shutdown = load_routers(api)

def seed_auth_mode():
    """Decide at boot whether authentication is on.

    Three writers, and a boot has to take the right one. `run.py start/restart` says it
    in the environment of a container it has just created. `run.py config` says it on the
    running instance and in `.firegex-conf.json` — but a container's environment is fixed
    when it is created, so a container Docker started again by itself (a reboot, a daemon
    restart, a crash under `restart: unless-stopped`) came back up with the value it was
    created with. Authentication re-enabled with `run.py config --password` was off again
    after the next reboot, while `config --show` went on saying it was on.

    So `run.py config` also writes what it decided under `AUTH_HOST_KEY`, and a boot that
    is not fresh takes that over its stale environment. A fresh one — a container `run.py`
    has just created from the current configuration — takes the environment, which already
    says the same thing, and clears the key. What the interface sets (`/api/auth-mode`)
    writes neither, so it lasts as long as the process, as it says it does.
    """
    disabled, keep_held = boot_auth_mode(db.get(AUTH_HOST_KEY), FRESH_BOOT,
                                         UNSAFE_DISABLE_AUTH_ENV)
    db.put("auth_disabled", "1" if disabled else "0")
    if not keep_held:
        db.query("DELETE FROM keys_values WHERE key = ?;", AUTH_HOST_KEY)


async def startup_main(seed_auth: bool = True):
    db.init()
    # Only when a process is starting. An import restarts the application state without
    # anything about the deployment having changed, and re-deciding here opened a window —
    # the length of every service's start — in which a container booted without
    # authentication answered everybody as an administrator, whatever it had been set to.
    if seed_auth:
        seed_auth_mode()
    if os.getenv("PSW_HASH_SET"):
        db.put("password", os.getenv("PSW_HASH_SET"))
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

@api.get('/export')
async def export_db():
    """Export all configuration databases as JSON"""
    dbs = {}
    if not os.path.exists('db'):
        return dbs
    for f in os.listdir('db'):
        if f.endswith('.db'):
            temp_db = SQLite(os.path.join('db', f))
            dbs[f] = temp_db.dump()
            
    # Export the user's own filter code
    if os.path.exists('db/service_filters'):
        dbs['service_filters'] = {}
        for f in os.listdir('db/service_filters'):
            if f.endswith('.py'):
                with open(os.path.join('db/service_filters', f), 'rb') as script_file:
                    dbs['service_filters'][f] = base64.b64encode(script_file.read()).decode('utf-8')
    return dbs

# The charset a backup entry's name has to satisfy lives in `utils`, beside `safe_join`:
# the two are one defence in two halves — what a name may contain, and where it may land.

@api.post('/import', response_model=StatusMessageModel)
async def import_db(data: dict):
    """Import all configuration databases from JSON"""
    # Validate the ENTIRE payload before touching any file, so a malformed or
    # malicious backup is rejected atomically instead of being half-applied.
    db_imports = []       # (destination path, dump dict)
    filter_imports = []   # (destination path, decoded bytes)

    for key, value in data.items():
        if not isinstance(key, str):
            raise HTTPException(status_code=400, detail="Invalid backup: keys must be strings")
        if SAFE_DB_NAME.fullmatch(key):
            if not isinstance(value, dict):
                raise HTTPException(status_code=400, detail=f"Invalid backup: '{key}' must be an object")
            # safe_join is defense-in-depth on top of the regex: it rejects any
            # path that would resolve outside the db/ directory.
            db_imports.append((safe_join('db', key), value))
        elif key == 'service_filters':
            if not isinstance(value, dict):
                raise HTTPException(status_code=400, detail="Invalid backup: 'service_filters' must be an object")
            for fname, script_content in value.items():
                if not isinstance(fname, str) or not SAFE_PY_NAME.fullmatch(fname):
                    raise HTTPException(status_code=400, detail=f"Invalid backup: illegal filter filename '{fname}'")
                if not isinstance(script_content, str):
                    raise HTTPException(status_code=400, detail=f"Invalid backup: filter '{fname}' must be a base64 string")
                try:
                    decoded = base64.b64decode(script_content, validate=True)
                except ValueError:
                    raise HTTPException(status_code=400, detail=f"Invalid backup: filter '{fname}' is not valid base64")
                filter_imports.append((safe_join('db/service_filters', fname), decoded))
        else:
            raise HTTPException(status_code=400, detail=f"Invalid backup: unexpected entry '{key}'")

    if not os.path.exists('db'):
        os.makedirs('db')

    # Backups never contain the password, the secret or the auth mode (export_db strips
    # them), so preserve this instance's own values instead of losing them on import.
    kept = {key: db.get(key) for key in ("password", "secret", "auth_disabled", AUTH_HOST_KEY)}

    for db_path, db_data in db_imports:
        temp_db = SQLite(str(db_path))
        # Load into the existing schema; SQLite.load only writes to tables/columns
        # that actually exist, so unknown fields in the backup are ignored.
        temp_db.load(db_data)

    if filter_imports:
        os.makedirs('db/service_filters', exist_ok=True)
        for filter_path, decoded in filter_imports:
            with open(filter_path, 'wb') as script_file:
                script_file.write(decoded)

    for key, value in kept.items():
        if value is not None:
            db.put(key, value)

    # Restart the application state, without re-deciding authentication: nothing about the
    # deployment changed, and deciding again from the environment is what a boot does.
    await shutdown_main()
    await startup_main(seed_auth=False)
    # And once more after it, in case the restart recreated the database under an older
    # schema and took the values with it.
    for key, value in kept.items():
        if value is not None and db.get(key) != value:
            db.put(key, value)

    return {'status': 'ok'}

app.include_router(api)
frontend_deploy(app)

if __name__ == '__main__':
    # os.environ {PORT = Backend Port (Main Port), F_PORT = Frontend Port}
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    uvicorn.run(
        "app:app",
        # None allows to bind also on ipv6, and is selected if FIREGEX_HOST is any
        host="" if FIREGEX_HOST == "any" else FIREGEX_HOST,
        port=FIREGEX_PORT,
        uds=FIREGEX_SOCKET,
        reload=DEBUG and not NORELOAD,
        access_log=True,
        workers=1, # Firewall module can't be replicated in multiple workers
    )
