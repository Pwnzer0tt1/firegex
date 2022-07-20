import asyncio
from ipaddress import ip_interface
import os, socket, secrets, psutil
import sys
from fastapi_socketio import SocketManager

LOCALHOST_IP = socket.gethostbyname(os.getenv("LOCALHOST_IP","127.0.0.1"))

socketio:SocketManager = None

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ROUTERS_DIR = os.path.join(ROOT_DIR,"routers")
ON_DOCKER = len(sys.argv) > 1 and sys.argv[1] == "DOCKER"
DEBUG = len(sys.argv) > 1 and sys.argv[1] == "DEBUG"
FIREGEX_PORT = int(os.getenv("PORT","4444"))
JWT_ALGORITHM: str = "HS256"
API_VERSION = "2.0.0"

async def run_func(func, *args, **kwargs):
    if asyncio.iscoroutinefunction(func): 
        return await func(*args, **kwargs)
    else: 
        return func(*args, **kwargs)

async def refresh_frontend():
    await socketio.emit("update","Refresh")

def refactor_name(name:str):
    name = name.strip()
    while "  " in name: name = name.replace("  "," ")
    return name

def gen_service_id(db):
    while True:
        res = secrets.token_hex(8)
        if len(db.query('SELECT 1 FROM services WHERE service_id = ?;', res)) == 0:
            break
    return res

def list_files(mypath):
    from os import listdir
    from os.path import isfile, join
    return [f for f in listdir(mypath) if isfile(join(mypath, f))]

def ip_parse(ip:str):
    return str(ip_interface(ip).network)

def ip_family(ip:str):
    return "ip6" if ip_interface(ip).version == 6 else "ip"

def get_interfaces():
    def _get_interfaces():
        for int_name, interfs in psutil.net_if_addrs().items():
            for interf in interfs:
                if interf.family in [socket.AF_INET, socket.AF_INET6]:
                    yield {"name": int_name, "addr":interf.address}
    return list(_get_interfaces())