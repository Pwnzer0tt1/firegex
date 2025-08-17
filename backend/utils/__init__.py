import asyncio
from ipaddress import ip_address, ip_interface
import os
import socket
import psutil
import sys
import nftables
from socketio import AsyncServer
from fastapi import Path
from typing import Annotated
from functools import wraps
from pydantic import BaseModel, ValidationError
import traceback
from utils.models import StatusMessageModel
from typing import List

LOCALHOST_IP = socket.gethostbyname(os.getenv("LOCALHOST_IP","127.0.0.1"))

socketio:AsyncServer = None
sid_list:set = set()

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ROUTERS_DIR = os.path.join(ROOT_DIR,"routers")
ON_DOCKER = "DOCKER" in sys.argv
DEBUG = "DEBUG" in sys.argv
NORELOAD = "NORELOAD" in sys.argv
FIREGEX_PORT = int(os.getenv("PORT","4444"))
FIREGEX_HOST = os.getenv("HOST","0.0.0.0")
JWT_ALGORITHM: str = "HS256"
API_VERSION = "{{VERSION_PLACEHOLDER}}" if "{" not in "{{VERSION_PLACEHOLDER}}" else "0.0.0"

PortType = Annotated[int, Path(gt=0, lt=65536)]   

async def run_func(func, *args, **kwargs):
    if asyncio.iscoroutinefunction(func): 
        return await func(*args, **kwargs)
    else: 
        return func(*args, **kwargs)

async def socketio_emit(elements:list[str]):
    await socketio.emit("update",elements)

def refactor_name(name:str):
    name = name.strip()
    while "  " in name:
        name = name.replace("  "," ")
    return name

class SysctlManager:
    def __init__(self, ctl_table):
        self.old_table = {}
        self.new_table = {}
        if os.path.isdir("/sys_host/"):
            self.old_table = dict()
            self.new_table = dict(ctl_table)
            for name in ctl_table.keys():
                self.old_table[name] = read_sysctl(name)
    
    def write_table(self, table) -> bool:
        for name, value in table.items():
            if read_sysctl(name) != value:
                write_sysctl(name, value)
                
    def set(self):
        self.write_table(self.new_table)

    def reset(self):
        self.write_table(self.old_table)

def read_sysctl(name:str):
    with open(f"/sys_host/{name}", "rt") as f:
        return "1" in f.read()

def write_sysctl(name:str, value:bool):
    with open(f"/sys_host/{name}", "wt") as f:
        f.write("1" if value else "0")

def list_files(mypath):
    from os import listdir
    from os.path import isfile, join
    return [f for f in listdir(mypath) if isfile(join(mypath, f))]

def ip_parse(ip:str):
    return str(ip_interface(ip).network)

def is_ip_parse(ip:str):
    try:
        ip_parse(ip)
        return True
    except Exception:
        return False

def addr_parse(ip:str):
    return str(ip_address(ip))

def ip_family(ip:str):
    return "ip6" if ip_interface(ip).version == 6 else "ip"

def get_interfaces():
    def _get_interfaces():
        for int_name, interfs in psutil.net_if_addrs().items():
            for interf in interfs:
                if interf.family in [socket.AF_INET, socket.AF_INET6]:
                    yield {"name": int_name, "addr":interf.address}
    return list(_get_interfaces())

def nftables_int_to_json(ip_int):
    ip_int = ip_parse(ip_int)
    ip_addr = str(ip_int).split("/")[0]
    ip_addr_cidr = int(str(ip_int).split("/")[1])
    return {"prefix": {"addr": ip_addr, "len": ip_addr_cidr}}

def nftables_json_to_int(ip_json_int):
    if isinstance(ip_json_int,str):
        return str(ip_parse(ip_json_int))
    else:
        return f'{ip_json_int["prefix"]["addr"]}/{ip_json_int["prefix"]["len"]}'
    
class Singleton(object):
    __instance = None
    def __new__(class_, *args, **kwargs):
        if not isinstance(class_.__instance, class_):
            class_.__instance = object.__new__(class_, *args, **kwargs)
        return class_.__instance

class NFTableManager(Singleton):
    
    table_name = "firegex"
    
    def __init__(self, init_cmd, reset_cmd):
        self.__init_cmds = init_cmd
        self.__reset_cmds = reset_cmd
        self.nft = nftables.Nftables()
    
    def raw_cmd(self, *cmds):
        return self.nft.json_cmd({"nftables": list(cmds)})

    def cmd(self, *cmds):
        code, out, err = self.raw_cmd(*cmds)
        if code == 0:
            return out
        else:
            raise Exception(err)
    
    def init(self):
        self.reset()
        self.raw_cmd({"add":{"table":{"name":self.table_name,"family":"inet"}}})
        self.cmd(*self.__init_cmds)
            
    def reset(self):
        self.raw_cmd(*self.__reset_cmds)

    def list_rules(self, tables = None, chains = None):
        for filter in [ele["rule"] for ele in self.raw_list() if "rule" in ele ]:
            if tables and filter["table"] not in tables:
                continue
            if chains and filter["chain"] not in chains:
                continue
            yield filter
    
    def raw_list(self):
        return self.cmd({"list": {"ruleset": None}})["nftables"]

def _json_like(obj: BaseModel|List[BaseModel], unset=False, convert_keys:dict[str, str]=None, exclude:list[str]=None, mode:str="json"):
    res = obj.model_dump(mode=mode, exclude_unset=not unset)
    if convert_keys:
        for from_k, to_k in convert_keys.items():
            if from_k in res:
                res[to_k] = res.pop(from_k)
    if exclude:
        for ele in exclude:
            if ele in res:
                del res[ele]
    return res

def json_like(obj: BaseModel|List[BaseModel], unset=False, convert_keys:dict[str, str]=None, exclude:list[str]=None, mode:str="json") -> dict:
    if isinstance(obj, list):
        return [_json_like(ele, unset=unset, convert_keys=convert_keys, exclude=exclude, mode=mode) for ele in obj]
    return _json_like(obj, unset=unset, convert_keys=convert_keys, exclude=exclude, mode=mode)

def register_event(sio_server: AsyncServer, event_name: str, model: BaseModel, response_model: BaseModel|None = None):
    def decorator(func):
        @sio_server.on(event_name)  # Automatically registers the event
        @wraps(func)
        async def wrapper(sid, data):
            try:
                # Parse and validate incoming data
                parsed_data = model.model_validate(data)
            except ValidationError:
                return json_like(StatusMessageModel(status=f"Invalid {event_name} request"))
            
            # Call the original function with the parsed data
            result = await func(sid, parsed_data)
            # If a response model is provided, validate the output
            if response_model:
                try:
                    parsed_result = response_model.model_validate(result)
                except ValidationError:
                    traceback.print_exc()
                    return json_like(StatusMessageModel(status=f"SERVER ERROR: Invalid {event_name} response"))
            else:
                parsed_result = result
            # Emit the validated result
            if parsed_result:
                if isinstance(parsed_result, BaseModel):
                    return json_like(parsed_result)
                return parsed_result
        return wrapper
    return decorator

def nicenessify(priority:int, pid:int|None=None):
    try:
        pid = os.getpid() if pid is None else pid
        ps = psutil.Process(pid)
        if os.name == 'posix':
            ps.nice(priority)
    except Exception as e:
        print(f"Error setting priority: {e} {traceback.format_exc()}")
        pass
