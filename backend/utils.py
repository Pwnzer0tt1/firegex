from ipaddress import ip_interface
import os, socket, secrets, psutil

LOCALHOST_IP = socket.gethostbyname(os.getenv("LOCALHOST_IP","127.0.0.1"))

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