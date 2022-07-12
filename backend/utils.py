import os, socket, secrets

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