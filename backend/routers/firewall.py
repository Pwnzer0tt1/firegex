import sqlite3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from utils.sqlite import SQLite
from utils import ip_parse, ip_family, refactor_name, refresh_frontend, PortType
from utils.models import ResetRequest, StatusMessageModel
from modules.firewall.nftables import FiregexTables
from modules.firewall.firewall import FirewallManager

class RuleModel(BaseModel):
    active: bool
    name: str
    proto: str
    ip_src: str
    ip_dst: str
    port_src_from: PortType
    port_dst_from: PortType
    port_src_to: PortType
    port_dst_to: PortType
    action: str
    mode:str

class RuleFormAdd(BaseModel):
    rules: list[RuleModel]
    policy: str
    
class RuleInfo(BaseModel):
    rules: list[RuleModel]
    policy: str
    enabled: bool

class RuleAddResponse(BaseModel):
    status:str|list[dict]

class RenameForm(BaseModel):
    name:str

app = APIRouter()

db = SQLite('db/firewall-rules.db', {
    'rules': {
        'rule_id': 'INT PRIMARY KEY CHECK (rule_id >= 0)',
        'mode': 'VARCHAR(1) NOT NULL CHECK (mode IN ("O", "I"))', # O = out, I = in, B = both
        'name': 'VARCHAR(100) NOT NULL',
        'active' : 'BOOLEAN NOT NULL CHECK (active IN (0, 1))',
        'proto': 'VARCHAR(3) NOT NULL CHECK (proto IN ("tcp", "udp", "any"))',
        'ip_src': 'VARCHAR(100) NOT NULL',
        'port_src_from': 'INT CHECK(port_src_from > 0 and port_src_from < 65536)',
        'port_src_to': 'INT CHECK(port_src_to > 0 and port_src_to < 65536 and port_src_from <= port_src_to)',
        'ip_dst': 'VARCHAR(100) NOT NULL',
        'port_dst_from': 'INT CHECK(port_dst_from > 0 and port_dst_from < 65536)',
        'port_dst_to': 'INT CHECK(port_dst_to > 0 and port_dst_to < 65536 and port_dst_from <= port_dst_to)',
        'action': 'VARCHAR(10) NOT NULL CHECK (action IN ("accept", "drop", "reject"))',
    },
    'QUERY':[
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_rules ON rules (proto, ip_src, ip_dst, port_src_from, port_src_to, port_dst_from, port_dst_to, mode);"
    ]
})

firewall = FirewallManager(db)

async def reset(params: ResetRequest):
    if not params.delete: 
        db.backup()
    await firewall.close()
    FiregexTables().reset()
    if params.delete:
        db.delete()
        db.init()
    else:
        db.restore()
    await firewall.init()
    

async def startup():
    db.init()
    await firewall.init()

async def shutdown():
    db.backup()
    await firewall.close()
    db.disconnect()
    db.restore()

async def apply_changes():
    await firewall.reload()
    await refresh_frontend()
    return {'status': 'ok'}

@app.get('/rules', response_model=RuleInfo)
async def get_rule_list():
    """Get the list of existent firegex rules"""
    return {
        "policy": db.get("POLICY", "accept"),
        "rules": db.query("SELECT active, name, proto, ip_src, ip_dst, port_src_from, port_dst_from, port_src_to, port_dst_to, action, mode FROM rules ORDER BY rule_id;"),
        "enabled": db.get("ENABLED", "0") == "1"
    }

@app.get('/enable', response_model=StatusMessageModel)
async def enable_firewall():
    """Request enabling the firewall"""
    db.set("ENABLED", "1")
    return await apply_changes()

@app.get('/disable', response_model=StatusMessageModel)
async def disable_firewall():
    """Request disabling the firewall"""
    db.set("ENABLED", "0")
    return await apply_changes()

def parse_and_check_rule(rule:RuleModel):
    
    if rule.ip_src.lower().strip() == "any" or rule.ip_dst.lower().split() == "any":
        rule.ip_dst = rule.ip_src = "any"
    else:
        try:
            rule.ip_src = ip_parse(rule.ip_src)
            rule.ip_dst = ip_parse(rule.ip_dst)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid address")
        if ip_family(rule.ip_dst) != ip_family(rule.ip_src):
            raise HTTPException(status_code=400, detail="Destination and source addresses must be of the same family")
    
    rule.port_dst_from, rule.port_dst_to = min(rule.port_dst_from, rule.port_dst_to), max(rule.port_dst_from, rule.port_dst_to)
    rule.port_src_from, rule.port_src_to = min(rule.port_src_from, rule.port_src_to), max(rule.port_src_from, rule.port_src_to)

    if rule.proto not in ["tcp", "udp", "any"]:
        raise HTTPException(status_code=400, detail="Invalid protocol")
    if rule.action not in ["accept", "drop", "reject"]:
        raise HTTPException(status_code=400, detail="Invalid action")
    return rule

@app.post('/rules/set', response_model=RuleAddResponse)
async def add_new_service(form: RuleFormAdd):
    """Add a new service"""
    if form.policy not in ["accept", "drop", "reject"]:
        raise HTTPException(status_code=400, detail="Invalid policy")
    rules = [parse_and_check_rule(ele) for ele in form.rules]
    errors = [({"rule":i} | ele) for i, ele in enumerate(rules) if isinstance(ele, dict)]
    if len(errors) > 0:
        return {'status': errors}
    try:
        db.queries(["DELETE FROM rules"]+
            [("""
              INSERT INTO rules (
                  rule_id, active, name,
                  proto,
                  ip_src, ip_dst,
                  port_src_from, port_dst_from,
                  port_src_to, port_dst_to,
                  action, mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ? ,?, ?)""",
                rid, ele.active, ele.name,
                ele.proto,
                ele.ip_src, ele.ip_dst,
                ele.port_src_from, ele.port_dst_from,
                ele.port_src_to, ele.port_dst_to,
                ele.action, ele.mode
            ) for rid, ele in enumerate(rules)]
        )
        db.set("POLICY", form.policy)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Error saving the rules: maybe there are duplicated rules")
    return await apply_changes()
