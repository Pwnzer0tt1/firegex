import sqlite3
from fastapi import APIRouter, HTTPException
from utils.sqlite import SQLite
from utils import ip_parse, ip_family, socketio_emit
from utils.models import ResetRequest, StatusMessageModel
from modules.firewall.nftables import FiregexTables
from modules.firewall.firewall import FirewallManager
from modules.firewall.models import *
        
db = SQLite('db/firewall-rules.db', {
    'rules': {
        'rule_id': 'INT PRIMARY KEY CHECK (rule_id >= 0)',
        'mode': 'VARCHAR(10) NOT NULL CHECK (mode IN ("in", "out", "forward"))',
        '`table`': 'VARCHAR(10) NOT NULL CHECK (`table` IN ("filter", "mangle", "raw"))',
        'name': 'VARCHAR(100) NOT NULL',
        'active' : 'BOOLEAN NOT NULL CHECK (active IN (0, 1))',
        'proto': 'VARCHAR(10) NOT NULL CHECK (proto IN ("tcp", "udp", "both", "any"))',
        'src': 'VARCHAR(100) NOT NULL',
        'port_src_from': 'INT CHECK(port_src_from > 0 and port_src_from < 65536)',
        'port_src_to': 'INT CHECK(port_src_to > 0 and port_src_to < 65536 and port_src_from <= port_src_to)',
        'dst': 'VARCHAR(100) NOT NULL',
        'port_dst_from': 'INT CHECK(port_dst_from > 0 and port_dst_from < 65536)',
        'port_dst_to': 'INT CHECK(port_dst_to > 0 and port_dst_to < 65536 and port_dst_from <= port_dst_to)',
        'action': 'VARCHAR(10) NOT NULL CHECK (action IN ("accept", "drop", "reject"))',
    },
    'QUERY':[
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_rules ON rules (proto, src, dst, port_src_from, port_src_to, port_dst_from, port_dst_to, mode);"
    ]
})

app = APIRouter()

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
    keep_rules = firewall.keep_rules
    db.backup()
    if not keep_rules:
        await firewall.close()
    db.disconnect()
    db.restore()

async def refresh_frontend(additional:list[str]=[]):
    await socketio_emit(["firewall"]+additional)

async def apply_changes():
    await firewall.reload()
    await refresh_frontend()
    return {'status': 'ok'}


@app.get("/settings", response_model=FirewallSettings)
async def get_settings():
    """Get the firewall settings"""
    return firewall.settings

@app.post("/settings/set", response_model=StatusMessageModel)
async def set_settings(form: FirewallSettings):
    """Set the firewall settings"""
    firewall.settings = form
    return await apply_changes()

@app.get('/rules', response_model=RuleInfo)
async def get_rule_list():
    """Get the list of existent firegex rules"""
    return {
        "policy": firewall.policy,
        "rules": db.query("SELECT active, name, proto, src, dst, port_src_from, port_dst_from, port_src_to, port_dst_to, action, mode, `table` FROM rules ORDER BY rule_id;"),
        "enabled": firewall.enabled
    }

@app.get('/enable', response_model=StatusMessageModel)
async def enable_firewall():
    """Request enabling the firewall"""
    firewall.enabled = True
    return await apply_changes()

@app.get('/disable', response_model=StatusMessageModel)
async def disable_firewall():
    """Request disabling the firewall"""
    firewall.enabled = False
    return await apply_changes()

def parse_and_check_rule(rule:RuleModel):
    
    if rule.table == Table.MANGLE and rule.mode == Mode.FORWARD:
        raise HTTPException(status_code=400, detail="Mangle table does not support forward mode")
    
    is_src_ip = is_dst_ip = True
    
    try:
        rule.src = ip_parse(rule.src)
    except ValueError:
        is_src_ip = False
    
    try:
        rule.dst = ip_parse(rule.dst)
    except ValueError:
        is_dst_ip = False
    
    if not is_src_ip and "/" in rule.src: # Slash is not allowed in ip interfaces names
        raise HTTPException(status_code=400, detail="Invalid source address")
    if not is_dst_ip and "/" in rule.dst:
        raise HTTPException(status_code=400, detail="Invalid destination address")
    
    if is_src_ip and is_dst_ip and ip_family(rule.dst) != ip_family(rule.src):
        raise HTTPException(status_code=400, detail="Destination and source addresses must be of the same family")
    
    rule.port_dst_from, rule.port_dst_to = min(rule.port_dst_from, rule.port_dst_to), max(rule.port_dst_from, rule.port_dst_to)
    rule.port_src_from, rule.port_src_to = min(rule.port_src_from, rule.port_src_to), max(rule.port_src_from, rule.port_src_to)

    return rule

@app.post('/rules/set', response_model=StatusMessageModel)
async def add_new_service(form: RuleFormAdd):
    """Add a new service"""
    rules = [parse_and_check_rule(ele) for ele in form.rules]
    try:
        db.queries(["DELETE FROM rules"]+
            [("""
              INSERT INTO rules (
                  rule_id, active, name,
                  proto,
                  src, dst,
                  port_src_from, port_dst_from,
                  port_src_to, port_dst_to,
                  action, mode, `table`
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ? ,?, ?, ?)""",
                rid, ele.active, ele.name,
                ele.proto,
                ele.src, ele.dst,
                ele.port_src_from, ele.port_dst_from,
                ele.port_src_to, ele.port_dst_to,
                ele.action, ele.mode, ele.table
            ) for rid, ele in enumerate(rules)]
        )
        firewall.policy = form.policy.value
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Error saving the rules: maybe there are duplicated rules")
    return await apply_changes()
