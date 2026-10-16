import re
import sqlite3
import traceback
from fastapi import APIRouter, HTTPException
from utils.sqlite import SQLite
from utils import ip_parse, ip_family, socketio_emit
from utils.models import ResetRequest, StatusMessageModel
from modules.firewall.nftables import FiregexTables
from modules.firewall.firewall import FirewallManager
from modules.firewall.models import FirewallSettings, RuleInfo, RuleModel, RuleFormAdd, Mode, Table
        
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
        "CREATE UNIQUE INDEX IF NOT EXISTS unique_rules ON rules (proto, src, dst, port_src_from, port_src_to, port_dst_from, port_dst_to, mode, `table`);"
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
    firewall.stop_watching()
    if not firewall.keep_rules:
        await firewall.close()
    db.disconnect()

async def refresh_frontend(additional:list[str]=[]):
    await socketio_emit(["firewall"]+additional)

async def apply_changes(undo=None):
    """Put what the database now says into the kernel, or put the database back.

    `undo` restores what was stored before the change. nft refusing the new firewall
    leaves the old one in force (`FiregexTables.set` sends it as one batch), so the
    database has to follow: kept, the refused configuration would be what the watcher
    tries to put back every few seconds and what the next boot comes up with — failing
    each time, with no firewall behind it.
    """
    try:
        await firewall.reload()
    except Exception as e:
        if undo is None:
            raise
        undo()
        try:
            await firewall.reload()
        except Exception:
            traceback.print_exc()
        raise HTTPException(
            status_code=400,
            detail=f"nftables refused the new firewall, so nothing was changed: {e}",
        )
    await refresh_frontend()
    return {'status': 'ok'}


@app.get("/settings", response_model=FirewallSettings)
async def get_settings():
    """Get the firewall settings"""
    return firewall.settings

@app.put("/settings", response_model=StatusMessageModel)
async def set_settings(form: FirewallSettings):
    """Set the firewall settings"""
    before = firewall.settings
    firewall.settings = form

    def undo():
        firewall.settings = before

    return await apply_changes(undo)

@app.get('/rules', response_model=RuleInfo)
async def get_rule_list():
    """Get the list of existent firegex rules"""
    return {
        "policy": firewall.policy,
        "rules": db.query("SELECT active, name, proto, src, dst, port_src_from, port_dst_from, port_src_to, port_dst_to, action, mode, `table` FROM rules ORDER BY rule_id;"),
        "enabled": firewall.enabled
    }

@app.post('/enable', response_model=StatusMessageModel)
async def enable_firewall():
    """Request enabling the firewall"""
    was = firewall.enabled
    firewall.enabled = True

    def undo():
        firewall.enabled = was

    return await apply_changes(undo)

@app.post('/disable', response_model=StatusMessageModel)
async def disable_firewall():
    """Request disabling the firewall"""
    firewall.enabled = False
    return await apply_changes()

#: What an address field may hold when it is not an address: an interface name, as the
#: kernel takes one, or one ending in `*` to match every interface starting that way
#: (`br-*`). Fifteen characters at most, which is what `IFNAMSIZ` leaves for the name.
#:
#: Anything else used to be stored on the strength of containing no `/`, and nft then
#: refused the whole firewall over it — a name one character too long, or with a quote in
#: it, was enough to take every rule down, the policy with them.
INTERFACE = re.compile(r"[A-Za-z0-9_.:-]{1,15}|[A-Za-z0-9_.:-]{0,14}\*")

def _address_or_interface(value: str, what: str) -> tuple[str, bool]:
    """`value` normalised, and whether it is an IP address rather than an interface."""
    value = (value or "").strip()
    if value == "":
        return value, False
    try:
        return ip_parse(value), True
    except ValueError:
        pass
    if not INTERFACE.fullmatch(value):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {what} address {value!r}: it is neither an IP address nor an "
                   f"interface name (at most 15 letters, digits and '_.:-', optionally "
                   f"ending in '*')",
        )
    return value, False

def parse_and_check_rule(rule:RuleModel):
    
    if rule.table == Table.MANGLE and rule.mode == Mode.FORWARD:
        raise HTTPException(status_code=400, detail="Mangle table does not support forward mode")
    
    rule.src, is_src_ip = _address_or_interface(rule.src, "source")
    rule.dst, is_dst_ip = _address_or_interface(rule.dst, "destination")
    
    if is_src_ip and is_dst_ip and ip_family(rule.dst) != ip_family(rule.src):
        raise HTTPException(status_code=400, detail="Destination and source addresses must be of the same family")
    
    rule.port_dst_from, rule.port_dst_to = min(rule.port_dst_from, rule.port_dst_to), max(rule.port_dst_from, rule.port_dst_to)
    rule.port_src_from, rule.port_src_to = min(rule.port_src_from, rule.port_src_to), max(rule.port_src_from, rule.port_src_to)

    return rule

RULE_COLUMNS = ("active", "name", "proto", "src", "dst", "port_src_from", "port_dst_from",
                "port_src_to", "port_dst_to", "action", "mode", "`table`")

def _write_rules(rows: list[dict]) -> None:
    """Replace every stored rule with `rows`, in order, in one transaction."""
    db.queries(["DELETE FROM rules"] + [
        (
            f"INSERT INTO rules (rule_id, {', '.join(RULE_COLUMNS)}) "
            f"VALUES (?, {', '.join('?' for _ in RULE_COLUMNS)})",
            rid, *(row[column.strip('`')] for column in RULE_COLUMNS),
        )
        for rid, row in enumerate(rows)
    ])

@app.post('/rules', response_model=StatusMessageModel)
async def add_new_service(form: RuleFormAdd):
    """Edit rule table"""
    rules = [parse_and_check_rule(ele) for ele in form.rules]
    before = db.query(f"SELECT {', '.join(RULE_COLUMNS)} FROM rules ORDER BY rule_id;")
    policy_before = firewall.policy
    try:
        _write_rules([
            {
                "active": ele.active, "name": ele.name, "proto": ele.proto,
                "src": ele.src, "dst": ele.dst,
                "port_src_from": ele.port_src_from, "port_dst_from": ele.port_dst_from,
                "port_src_to": ele.port_src_to, "port_dst_to": ele.port_dst_to,
                "action": ele.action, "mode": ele.mode, "table": ele.table,
            }
            for ele in rules
        ])
        firewall.policy = form.policy.value
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Error saving the rules: maybe there are duplicated rules")

    def undo():
        _write_rules(before)
        firewall.policy = policy_before

    return await apply_changes(undo)
