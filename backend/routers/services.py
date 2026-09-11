"""Services: one network layer, one ordered chain of filters on top of it.

This is the module that replaced `nfregex`, `nfproxy` and `tls`. Those were three ways
of saying the same two things — how to intercept, and what to do — with the two welded
together, so choosing regexes also chose NFQUEUE, and choosing TLS meant creating a
second object and keeping its address in step with the first.

Here a service says only where the traffic is and how to reach it. Filters are attached
to it, in an order the operator chooses, and can be added, reordered, switched off and
switched on without the service being recreated or a single connection being dropped.
"""

import base64
import binascii
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from modules.services.firewall import (
    CODE_DIR,
    FirewallManager,
    clear_code,
    read_code,
    write_code,
)
from modules.services import stats
from modules.services.logs import log_for
from modules.services.models import (KIND, L4, MODE, PROTO, STATUS, Service,
                                     TRANSPORT)
from modules.services.nftables import FiregexTables
from modules.services import transports
from modules.services.transports import PROXY_ENGINE, PYWORKER, UnsupportedChain
from utils import (
    PortType,
    ip_parse,
    is_ip_parse,
    parse_ip_or_int,
    refactor_name,
    socketio_emit,
)
from utils.models import ResetRequest, StatusMessageModel

from utils.sqlite import SQLite

app = APIRouter()

db = SQLite(
    "db/services.db",
    {
        "services": {
            "service_id": "VARCHAR(100) PRIMARY KEY",
            "name": "VARCHAR(100) NOT NULL UNIQUE",
            "status": 'VARCHAR(100) NOT NULL CHECK (status IN ("active", "stop"))',
            # What the service speaks, which is not always what the kernel matches on:
            # `tls` is TCP on the wire. The address carries the second answer.
            "proto": 'VARCHAR(4) NOT NULL CHECK (proto IN ("tcp", "udp", "tls"))',
            "transport": 'VARCHAR(20) NOT NULL CHECK (transport IN ("nfqueue", "proxy", "external"))',
            "fail_open": "BOOLEAN NOT NULL CHECK (fail_open IN (0, 1)) DEFAULT 1",
            # How many connections (or UDP flows) this service may carry at once, and
            # what happens to the next one. `0` is no limit, which is what every service
            # had before there was one — kept as a value rather than as an absence,
            # because "unlimited" is a choice an operator can make and should have to.
            "max_connections": "INTEGER NOT NULL DEFAULT 0",
            # 0: refuse what does not fit. 1: forward it with no filter in front of it.
            "over_limit_forwards": "BOOLEAN NOT NULL CHECK (over_limit_forwards IN (0, 1)) DEFAULT 0",
            # Seconds a connection may carry nothing in either direction before it is
            # closed. 0 is off. Only until the *first* byte: a session that has spoken
            # and gone quiet is a session, and sessions are allowed to think.
            "first_byte_timeout": "INTEGER NOT NULL DEFAULT 0",
            # The trace. A counter in the log would be gone with the next thousand lines,
            # and the ring the live log keeps is bounded on purpose; this survives a
            # restart, so "did we ever hit the wall" has an answer tomorrow morning.
            "over_limit_hits": "INTEGER NOT NULL DEFAULT 0",
            #: When it first happened and when it last did, unix seconds. Two instants
            #: rather than one, because "it started an hour ago and is still going" and
            #: "it happened once at 3am" are different situations.
            "over_limit_first": "INT",
            "over_limit_last": "INT",
            "tls_cert": "TEXT",
            "tls_key": "TEXT",
            # The first instant this service could refuse anything: running, with a
            # filter attached. Statistics start there rather than at the beginning of
            # retention, because the hours before a service existed are not quiet hours
            # — they are hours the question was not being asked, and drawing them as an
            # empty chart says the opposite. Never cleared once set: a service stopped
            # and started again has a real gap in the middle, and that is worth seeing.
            "filtering_since": "INT",
        },
        # Where a service is reachable. A list, because one service routinely answers on
        # more than one address — a v4 and a v6 one, a public and an internal one, two
        # ports of the same daemon — and making the operator create one service per
        # address meant keeping their filter chains in step by hand.
        "service_addresses": {
            "address_id": "VARCHAR(100) PRIMARY KEY",
            "service_id": "VARCHAR(100) NOT NULL",
            "ip_int": "VARCHAR(100) NOT NULL",
            "port": "INT NOT NULL CHECK(port > 0 and port < 65536)",
            # The transport the *kernel* sees, derived from the service's own: `tls` is
            # TCP on the wire. Kept here so `(ip, port, proto)` is a usable uniqueness
            # key — a TCP service and a UDP one may share an address exactly as the
            # kernel allows, while a TCP service and a TLS one may not, because that is
            # the same port twice.
            "proto": 'VARCHAR(3) NOT NULL CHECK (proto IN ("tcp", "udp"))',
            # Where the operator's own proxy is listening for *this* address. Only for
            # `external`; loopback when they do not say otherwise, which is where such a
            # proxy normally is.
            "proxy_ip": "VARCHAR(100)",
            "proxy_port": "INT CHECK(proxy_port IS NULL OR (proxy_port > 0 AND proxy_port < 65536))",
            "FOREIGN KEY (service_id)": "REFERENCES services (service_id)",
        },
        # The chain. `position` is what makes it ordered, and the operator sets it.
        "filters": {
            "filter_id": "VARCHAR(100) PRIMARY KEY",
            "service_id": "VARCHAR(100) NOT NULL",
            "position": "INT NOT NULL",
            "kind": 'VARCHAR(20) NOT NULL CHECK (kind IN ("regex", "pyfilter"))',
            # Only meaningful for a pyfilter, and never chosen: read off the code when
            # it is saved, and stored so the interface can show it without executing
            # anything. The code stays the only thing that decides it.
            "proto": 'VARCHAR(10) NOT NULL CHECK (proto IN ("tcp", "http")) DEFAULT "tcp"',
            "name": "VARCHAR(100) NOT NULL",
            "active": "BOOLEAN NOT NULL CHECK (active IN (0, 1)) DEFAULT 1",
            "blocked": "INTEGER UNSIGNED NOT NULL DEFAULT 0",
            "FOREIGN KEY (service_id)": "REFERENCES services (service_id)",
        },
        # One row per `@pyfilter` function a filter's code defines. Derived from the
        # code and reconciled with it every time the code is saved — the function list
        # is the file's to decide — but `active` and `blocked` are the operator's, and
        # survive an edit that leaves the function in place. Turning a function off is
        # how you stop consulting it without deleting the code that defines it.
        "pyfilters": {
            "filter_id": "VARCHAR(100) NOT NULL",
            "name": "VARCHAR(100) NOT NULL",
            "active": "BOOLEAN NOT NULL CHECK (active IN (0, 1)) DEFAULT 1",
            "blocked": "INTEGER UNSIGNED NOT NULL DEFAULT 0",
            # Where the function sits in its file. The library runs them in definition
            # order, so listing them in any other order — this was `ORDER BY name`, and
            # before that the run order itself was a set's — shows the operator a
            # sequence that is not the one deciding their traffic.
            "position": "INTEGER NOT NULL DEFAULT 0",
            "FOREIGN KEY (filter_id)": "REFERENCES filters (filter_id)",
        },
        # The patterns inside one regex filter. They are compiled together into a
        # single hyperscan database, which is why they belong to a filter rather than
        # each being one.
        "regexes": {
            "regex_id": "VARCHAR(100) PRIMARY KEY",
            "filter_id": "VARCHAR(100) NOT NULL",
            "regex": "TEXT NOT NULL",
            "mode": 'VARCHAR(1) NOT NULL CHECK (mode IN ("C", "S", "B"))',
            "case_sensitive": "BOOLEAN NOT NULL CHECK (case_sensitive IN (0, 1)) DEFAULT 1",
            "active": "BOOLEAN NOT NULL CHECK (active IN (0, 1)) DEFAULT 1",
            "blocked": "INTEGER UNSIGNED NOT NULL DEFAULT 0",
            "FOREIGN KEY (filter_id)": "REFERENCES filters (filter_id)",
        },
        # How much each filter refused, in fixed time buckets. Bounded and coalesced —
        # see `modules/services/stats.py`, where both properties are the point.
        "block_history": {
            "service_id": "VARCHAR(100) NOT NULL",
            "filter_id": "VARCHAR(100) NOT NULL",
            # Whatever the datapath reported: a pattern id, `<filter>/<function>`, or the
            # filter itself. Kept at this resolution so that asking for a time range
            # answers the same question everywhere on the page — the chart, the totals
            # and the shares — instead of the chart honouring it and the table beside it
            # quietly reporting all of time.
            "rule_id": "VARCHAR(200) NOT NULL",
            "bucket": "INTEGER NOT NULL",
            "blocked": "INTEGER UNSIGNED NOT NULL DEFAULT 0",
        },
        "QUERY": [
            "CREATE UNIQUE INDEX IF NOT EXISTS unique_block_bucket "
            "ON block_history (rule_id, bucket);",
            "CREATE INDEX IF NOT EXISTS block_history_by_service "
            "ON block_history (service_id, bucket);",
            "CREATE UNIQUE INDEX IF NOT EXISTS unique_service_address "
            "ON service_addresses (ip_int, port, proto);",
            # Two addresses handed to the same proxy endpoint could not be told apart on
            # the way back: the return rule recognises the operator's proxy by address
            # and port, and puts the original port back. Refusing the collision here is
            # cheaper than an intermittently wrong source port in production.
            "CREATE UNIQUE INDEX IF NOT EXISTS unique_hijack_target "
            "ON service_addresses (proxy_ip, proxy_port) WHERE proxy_port IS NOT NULL;",
            "CREATE UNIQUE INDEX IF NOT EXISTS unique_filter_position ON filters (service_id, position);",
            "CREATE UNIQUE INDEX IF NOT EXISTS unique_pyfilter ON pyfilters (filter_id, name);",
            "CREATE UNIQUE INDEX IF NOT EXISTS unique_regex ON regexes (filter_id, regex, mode, case_sensitive);",
        ],
    },
)

firewall = FirewallManager(db)


class AddressModel(BaseModel):
    address_id: str
    service_id: str
    ip_int: str
    port: PortType
    proto: str
    proxy_ip: str | None = None
    proxy_port: int | None = None


class AddressForm(BaseModel):
    ip_int: str
    port: PortType
    #: `external` only: where your own proxy listens for this address. Two addresses
    #: cannot share one — the return rule tells them apart by it.
    proxy_ip: str | None = None
    proxy_port: PortType | None = None


class ServiceModel(BaseModel):
    service_id: str
    name: str
    status: str
    proto: str
    transport: str
    fail_open: bool
    #: How many connections or UDP flows may be in flight at once; 0 means no limit.
    max_connections: int = 0
    #: Whether what does not fit is forwarded unfiltered rather than refused.
    over_limit_forwards: bool = False
    #: Seconds a connection may say nothing at all before it is closed; 0 means never.
    first_byte_timeout: int = 0
    #: How many times the limit turned something away, ever. Survives a restart, which
    #: is what makes it a trace rather than a reading.
    over_limit_hits: int = 0
    over_limit_first: int | None = None
    over_limit_last: int | None = None
    #: Whether a certificate *and* a key are stored for it. The material itself never
    #: comes back — the key deliberately, the certificate for symmetry — so this is what
    #: lets the form know whether an empty field means "unchanged" or "never set", and
    #: ask for one before the service is started rather than after the engine has refused it.
    has_tls_material: bool = False
    addresses: list[AddressModel] = []
    n_filters: int
    n_blocked: int


class ServiceAddForm(BaseModel):
    name: str
    proto: str = L4.TCP
    #: Every address to protect. At least one, and they may mix address families —
    #: one service, one chain, however many places it answers.
    addresses: list[AddressForm]
    transport: str = TRANSPORT.PROXY
    fail_open: bool = True
    max_connections: int = 0
    over_limit_forwards: bool = False
    first_byte_timeout: int = 0
    tls_cert: str | None = None
    tls_key: str | None = None


class ServiceSettingsForm(BaseModel):
    name: str | None = None
    proto: str | None = None
    transport: str | None = None
    fail_open: bool | None = None
    max_connections: int | None = None
    over_limit_forwards: bool | None = None
    first_byte_timeout: int | None = None
    tls_cert: str | None = None
    tls_key: str | None = None


class ServiceAddResponse(BaseModel):
    status: str
    service_id: str | None = None


class FilterModel(BaseModel):
    filter_id: str
    service_id: str
    position: int
    kind: str
    proto: str
    name: str
    active: bool
    blocked: int
    n_regexes: int
    #: How many `@pyfilter` functions the code defines, and how many are switched on.
    n_functions: int = 0
    n_functions_active: int = 0


class FilterAddForm(BaseModel):
    kind: str
    name: str | None = None
    active: bool = True


class FilterEditForm(BaseModel):
    name: str | None = None
    active: bool | None = None


class PyFunctionModel(BaseModel):
    filter_id: str
    #: The `@pyfilter` function's own name, as written in the code.
    name: str
    active: bool
    blocked: int


class PyFunctionEditForm(BaseModel):
    active: bool


class ReorderForm(BaseModel):
    #: Every filter of the service, in the order they should run.
    filters: list[str]


class RegexModel(BaseModel):
    regex_id: str
    filter_id: str
    regex: str
    mode: str
    case_sensitive: bool
    active: bool
    blocked: int


class RegexAddForm(BaseModel):
    regex: str
    mode: str = MODE.BOTH
    case_sensitive: bool = True
    active: bool = True


class RegexEditForm(BaseModel):
    active: bool | None = None
    #: base64, like the one on the add form: a pattern is bytes.
    regex: str | None = None
    mode: str | None = None
    case_sensitive: bool | None = None


class CodeForm(BaseModel):
    code: str


class StatsEntryModel(BaseModel):
    id: str
    name: str
    kind: str
    filter_id: str | None = None
    #: True for the one entry per filter that stands for blocks no rule still in it
    #: accounts for — a pattern deleted, or one whose text was edited and so gave its
    #: history back to the filter. `name` describes it rather than naming a rule, which
    #: is why the interface prints it as prose instead of as a pattern.
    residual: bool = False
    #: Refused in the selected range.
    blocked: int
    #: Refused since it was created. Only reported for filters, which are the only
    #: things carrying a lifetime counter of their own.
    all_time: int | None = None
    #: What share of everything this service refused is this one's doing, 0–100.
    #: Computed against the total rather than left to the browser, so every view of it
    #: agrees and a chart cannot disagree with a table beside it.
    share: float = 0.0


class TrafficModel(BaseModel):
    """How much arrived, in the units each layer can honestly report.

    Packets come from the kernel's own counters on the intercept rules, and are
    available on every network layer. Connections come from the proxy engine, which is
    the only layer that works in them — and is therefore the only one where the share
    of refused traffic can be computed without dividing two different things.
    """

    packets: int = 0
    bytes: int = 0
    connections: int | None = None
    connections_refused: int | None = None
    #: Percentage of connections refused, 0–100. Null where the layer counts packets.
    refused_share: float | None = None


class StatsSeriesModel(BaseModel):
    id: str
    name: str
    counts: list[int]


class StatsModel(BaseModel):
    filters: list[StatsEntryModel]
    patterns: list[StatsEntryModel]
    #: One entry per `@pyfilter` function, across every pyfilter in the chain.
    functions: list[StatsEntryModel]
    buckets: list[int]
    #: How wide one bucket is. Widens with the range, so a chart stays readable.
    bucket_seconds: int
    series: list[StatsSeriesModel]
    #: Refused in the selected range. Every list above counts the same range.
    total: int
    #: Refused since each rule was created, which is what the cards show. Reported
    #: alongside so a narrow range showing nothing is not read as a contradiction.
    all_time: int
    #: The range actually served, after clamping to what is still kept.
    range_from: int
    range_to: int
    #: The oldest instant anything is known about, so "everything" has a meaning.
    kept_from: int
    #: When this service first became able to refuse anything, if it ever did. The
    #: effective floor of every range, the same way `kept_from` is.
    filtering_since: int | None = None
    traffic: TrafficModel


class LogEntryModel(BaseModel):
    at: int
    level: str
    text: str
    seq: int


class DebugPatternForm(BaseModel):
    id: str
    expr: str
    case_sensitive: bool = True


class DebugForm(BaseModel):
    patterns: list[DebugPatternForm]
    #: base64, because a pattern is matched against bytes and a useful sample is not
    #: always valid text.
    sample: str


class DebugMatchModel(BaseModel):
    id: str
    start: int
    end: int


class DebugErrorModel(BaseModel):
    id: str
    error: str


class DebugResponse(BaseModel):
    matches: list[DebugMatchModel]
    errors: list[DebugErrorModel]
    error: str | None = None
    #: Valid, and will run, but cannot be highlighted here.
    unscannable: list[DebugErrorModel] = []
    #: base64: what the sample becomes, produced by the engine's own rewriting code.
    rewritten: str | None = None
    truncated: bool


# --- lifecycle hooks the loader calls ----------------------------------------


async def refresh_frontend(extra: list[str] | None = None):
    await socketio_emit(["services"] + (extra or []))


async def startup():
    db.init()
    try:
        await firewall.init()
    except Exception as e:
        print("WARNING cannot start the services firewall:", e)
    # Whatever came back up is filtering from now, if it was not already marked. This is
    # what covers the services that existed before the mark did, and the ones restored
    # from a backup: both are running with a chain the moment `init()` returns, and
    # neither passes through a start or an edit to say so.
    for row in db.query("SELECT service_id FROM services;"):
        _note_filtering(row["service_id"])


async def shutdown():
    await firewall.close()
    db.disconnect()


async def reset(params: ResetRequest):
    if not params.delete:
        db.backup()
    await firewall.close()
    FiregexTables().reset()
    if params.delete:
        db.delete()
        db.init()
        # The user's Python and the certificates are not in the database, so wiping
        # the database alone would leave them behind to be inherited by whatever
        # reuses their id.
        for name in os.listdir(CODE_DIR) if os.path.isdir(CODE_DIR) else []:
            os.remove(os.path.join(CODE_DIR, name))
    else:
        db.restore()
    try:
        await firewall.init()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def gen_id() -> str:
    return secrets.token_hex(8)


def _service_or_404(service_id: str) -> dict:
    res = db.query("SELECT * FROM services WHERE service_id = ?;", service_id)
    if not res:
        raise HTTPException(status_code=404, detail="This service does not exist")
    return res[0]


def _addresses(service_id: str) -> list[dict]:
    return db.query(
        "SELECT * FROM service_addresses WHERE service_id = ? ORDER BY ip_int, port;",
        service_id,
    )


def _address_or_404(service_id: str, address_id: str) -> dict:
    """An address is addressed through its service, and has to actually be in it."""
    res = db.query(
        "SELECT * FROM service_addresses WHERE address_id = ? AND service_id = ?;",
        address_id,
        service_id,
    )
    if not res:
        raise HTTPException(status_code=404, detail="This address does not exist")
    return res[0]


def load_service(service_id: str):
    """The service and everywhere it is reachable, as the datapath sees it."""
    from modules.services.models import Address

    row = _service_or_404(service_id)
    srv = Service.from_dict(row)
    srv.addresses = [Address.from_dict(a) for a in _addresses(service_id)]
    return srv


def _filter_or_404(service_id: str, filter_id: str) -> dict:
    """A filter is addressed through its service, and has to actually be in it.

    Without the second half of that check the nesting would be decoration: any filter
    id would work under any service, and the chain the caller thought it was editing
    would not be the one that changed.
    """
    res = db.query(
        "SELECT * FROM filters WHERE filter_id = ? AND service_id = ?;", filter_id, service_id
    )
    if not res:
        raise HTTPException(status_code=404, detail="This filter does not exist")
    return res[0]


def _regex_or_404(filter_id: str, regex_id: str) -> dict:
    res = db.query(
        "SELECT * FROM regexes WHERE regex_id = ? AND filter_id = ?;", regex_id, filter_id
    )
    if not res:
        raise HTTPException(status_code=404, detail="This pattern does not exist")
    return res[0]


def _note_filtering(service_id: str) -> None:
    """Remember the first moment this service could have refused something.

    Two things have to be true — it is running, and there is at least one active filter
    in its chain — and neither of them is where the other is changed, so this is called
    from both: starting a service, and every edit that goes through `_apply_chain`.
    Asking the database is cheaper than keeping a third copy of the answer in step.

    Written once and never rewritten. A service that stops filtering and starts again
    has a real gap in the middle of its history, and moving the mark forward would hide
    it; clearing it would make the chart claim the earlier hours never happened.
    """
    row = db.query(
        "SELECT s.filtering_since since, s.status status, "
        "(SELECT COUNT(*) FROM filters f WHERE f.service_id = s.service_id AND f.active = 1) n "
        "FROM services s WHERE s.service_id = ?;",
        service_id,
    )
    if not row or row[0]["since"] is not None:
        return
    if row[0]["status"] != STATUS.ACTIVE or int(row[0]["n"]) < 1:
        return
    # Stored aligned to its bucket, like everything else the statistics work in: the
    # mark names the first bucket that can hold one of this service's blocks. An
    # unaligned mark is a few seconds *after* the minute-aligned "now" the stats endpoint
    # compares it against, which silently switched the floor off for the first minute of
    # every service's life — exactly the minute it matters most.
    db.query(
        "UPDATE services SET filtering_since = ? WHERE service_id = ?;",
        stats.bucket_of(),
        service_id,
    )


async def _apply_chain(service_id: str, undo=None):
    """Push the chain to a running service, translating a refusal into a 400.

    A chain the transport cannot host is the operator's mistake, not the server's, and
    the message has to say which combination was impossible — an unqualified 500 would
    leave them guessing.

    `undo` puts the database back. Without it a refused edit would still have been
    written: the operator would be told their filter was rejected and then find it in
    the list, and the next start would fail for a reason they thought they had avoided.
    A refusal has to mean nothing changed.
    """
    try:
        await firewall.get(service_id).update_chain()
    except UnsupportedChain as e:
        if undo:
            undo()
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        if undo:
            undo()
        raise HTTPException(status_code=500, detail=str(e))
    _note_filtering(service_id)


# --- services ----------------------------------------------------------------

SERVICE_QUERY = """
    SELECT
        s.service_id service_id, s.name name, s.status status, s.proto proto,
        s.transport transport, s.fail_open fail_open,
        s.max_connections max_connections, s.over_limit_forwards over_limit_forwards,
        s.first_byte_timeout first_byte_timeout,
        s.over_limit_hits over_limit_hits, s.over_limit_first over_limit_first,
        s.over_limit_last over_limit_last,
        (s.tls_cert IS NOT NULL AND TRIM(s.tls_cert) != ''
         AND s.tls_key IS NOT NULL AND TRIM(s.tls_key) != '') has_tls_material,
        COUNT(DISTINCT f.filter_id) n_filters,
        COALESCE(SUM(DISTINCT f.blocked), 0) n_blocked
    FROM services s LEFT JOIN filters f ON s.service_id = f.service_id
"""


def _address_row(row: dict) -> dict:
    """One address, as it is stored.

    It used to grow two loopback ports here, because a TLS service was protected on a
    pair of them rather than on the address itself. Nothing is derived any more: the
    engine decrypts at the address the world dials.
    """
    return dict(row)


def _with_addresses(row: dict) -> dict:
    row = dict(row)
    row["addresses"] = [
        _address_row(a) for a in _addresses(row["service_id"])
    ]
    return row


@app.get("", response_model=list[ServiceModel])
async def get_services():
    """Every service, with how many filters it runs and how much they have blocked."""
    return [_with_addresses(row) for row in db.query(SERVICE_QUERY + " GROUP BY s.service_id;")]


class ApiMemberModel(BaseModel):
    name: str
    doc: str = ""
    #: True for the few things a filter may assign to — the payload, and nothing else.
    writable: bool = False
    signature: str | None = None


class ApiModelModel(BaseModel):
    name: str
    doc: str = ""
    members: list[ApiMemberModel] = []
    #: Which application protocols provide it; a file asking for one of these is one of
    #: those. `tcp` and `http` both means it runs on anything.
    protocols: list[str] = []


class ApiEntryModel(BaseModel):
    name: str
    doc: str = ""
    value: int | None = None
    values: list[str] = []


class PyFilterApiModel(BaseModel):
    models: list[ApiModelModel]
    verdicts: list[ApiEntryModel]
    settings: list[ApiEntryModel]


# Declared before `/{service_id}`, or that route matches this path and looks for a
# service called "pyfilter-api".
@app.get("/pyfilter-api", response_model=PyFilterApiModel)
async def get_pyfilter_api():
    """What the filter library offers, for the editor to suggest.

    Introspected from the library rather than written down: hints that disagree with the
    thing they describe are worse than none, and a second description would disagree the
    first time a model gained a property.
    """
    from modules.services.pyapi import describe

    return describe()


@app.get("/{service_id}", response_model=ServiceModel)
async def get_service(service_id: str):
    res = db.query(SERVICE_QUERY + " WHERE s.service_id = ? GROUP BY s.service_id;", service_id)
    if not res:
        raise HTTPException(status_code=404, detail="This service does not exist")
    return _with_addresses(res[0])


def _insert_address(service_id: str, proto: str, form: AddressForm) -> str:
    """Add one address, carrying the transport the kernel will match on.

    Not the service's own protocol: `tls` is TCP on the wire, and an address storing it
    verbatim would let a TCP service and a TLS one claim one `ip:port` between them.
    """
    try:
        parsed_ip = parse_ip_or_int(form.ip_int)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    address_id = gen_id()
    db.query(
        "INSERT INTO service_addresses (address_id, service_id, ip_int, port, proto, "
        "proxy_ip, proxy_port) VALUES (?, ?, ?, ?, ?, ?, ?);",
        address_id,
        service_id,
        parsed_ip,
        form.port,
        L4.l4_of(proto),
        form.proxy_ip or None,
        form.proxy_port,
    )
    return address_id


def _address_taken(e: sqlite3.IntegrityError) -> str:
    """Say which uniqueness rule was broken, because they mean different things."""
    if "unique_hijack_target" in str(e):
        return (
            "another address already hands its traffic to that proxy endpoint. Give "
            "this one its own port: the return rule recognises your proxy by address "
            "and port to put the original port back, so two addresses behind the same "
            "endpoint could not be told apart on the way out."
        )
    return "one of these addresses is already protected by a service"


def _check_tls_material(cert: str | None, key: str | None) -> None:
    """Refuse TLS material the engine would refuse, at the point it is handed over.

    Only the PEM envelope is checked, not the key itself: the aim is to catch the two
    mistakes that are made by hand and cost a restart to discover — a DER or PKCS#12
    file pasted in whole, and the certificate and the key swapped between the two
    fields. Both used to surface as a service that simply would not start, with the
    reason in the service log rather than in the answer to the request that caused it.

    Anything that carries the right header is passed through untouched: judging a
    certificate here by more than its envelope would be a second opinion on what the
    engine accepts, and the second opinion is the one that is wrong.
    """
    if cert is not None and cert.strip():
        if "-----BEGIN CERTIFICATE-----" not in cert:
            raise HTTPException(
                status_code=400,
                detail="That does not look like a PEM certificate: no "
                       "'BEGIN CERTIFICATE' block in it."
                       + (" It contains a private key — the two fields are the other way "
                          "round." if "PRIVATE KEY-----" in cert else ""),
            )
    if key is not None and key.strip():
        if "PRIVATE KEY-----" not in key:
            raise HTTPException(
                status_code=400,
                detail="That does not look like a PEM private key: no 'BEGIN PRIVATE "
                       "KEY' block in it."
                       + (" It contains a certificate — the two fields are the other way "
                          "round." if "-----BEGIN CERTIFICATE-----" in key else ""),
            )
        if "ENCRYPTED PRIVATE KEY-----" in key:
            raise HTTPException(
                status_code=400,
                detail="That private key is passphrase-protected, and nothing here can "
                       "be asked for the passphrase. Decrypt it first: "
                       "openssl pkey -in key.pem -out plain.pem",
            )


@app.post("", response_model=ServiceAddResponse)
async def add_service(form: ServiceAddForm):
    if form.transport not in TRANSPORT.ALL:
        raise HTTPException(status_code=400, detail=f"Unknown transport {form.transport!r}")
    if form.proto not in L4.ALL:
        raise HTTPException(status_code=400, detail=f"Unknown protocol {form.proto!r}")
    if not form.addresses:
        raise HTTPException(
            status_code=400, detail="A service needs at least one address to protect"
        )
    if form.proto == L4.TLS:
        if not (form.tls_cert and form.tls_key):
            raise HTTPException(
                status_code=400,
                detail="A service that speaks TLS needs both a certificate and a private key",
            )
        _check_tls_material(form.tls_cert, form.tls_key)
    # The transport gets a look before the row exists. A chain it could not host is
    # caught later, when there is one; what is caught here is what the *service* makes
    # impossible on its own — a protocol this layer cannot carry — and it is worth
    # catching now, because the alternative is a row that is created happily and then
    # refuses to start every time, with the reason arriving one action too late.
    try:
        transports.build_class(form.transport).check(
            Service.from_dict({
                "service_id": "", "name": form.name, "status": STATUS.STOP,
                "proto": form.proto, "transport": form.transport,
                "fail_open": form.fail_open,
            }),
            [],
        )
    except UnsupportedChain as e:
        raise HTTPException(status_code=400, detail=str(e))
    if form.transport == TRANSPORT.EXTERNAL and any(not a.proxy_port for a in form.addresses):
        raise HTTPException(
            status_code=400,
            detail="A service handing its traffic to your own proxy needs that proxy's "
                   "port for every address",
        )
    if form.transport == TRANSPORT.EXTERNAL and any(not is_ip_parse(a.ip_int) for a in form.addresses):
        raise HTTPException(
            status_code=400,
            detail="The external transport hands traffic to your own proxy and rewrites the "
                   "source address on return, which requires a concrete IP address rather than an interface.",
        )
    service_id = gen_id()
    try:
        db.query(
            "INSERT INTO services (service_id, name, status, proto, transport, "
            "fail_open, max_connections, over_limit_forwards, first_byte_timeout, "
            "tls_cert, tls_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            service_id,
            refactor_name(form.name),
            STATUS.STOP,
            form.proto,
            form.transport,
            form.fail_open,
            max(0, form.max_connections),
            form.over_limit_forwards,
            max(0, form.first_byte_timeout),
            form.tls_cert,
            form.tls_key,
        )
    except sqlite3.IntegrityError:
        return {"status": "A service with this name already exists"}
    try:
        for address in form.addresses:
            _insert_address(service_id, form.proto, address)
    except sqlite3.IntegrityError as e:
        # All of it or none: a service that came up on half the addresses the operator
        # listed is one they would believe is protecting the other half.
        db.query("DELETE FROM service_addresses WHERE service_id = ?;", service_id)
        db.query("DELETE FROM services WHERE service_id = ?;", service_id)
        return {"status": _address_taken(e)}
    await firewall.reload()
    await refresh_frontend()
    return {"status": "ok", "service_id": service_id}


@app.put("/{service_id}", response_model=StatusMessageModel)
async def edit_service(service_id: str, form: ServiceSettingsForm):
    """Change a service's definition.

    Anything here changes what the datapath is, not what it enforces, so a running
    service is stopped and started around it. That is a visible interruption, which is
    why filters and addresses are edited through their own endpoints instead — those
    cost at most the connections on the address that changed.
    """
    row = _service_or_404(service_id)
    fields = {}
    if form.name is not None:
        fields["name"] = refactor_name(form.name)
    if form.proto is not None:
        if form.proto not in L4.ALL:
            raise HTTPException(status_code=400, detail=f"Unknown protocol {form.proto!r}")
        fields["proto"] = form.proto
    if form.transport is not None:
        if form.transport not in TRANSPORT.ALL:
            raise HTTPException(status_code=400, detail=f"Unknown transport {form.transport!r}")
        fields["transport"] = form.transport
    if form.fail_open is not None:
        fields["fail_open"] = form.fail_open
    if form.max_connections is not None:
        if form.max_connections < 0:
            raise HTTPException(status_code=400, detail="A limit cannot be negative; 0 means none")
        fields["max_connections"] = form.max_connections
    if form.over_limit_forwards is not None:
        fields["over_limit_forwards"] = form.over_limit_forwards
    if form.first_byte_timeout is not None:
        if form.first_byte_timeout < 0:
            raise HTTPException(status_code=400, detail="A deadline cannot be negative; 0 means none")
        fields["first_byte_timeout"] = form.first_byte_timeout
    _check_tls_material(form.tls_cert, form.tls_key)
    # What has to hold is the state this edit *lands on*, not what it carries: turning
    # TLS on for a service that has never been given a certificate is a valid-looking
    # request whose only symptom is the engine refusing to start later, on a restart the
    # operator has by then attributed to something else. So the stored material counts
    # towards it, and a service already holding a certificate can be switched on without
    # pasting it again.
    lands_on_tls = (form.proto if form.proto is not None else row["proto"]) == L4.TLS
    if lands_on_tls:
        cert = form.tls_cert if form.tls_cert is not None else row["tls_cert"]
        key = form.tls_key if form.tls_key is not None else row["tls_key"]
        if not (cert and cert.strip()) or not (key and key.strip()):
            missing = "a certificate and a private key" if not (cert and cert.strip()) and not (key and key.strip()) \
                else "a certificate" if not (cert and cert.strip()) else "a private key"
            raise HTTPException(
                status_code=400,
                detail=f"This service terminates TLS, so it needs {missing}. Give it one "
                       f"here — the engine would refuse to start without it, and the service "
                       f"would fail on its next start rather than now.",
            )
    if form.tls_cert is not None:
        fields["tls_cert"] = form.tls_cert
    if form.tls_key is not None:
        fields["tls_key"] = form.tls_key
    if not fields:
        return {"status": "ok"}
    try:
        db.query(
            f"UPDATE services SET {', '.join(f'{k} = ?' for k in fields)} WHERE service_id = ?;",
            *fields.values(),
            service_id,
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="That name is already taken")
    if "proto" in fields:
        # The addresses carry the transport the kernel matches on, so that
        # `(ip, port, proto)` can be unique. Kept in step here rather than being a second
        # thing the operator sets — and derived, because `tls` is TCP on the wire.
        try:
            db.query(
                "UPDATE service_addresses SET proto = ? WHERE service_id = ?;",
                L4.l4_of(fields["proto"]),
                service_id,
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=400,
                detail="Another service already protects one of these addresses on "
                       f"{fields['proto']}",
            )

    srv = load_service(service_id)
    try:
        await firewall.get(service_id).refresh(srv)
    except UnsupportedChain as e:
        raise HTTPException(status_code=400, detail=str(e))
    await refresh_frontend()
    return {"status": "ok"}


# --- where a service is reachable ---------------------------------------------


@app.get("/{service_id}/addresses", response_model=list[AddressModel])
async def get_addresses(service_id: str):
    row = _service_or_404(service_id)
    return [_address_row(a) for a in _addresses(service_id)]


@app.post("/{service_id}/addresses", response_model=StatusMessageModel)
async def add_address(service_id: str, form: AddressForm):
    """Protect one more address with this service's existing chain.

    Not a restart: the datapath is already running and already enforcing the chain, so
    this installs the rules that point the new address at it. The connections on the
    other addresses are untouched. The one exception is a proxy service gaining its
    first IPv6 address, because the listener has to be reopened in a family that can
    accept it — the manager says so and rebuilds.
    """
    row = _service_or_404(service_id)
    if row["transport"] == TRANSPORT.EXTERNAL and not form.proxy_port:
        raise HTTPException(
            status_code=400,
            detail="This service hands its traffic to your own proxy, so the new "
                   "address needs the port that proxy listens on for it",
        )
    if row["transport"] == TRANSPORT.EXTERNAL and not is_ip_parse(form.ip_int):
        raise HTTPException(
            status_code=400,
            detail="The external transport hands traffic to your own proxy and rewrites the "
                   "source address on return, which requires a concrete IP address rather than an interface.",
        )
    try:
        address_id = _insert_address(service_id, row["proto"], form)
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=400, detail=_address_taken(e))
    def undo():
        # The row *and* the manager's copy of it: the manager re-read the list on its
        # way in, so leaving it there would mean the next start protecting an address
        # that was refused and no longer exists.
        db.query("DELETE FROM service_addresses WHERE address_id = ?;", address_id)
        firewall.get(service_id).reload_addresses()

    try:
        await firewall.get(service_id).address_added(address_id)
    except UnsupportedChain as e:
        undo()
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        undo()
        raise HTTPException(status_code=500, detail=str(e))
    await refresh_frontend()
    return {"status": "ok"}


@app.put("/{service_id}/addresses/{address_id}", response_model=StatusMessageModel)
async def edit_address(service_id: str, address_id: str, form: AddressForm):
    """Move an address. The rules for it are taken back and reinstalled."""
    row = _service_or_404(service_id)
    was = _address_or_404(service_id, address_id)
    if row["transport"] == TRANSPORT.EXTERNAL and not form.proxy_port:
        raise HTTPException(
            status_code=400,
            detail="This service hands its traffic to your own proxy, so every address "
                   "needs the port that proxy listens on for it",
        )
    if row["transport"] == TRANSPORT.EXTERNAL and not is_ip_parse(form.ip_int):
        raise HTTPException(
            status_code=400,
            detail="The external transport hands traffic to your own proxy and rewrites the "
                   "source address on return, which requires a concrete IP address rather than an interface.",
        )

    def write(ip_int, port, proxy_ip, proxy_port):
        db.query(
            "UPDATE service_addresses SET ip_int = ?, port = ?, proxy_ip = ?, "
            "proxy_port = ? WHERE address_id = ?;",
            ip_int, port, proxy_ip, proxy_port, address_id,
        )

    async def restore():
        """Put the address back exactly as it was, and steer it again.

        Best effort by design: the edit has already taken the old rules back, so the
        alternative to trying is an address left unprotected because the *new* one was
        impossible. A failure here is reported by the exception that caused it.
        """
        write(was["ip_int"], was["port"], was["proxy_ip"], was["proxy_port"])
        try:
            await firewall.get(service_id).address_added(address_id)
        except Exception:
            pass

    try:
        parsed_ip = parse_ip_or_int(form.ip_int)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    manager = firewall.get(service_id)
    await manager.address_removed(address_id)
    try:
        write(parsed_ip, form.port, form.proxy_ip or None, form.proxy_port)
    except sqlite3.IntegrityError as e:
        await restore()
        raise HTTPException(status_code=400, detail=_address_taken(e))
    try:
        await manager.address_added(address_id)
    except UnsupportedChain as e:
        await restore()
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        await restore()
        raise HTTPException(status_code=500, detail=str(e))
    await refresh_frontend()
    return {"status": "ok"}


@app.delete("/{service_id}/addresses/{address_id}", response_model=StatusMessageModel)
async def delete_address(service_id: str, address_id: str):
    _service_or_404(service_id)
    _address_or_404(service_id, address_id)
    if len(_addresses(service_id)) == 1:
        raise HTTPException(
            status_code=400,
            detail="This is the only address this service protects. Delete the service "
                   "itself, or add another address first.",
        )
    await firewall.get(service_id).address_removed(address_id)
    db.query("DELETE FROM service_addresses WHERE address_id = ?;", address_id)
    await refresh_frontend()
    return {"status": "ok"}


@app.delete("/{service_id}", response_model=StatusMessageModel)
async def delete_service(service_id: str):
    _service_or_404(service_id)
    await firewall.remove(service_id)
    for row in db.query("SELECT filter_id FROM filters WHERE service_id = ?;", service_id):
        clear_code(row["filter_id"])
        db.query("DELETE FROM regexes WHERE filter_id = ?;", row["filter_id"])
        db.query("DELETE FROM pyfilters WHERE filter_id = ?;", row["filter_id"])
    db.query("DELETE FROM filters WHERE service_id = ?;", service_id)
    db.query("DELETE FROM service_addresses WHERE service_id = ?;", service_id)
    stats.forget(db, service_id)
    db.query("DELETE FROM services WHERE service_id = ?;", service_id)
    await refresh_frontend()
    return {"status": "ok"}


@app.post("/{service_id}/start", response_model=StatusMessageModel)
async def start_service(service_id: str):
    _service_or_404(service_id)
    try:
        await firewall.get(service_id).next(STATUS.ACTIVE)
    except UnsupportedChain as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    _note_filtering(service_id)
    await refresh_frontend()
    return {"status": "ok"}


@app.post("/{service_id}/stop", response_model=StatusMessageModel)
async def stop_service(service_id: str):
    _service_or_404(service_id)
    await firewall.get(service_id).next(STATUS.STOP)
    firewall.release_capture_if_idle()
    await refresh_frontend()
    return {"status": "ok"}


# --- the chain ---------------------------------------------------------------


@app.get("/{service_id}/filters", response_model=list[FilterModel])
async def get_filters(service_id: str):
    """The chain, in the order it runs."""
    _service_or_404(service_id)
    return db.query(
        "SELECT f.filter_id filter_id, f.service_id service_id, f.position position, "
        "f.kind kind, f.proto proto, f.name name, f.active active, f.blocked blocked, "
        "(SELECT COUNT(*) FROM regexes r WHERE r.filter_id = f.filter_id) n_regexes, "
        "(SELECT COUNT(*) FROM pyfilters p WHERE p.filter_id = f.filter_id) n_functions, "
        "(SELECT COUNT(*) FROM pyfilters p WHERE p.filter_id = f.filter_id AND p.active = 1) "
        "n_functions_active "
        "FROM filters f WHERE f.service_id = ? ORDER BY f.position ASC;",
        service_id,
    )


@app.post("/{service_id}/filters", response_model=StatusMessageModel)
async def add_filter(service_id: str, form: FilterAddForm):
    """Attach a filter to the end of a service's chain."""
    _service_or_404(service_id)
    if form.kind not in KIND.ALL:
        raise HTTPException(status_code=400, detail=f"Unknown filter kind {form.kind!r}")
    last = db.query(
        "SELECT COALESCE(MAX(position), -1) p FROM filters WHERE service_id = ?;", service_id
    )[0]["p"]
    filter_id = gen_id()
    db.query(
        "INSERT INTO filters (filter_id, service_id, position, kind, proto, name, active) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);",
        filter_id,
        service_id,
        last + 1,
        form.kind,
        # A new pyfilter has no code yet, so it asks for nothing and speaks the simplest
        # protocol there is. Saving code is what settles it.
        PROTO.TCP,
        refactor_name(form.name or form.kind),
        form.active,
    )
    if form.kind == KIND.PYFILTER:
        write_code(filter_id, "")

    def undo():
        db.query("DELETE FROM filters WHERE filter_id = ?;", filter_id)
        clear_code(filter_id)

    await _apply_chain(service_id, undo)
    await refresh_frontend()
    return {"status": "ok"}


@app.put("/{service_id}/filters/{filter_id}", response_model=StatusMessageModel)
async def edit_filter(service_id: str, filter_id: str, form: FilterEditForm):
    was = _filter_or_404(service_id, filter_id)
    fields = {}
    if form.name is not None:
        fields["name"] = refactor_name(form.name)
    if form.active is not None:
        fields["active"] = form.active
    if fields:
        db.query(
            f"UPDATE filters SET {', '.join(f'{k} = ?' for k in fields)} WHERE filter_id = ?;",
            *fields.values(),
            filter_id,
        )

        def undo():
            db.query(
                f"UPDATE filters SET {', '.join(f'{k} = ?' for k in fields)} WHERE filter_id = ?;",
                *[was[k] for k in fields],
                filter_id,
            )

        await _apply_chain(service_id, undo)
        await refresh_frontend()
    return {"status": "ok"}


@app.delete("/{service_id}/filters/{filter_id}", response_model=StatusMessageModel)
async def delete_filter(service_id: str, filter_id: str):
    _filter_or_404(service_id, filter_id)
    db.query("DELETE FROM regexes WHERE filter_id = ?;", filter_id)
    db.query("DELETE FROM pyfilters WHERE filter_id = ?;", filter_id)
    db.query("DELETE FROM filters WHERE filter_id = ?;", filter_id)
    # Its history goes with it, or the chart would keep drawing a line for something
    # that no longer exists, labelled with an id nobody can look up.
    stats.forget_filter(db, filter_id)
    clear_code(filter_id)
    # Positions must stay contiguous: a gap is invisible until something orders by
    # position and gets a different answer than the operator saw.
    _renumber(service_id)
    await _apply_chain(service_id)
    await refresh_frontend()
    return {"status": "ok"}


def _renumber_to(order: list[str]):
    """Write an explicit order. Two passes because `position` is unique per service:
    writing the final numbers directly would collide with the ones not yet moved."""
    for offset, filter_id in enumerate(order):
        db.query("UPDATE filters SET position = ? WHERE filter_id = ?;", -1000 - offset, filter_id)
    for position, filter_id in enumerate(order):
        db.query("UPDATE filters SET position = ? WHERE filter_id = ?;", position, filter_id)


def _renumber(service_id: str):
    rows = db.query(
        "SELECT filter_id FROM filters WHERE service_id = ? ORDER BY position ASC;", service_id
    )
    # Out of the way first: `position` is unique per service, so writing the final
    # numbers directly would collide with the ones not yet moved.
    for offset, row in enumerate(rows):
        db.query(
            "UPDATE filters SET position = ? WHERE filter_id = ?;",
            -1000 - offset,
            row["filter_id"],
        )
    for position, row in enumerate(rows):
        db.query(
            "UPDATE filters SET position = ? WHERE filter_id = ?;", position, row["filter_id"]
        )


@app.post("/{service_id}/filters/order", response_model=StatusMessageModel)
async def reorder_filters(service_id: str, form: ReorderForm):
    """Set the order the chain runs in.

    The whole list at once rather than a move: a partial reorder has to be reconciled
    against whatever the operator's page last saw, and two tabs doing that at once
    produce an order neither of them asked for.
    """
    _service_or_404(service_id)
    existing = [
        r["filter_id"]
        for r in db.query("SELECT filter_id FROM filters WHERE service_id = ?;", service_id)
    ]
    if sorted(existing) != sorted(form.filters):
        raise HTTPException(
            status_code=400,
            detail="The order must list exactly the filters this service has",
        )
    previous = {
        r["filter_id"]: r["position"]
        for r in db.query(
            "SELECT filter_id, position FROM filters WHERE service_id = ?;", service_id
        )
    }
    _renumber_to(form.filters)

    def undo():
        _renumber_to(sorted(previous, key=lambda fid: previous[fid]))

    await _apply_chain(service_id, undo)
    await refresh_frontend()
    return {"status": "ok"}


# --- a pyfilter's code -------------------------------------------------------


class CodeCheckError(BaseModel):
    type: str
    message: str
    #: 1-based, or 0 when nothing in the file could be pointed at.
    line: int = 0
    column: int = 0
    #: The offending source line, so the reason can be shown without a second lookup.
    text: str = ""
    traceback: str = ""


class CodeCheckResult(BaseModel):
    ok: bool
    #: Which application protocol the code speaks, when it loads.
    proto: str | None = None
    #: The `@pyfilter` functions it defines, in the order the library found them.
    filters: list[str] = []
    #: The models it asks for, which is what decides where it can run.
    models: list[str] = []
    error: CodeCheckError | None = None


@app.post("/{service_id}/filters/{filter_id}/check", response_model=CodeCheckResult)
async def check_filter_code(service_id: str, filter_id: str, form: CodeForm):
    """Would this code load? Answered without saving it.

    Always 200, even when the answer is no: a refusal here is the result, not a failure
    of the request, and the editor wants a position to put a marker on rather than a
    string to print.
    """
    row = _filter_or_404(service_id, filter_id)
    if row["kind"] != KIND.PYFILTER:
        raise HTTPException(status_code=400, detail="This filter is not a pyfilter")
    return validate_code(form.code)


@app.get("/{service_id}/filters/{filter_id}/code", response_class=PlainTextResponse)
async def get_filter_code(service_id: str, filter_id: str):
    """The user's Python. Plain text, not JSON: it is a file, not a value."""
    row = _filter_or_404(service_id, filter_id)
    if row["kind"] != KIND.PYFILTER:
        raise HTTPException(status_code=400, detail="This filter is not a pyfilter")
    return read_code(filter_id)


@app.put("/{service_id}/filters/{filter_id}/code", response_model=StatusMessageModel)
async def set_filter_code(service_id: str, filter_id: str, form: CodeForm):
    """Replace a pyfilter's code, and record which protocol it now speaks.

    The protocol is not asked for and cannot be set: the library reads it off the
    filters' parameter annotations, because that is already what decides when each one
    is called. Asking would mean two places that can disagree, and the symptom of a
    disagreement is a filter that silently never runs — or, as it happened here, one
    refused for asking for an `HttpRequest`, which is the only thing an HTTP filter does.

    A file whose filters want two *different* application protocols is refused, naming
    both: a connection is only ever one of them.
    """
    row = _filter_or_404(service_id, filter_id)
    if row["kind"] != KIND.PYFILTER:
        raise HTTPException(status_code=400, detail="This filter is not a pyfilter")
    # Refused here, with the reason and the line, rather than by the datapath a moment
    # later with "the filter code did not load: worker exited" — which is true, useless,
    # and leaves the operator reading a traceback out of the service log.
    checked = validate_code(form.code)
    if not checked.get("ok"):
        raise HTTPException(status_code=400, detail=describe_error(checked["error"]))
    service = _service_or_404(service_id)
    if str(service["proto"]) == L4.UDP:
        # Refused rather than accepted and never called: on a datagram these models
        # decline to be built, so the filter would sit in the chain doing nothing and
        # nothing would say so.
        wanted = needs_a_stream(checked.get("models", []))
        if wanted:
            raise HTTPException(
                status_code=400,
                detail=f"This service speaks UDP, and {', '.join(wanted)} needs a TCP "
                       f"stream underneath — an assembled stream or a parsed HTTP "
                       f"message. On datagrams the library would decline to build it and "
                       f"the filter would never be called. Ask for a RawPacket instead, "
                       f"which carries the datagram and its metadata.",
            )
    proto = checked.get("proto", PROTO.TCP)
    was = read_code(filter_id)
    was_functions = db.query(
        "SELECT name, active, blocked FROM pyfilters WHERE filter_id = ?;", filter_id
    )
    write_code(filter_id, form.code)
    db.query("UPDATE filters SET proto = ? WHERE filter_id = ?;", proto, filter_id)
    _reconcile_functions(filter_id, form.code)

    def undo():
        write_code(filter_id, was)
        db.query("UPDATE filters SET proto = ? WHERE filter_id = ?;", row["proto"], filter_id)
        db.query("DELETE FROM pyfilters WHERE filter_id = ?;", filter_id)
        for fn in was_functions:
            db.query(
                "INSERT INTO pyfilters (filter_id, name, active, blocked) VALUES (?, ?, ?, ?);",
                filter_id, fn["name"], fn["active"], fn["blocked"],
            )

    await _apply_chain(service_id, undo)
    await refresh_frontend()
    return {"status": "ok"}


def _reconcile_functions(filter_id: str, code: str) -> None:
    """Line the stored function list up with what the code now defines.

    The code decides which functions exist; the operator decides which of them run. So a
    function that has gone from the file is dropped, one that has appeared is added
    switched on, and one that is still there keeps whatever the operator had set — an
    edit elsewhere in the file must not silently switch a function back on.

    A file that will not load leaves the list alone rather than emptying it: the
    datapath refuses the ruleset with the real error a moment later, and wiping the
    operator's choices on the way to that would be a second failure.
    """
    from firegex.pyfilters.internals import get_filter_names

    try:
        defined = get_filter_names(code) if code.strip() else []
    except Exception:
        return
    existing = {
        row["name"] for row in db.query(
            "SELECT name FROM pyfilters WHERE filter_id = ?;", filter_id
        )
    }
    for name in existing - set(defined):
        db.query("DELETE FROM pyfilters WHERE filter_id = ? AND name = ?;", filter_id, name)
    for position, name in enumerate(defined):
        if name in existing:
            # A survivor keeps its `active` and its counters, but not its old place: a
            # function inserted above it moved it down in the file, and the file is what
            # the order means.
            db.query(
                "UPDATE pyfilters SET position = ? WHERE filter_id = ? AND name = ?;",
                position, filter_id, name,
            )
        else:
            db.query(
                "INSERT INTO pyfilters (filter_id, name, position) VALUES (?, ?, ?);",
                filter_id, name, position,
            )


#: How long the operator's code gets to load before the check gives up on it.
CHECK_TIMEOUT = 8


def validate_code(code: str) -> dict:
    """Would this filter load, and if not, exactly where does it go wrong?

    Asked of `pyworker.py --check`, which is the process that will run the filter — the
    same build, the same compile, the same library. A stand-in that merely parsed the
    file would accept things the datapath refuses, which is the class of lie the regex
    tester exists to avoid.

    In a subprocess, and not only for the answer: the module body of a filter is
    arbitrary code, and this used to be `exec`ed inside the backend's own event loop. A
    `while True:` at module level would have taken the whole interface down with it.
    Here it costs a timeout.
    """
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        probe = f.name
    try:
        proc = subprocess.run(
            [sys.executable or "python3", PYWORKER, "--check", probe],
            capture_output=True,
            timeout=CHECK_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": {
                "type": "Timeout", "line": 0, "column": 0, "text": "",
                "message": f"the file did not finish loading within {CHECK_TIMEOUT}s. "
                           f"Code at module level runs once per connection, so it has to "
                           f"return — a loop or a blocking call there never will.",
                "traceback": "",
            },
        }
    finally:
        try:
            os.remove(probe)
        except OSError:
            pass
    try:
        return json.loads(proc.stdout.decode())
    except (ValueError, UnicodeDecodeError):
        # The checker itself failed, which is ours to explain rather than theirs.
        detail = proc.stderr.decode(errors="replace").strip() or "the check produced no answer"
        return {"ok": False, "error": {"type": "CheckFailed", "message": detail,
                                       "line": 0, "column": 0, "text": "",
                                       "traceback": ""}}


#: The one model that does not need a connection under it.
#:
#: Every other model reaches for something only TCP has — an assembled stream, a parsed
#: HTTP message — and answers `NotReadyToRun` on a datagram, which means the filter is
#: never called. Stated here rather than inferred because the library expresses it by
#: declining at runtime, and a filter that silently never fires is the failure this
#: whole module is arranged to prevent.
DATAGRAM_SAFE_MODELS = {"RawPacket"}


def needs_a_stream(models: list[str]) -> list[str]:
    return sorted(set(models) - DATAGRAM_SAFE_MODELS)


def describe_error(error: dict) -> str:
    """The one-line form, for a caller that has nowhere to put a marker."""
    where = f" (line {error['line']})" if error.get("line") else ""
    return f"{error.get('type', 'Error')}{where}: {error.get('message', '')}"


# --- the functions inside one pyfilter ---------------------------------------


@app.get("/{service_id}/filters/{filter_id}/functions", response_model=list[PyFunctionModel])
async def get_functions(service_id: str, filter_id: str):
    """Every `@pyfilter` the code defines, and whether it is switched on."""
    row = _filter_or_404(service_id, filter_id)
    if row["kind"] != KIND.PYFILTER:
        raise HTTPException(status_code=400, detail="This filter is not a pyfilter")
    return db.query(
        "SELECT filter_id, name, active, blocked FROM pyfilters "
        "WHERE filter_id = ? ORDER BY position ASC, name ASC;",
        filter_id,
    )


@app.put(
    "/{service_id}/filters/{filter_id}/functions/{name}", response_model=StatusMessageModel
)
async def edit_function(service_id: str, filter_id: str, name: str, form: PyFunctionEditForm):
    """Switch one function of a pyfilter on or off.

    The code is untouched: only the list of names handed to the library changes, which
    is exactly what decides whether a function is ever called. Deleting the code to stop
    consulting it, and pasting it back to resume, is the thing this exists to avoid.
    """
    row = _filter_or_404(service_id, filter_id)
    if row["kind"] != KIND.PYFILTER:
        raise HTTPException(status_code=400, detail="This filter is not a pyfilter")
    found = db.query(
        "SELECT active FROM pyfilters WHERE filter_id = ? AND name = ?;", filter_id, name
    )
    if not found:
        raise HTTPException(status_code=404, detail="This filter defines no such function")
    db.query(
        "UPDATE pyfilters SET active = ? WHERE filter_id = ? AND name = ?;",
        form.active, filter_id, name,
    )
    await _apply_chain(service_id, lambda: db.query(
        "UPDATE pyfilters SET active = ? WHERE filter_id = ? AND name = ?;",
        found[0]["active"], filter_id, name))
    await refresh_frontend()
    return {"status": "ok"}


# --- a regex filter's patterns -----------------------------------------------


@app.get("/{service_id}/filters/{filter_id}/regexes", response_model=list[RegexModel])
async def get_regexes(service_id: str, filter_id: str):
    _filter_or_404(service_id, filter_id)
    return db.query("SELECT * FROM regexes WHERE filter_id = ?;", filter_id)


@app.post("/{service_id}/filters/{filter_id}/regexes", response_model=StatusMessageModel)
async def add_regex(service_id: str, filter_id: str, form: RegexAddForm):
    row = _filter_or_404(service_id, filter_id)
    if row["kind"] != KIND.REGEX:
        raise HTTPException(status_code=400, detail="This filter does not hold patterns")
    if form.mode not in MODE.ALL:
        raise HTTPException(status_code=400, detail=f"Unknown mode {form.mode!r}")
    try:
        pattern = base64.b64decode(form.regex).decode(errors="replace")
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="The pattern must be base64-encoded")
    # Checked by the engine that will run it, not by a stand-in. A pattern accepted
    # here and refused at start time would leave the operator with a service that
    # will not come up and no idea which rule is at fault.
    ok, why = check_pattern(pattern, form.case_sensitive)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Invalid pattern: {why}")
    try:
        regex_id = gen_id()
        db.query(
            "INSERT INTO regexes (regex_id, filter_id, regex, mode, case_sensitive, active) "
            "VALUES (?, ?, ?, ?, ?, ?);",
            regex_id,
            filter_id,
            form.regex,
            form.mode,
            form.case_sensitive,
            form.active,
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="This pattern is already in this filter")
    await _apply_chain(service_id, lambda: db.query(
        "DELETE FROM regexes WHERE regex_id = ?;", regex_id))
    await refresh_frontend()
    return {"status": "ok"}


@app.put("/{service_id}/filters/{filter_id}/regexes/{regex_id}", response_model=StatusMessageModel)
async def edit_regex(service_id: str, filter_id: str, regex_id: str, form: RegexEditForm):
    """Change a pattern in place, without dropping the connections it is matching.

    The same rule keeps its row, so it keeps its place and its counters — except when the
    *pattern itself* changes. Then its history stops being its own: a count is about what
    a rule matched, and carrying yesterday's blocks over to a matcher that now matches
    something else would credit them to something that never made them. It is handed to
    the filter rather than deleted, so the timeline keeps its shape — those connections
    were refused, and correcting a typo afterwards does not unrefuse them.
    """
    _filter_or_404(service_id, filter_id)
    was = _regex_or_404(filter_id, regex_id)

    fields: dict = {}
    if form.active is not None:
        fields["active"] = form.active
    if form.mode is not None:
        if form.mode not in MODE.ALL:
            raise HTTPException(status_code=400, detail=f"Unknown mode {form.mode!r}")
        fields["mode"] = form.mode
    if form.case_sensitive is not None:
        fields["case_sensitive"] = form.case_sensitive
    if form.regex is not None:
        fields["regex"] = form.regex

    if not fields:
        return {"status": "ok"}

    # Whatever the row will hold once this is applied, checked as a whole rather than
    # field by field: what the engine has to accept is the resulting pattern.
    try:
        pattern = base64.b64decode(fields.get("regex", was["regex"])).decode(errors="replace")
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="The pattern must be base64-encoded")
    ok, why = check_pattern(pattern, fields.get("case_sensitive", was["case_sensitive"]))
    if not ok:
        raise HTTPException(status_code=400, detail=f"Invalid pattern: {why}")

    changed_matcher = "regex" in fields and fields["regex"] != was["regex"]
    if changed_matcher:
        fields["blocked"] = 0

    try:
        db.query(
            f"UPDATE regexes SET {', '.join(f'{k} = ?' for k in fields)} WHERE regex_id = ?;",
            *fields.values(),
            regex_id,
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400, detail="This filter already holds that exact pattern"
        )
    def undo():
        db.query(
            f"UPDATE regexes SET {', '.join(f'{k} = ?' for k in fields)} WHERE regex_id = ?;",
            *[was[k] for k in fields],
            regex_id,
        )

    await _apply_chain(service_id, undo)
    # After the chain has accepted it, and not before: a refusal has to leave the rule
    # exactly as it was, and history moved ahead of the verdict could not be put back.
    if changed_matcher:
        stats.disown_rule(db, filter_id, regex_id)
    await refresh_frontend()
    return {"status": "ok"}


@app.delete("/{service_id}/filters/{filter_id}/regexes/{regex_id}", response_model=StatusMessageModel)
async def delete_regex(service_id: str, filter_id: str, regex_id: str):
    _filter_or_404(service_id, filter_id)
    _regex_or_404(filter_id, regex_id)
    db.query("DELETE FROM regexes WHERE regex_id = ?;", regex_id)
    await _apply_chain(service_id)
    await refresh_frontend()
    return {"status": "ok"}


# --- what the service is doing -----------------------------------------------


@app.get("/{service_id}/stats", response_model=StatsModel)
async def get_stats(
    service_id: str,
    range_from: int | None = None,
    range_to: int | None = None,
    buckets: int = 60,
    step: int | None = None,
):
    """What this service's filters have refused, over a range you choose.

    `range_from`/`range_to` are unix seconds; leaving them out means the last hour.
    Everything in the answer counts the same range — the chart, the per-filter,
    per-pattern and per-function totals, and the shares — because a page where the chart
    honours the range and the table beside it does not is a page that contradicts itself.

    The bucket widens with the range rather than the count growing: twelve hours at
    one-minute resolution is seven hundred bars in a few hundred pixels. `step` overrides
    that with a width in seconds, for an operator who wants two ranges to be comparable
    by eye; it is rounded to whole stored buckets and widened if it would draw more bars
    than a chart can carry, and `bucket_seconds` reports what was actually used.
    """
    service = _service_or_404(service_id)
    buckets = max(5, min(int(buckets), 400))
    # The real instant, not the bucket it falls in: the window is aligned to buckets
    # inside `stats`, and truncating here would report the current, partial minute as
    # ending at the moment it began — which on a service a few seconds old prints as
    # "23:35 → 23:35".
    now = int(time.time())
    kept_from = stats.retention_start()
    began = service.get("filtering_since")
    end = min(int(range_to) if range_to else now, now)
    start = int(range_from) if range_from else end - 3600
    if end < start:
        start, end = end, start  # asked for the wrong way round
    # Clamped rather than refused: asking for a week of a two-day history is a reasonable
    # thing to do, and so is asking for a day of a service that has been up for ten
    # minutes. The answer is what there is, with the range actually served reported back
    # so the interface can say what it drew.
    start = max(start, kept_from)
    # The second floor, and the one that bites every day: without it a new service is a
    # chart of twenty-three empty hours with a smudge at the right-hand edge, which reads
    # as "nothing is happening" when what it means is "this only started existing a
    # moment ago". Only when the window reaches into the service's life at all — a window
    # that ended before it began is answered as asked, and is empty because it is, rather
    # than being dragged forward onto minutes nobody asked about.
    if began is not None and end >= began:
        start = max(start, began)

    window = stats.window(db, service_id, start, end, buckets, step if step else None)
    counted = stats.totals(db, service_id, start, end)
    by_filter = stats.totals_by_filter(db, service_id, start, end)
    total = sum(counted.values())

    def with_share(rows: list[dict]) -> list[dict]:
        for row in rows:
            row["share"] = round(100 * int(row["blocked"]) / total, 1) if total else 0.0
        return rows

    filters = db.query(
        "SELECT filter_id id, name, kind, blocked all_time FROM filters "
        "WHERE service_id = ? ORDER BY position ASC;",
        service_id,
    )
    for row in filters:
        # Summed over the rules inside it, not looked up by its own id: a regex block is
        # reported by its pattern and a Python one by its function, so a filter's own
        # token appears only when neither named itself.
        row["blocked"] = by_filter.get(row["id"], 0)

    patterns = db.query(
        "SELECT r.regex_id id, r.regex name, f.kind kind, r.filter_id filter_id "
        "FROM regexes r JOIN filters f ON r.filter_id = f.filter_id WHERE f.service_id = ?;",
        service_id,
    )
    for row in patterns:
        row["blocked"] = counted.get(row["id"], 0)
        # The pattern is stored base64 because it is bytes; a chart legend wants text.
        try:
            row["name"] = base64.b64decode(row["name"]).decode(errors="replace")
        except (binascii.Error, ValueError):
            pass

    functions = db.query(
        "SELECT p.name name, 'pyfilter' kind, p.filter_id filter_id FROM pyfilters p "
        "JOIN filters f ON p.filter_id = f.filter_id WHERE f.service_id = ?;",
        service_id,
    )
    for row in functions:
        # A function's name is unique inside its file, not across the chain, so the
        # token the datapath reports is what identifies it here too.
        row["id"] = f"{row['filter_id']}/{row['name']}"
        row["blocked"] = counted.get(row["id"], 0)

    # What a filter was credited with that no rule still in it accounts for: a pattern
    # that was deleted, or one whose text was edited and so handed its history to the
    # filter. Those blocks are in the chart and in the total because they happened, so
    # the breakdown has to name them — otherwise it quietly adds up to less than the
    # chart above it, and the operator is left looking for the difference.
    accounted: dict[str, int] = {}
    for row in patterns + functions:
        accounted[row["filter_id"]] = accounted.get(row["filter_id"], 0) + int(row["blocked"])
    for row in filters:
        left = int(row["blocked"]) - accounted.get(row["id"], 0)
        if left <= 0:
            continue
        is_py = row["kind"] == KIND.PYFILTER
        (functions if is_py else patterns).append({
            "id": f"{row['id']}/",
            "name": "functions since removed" if is_py else "patterns since edited or removed",
            "kind": row["kind"],
            "filter_id": row["id"],
            "blocked": left,
            "all_time": None,
            "residual": True,
        })

    named = {row["id"]: row["name"] for row in filters}
    manager = None
    try:
        manager = firewall.get(service_id)
    except Exception:
        pass
    traffic = manager.traffic() if manager else {}
    seen, refused = traffic.get("connections"), traffic.get("connections_refused")
    return {
        "filters": with_share(filters),
        "patterns": with_share(sorted(patterns, key=lambda r: -r["blocked"])),
        "functions": with_share(sorted(functions, key=lambda r: -r["blocked"])),
        "buckets": window["edges"],
        "bucket_seconds": window["width"],
        # Only the filters that actually refused something in the range: an empty line
        # per filter would make a busy chain unreadable to say nothing.
        "series": [
            {"id": fid, "name": named.get(fid, fid), "counts": counts}
            for fid, counts in window["series"].items()
        ],
        "total": total,
        "all_time": sum(int(row["all_time"]) for row in filters),
        "range_from": start,
        "range_to": end,
        "kept_from": kept_from,
        "filtering_since": began,
        "traffic": {
            **traffic,
            # Only where both numbers are connections. Dividing refused connections by
            # a packet count would produce a number that looks like a percentage and
            # means nothing.
            "refused_share": (
                round(100 * refused / seen, 2) if seen and refused is not None else None
            ),
        },
    }


@app.get("/{service_id}/logs", response_model=list[LogEntryModel])
async def get_logs(service_id: str):
    """The tail of what this service has been doing.

    Only the tail: new lines arrive over the `log` socket event as they happen, so this
    exists to fill the panel when it opens rather than to be polled. It is bounded, so a
    service that has blocked a million connections still answers instantly.
    """
    _service_or_404(service_id)
    return log_for(service_id).entries()


@app.delete("/{service_id}/logs", response_model=StatusMessageModel)
async def clear_logs(service_id: str):
    _service_or_404(service_id)
    log_for(service_id).clear()
    return {"status": "ok"}


# --- the debugger ------------------------------------------------------------


def _ask_engine(request: dict) -> dict:
    """Put the question to the binary that would enforce the answer."""
    try:
        proc = subprocess.run(
            [PROXY_ENGINE, "--debug-regex"],
            input=json.dumps(request).encode(),
            capture_output=True,
            timeout=10,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="The matching engine is not installed")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=400, detail="The pattern took too long to evaluate")
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip() or "the engine refused the request"
        raise HTTPException(status_code=400, detail=detail)
    return json.loads(proc.stdout.decode())


def check_pattern(pattern: str, case_sensitive: bool = True) -> tuple[bool, str]:
    """Would the engine accept this pattern?

    Asked of the engine that will run it rather than of a stand-in, and compiled for
    stream matching, which is the only mode anything runs in now: a pattern blocks, and
    blocking follows the stream across chunk boundaries. This used to take the action
    too, because rewriting compiled in block mode and the two do not accept quite the
    same patterns.

    `case_sensitive` is coerced rather than trusted: a caller checking a pattern it just
    read back from the database hands over SQLite's 1, and the engine's request format
    is strict about the difference — which came out as "invalid type: integer 1" against
    a pattern that was perfectly fine.
    """
    try:
        res = _ask_engine(
            {
                "patterns": [
                    {
                        "id": "x",
                        "expr": pattern,
                        "case_sensitive": bool(case_sensitive),
                    }
                ],
                "sample": "",
            }
        )
    except HTTPException as e:
        return False, str(e.detail)
    if res.get("error"):
        return False, res["error"]
    if res.get("errors"):
        return False, res["errors"][0]["error"]
    return True, "ok"


@app.post("/debug-regex", response_model=DebugResponse)
async def debug_regexes(form: DebugForm):
    """Try patterns against a sample, with the engine that will run them.

    Deliberately not a `re`-based approximation. hyperscan takes a subset of PCRE and
    rejects things Python accepts, so anything else would bless patterns that cannot
    be saved and disagree about what matches — a tester the operator would learn not
    to trust, which is worse than none.
    """
    res = _ask_engine(
        {
            "patterns": [
                {
                    "id": p.id,
                    "expr": p.expr,
                    "case_sensitive": p.case_sensitive,
                }
                for p in form.patterns
            ],
            "sample": form.sample,
        }
    )
    return {
        "matches": [
            {"id": m["id"], "start": m["from"], "end": m["to"]} for m in res.get("matches", [])
        ],
        "errors": res.get("errors", []),
        "error": res.get("error"),
        "unscannable": res.get("unscannable", []),
        "rewritten": res.get("rewritten"),
        "truncated": res.get("truncated", False),
    }
