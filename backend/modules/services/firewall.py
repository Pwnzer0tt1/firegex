"""Running services: the transport, the chain on top of it, and the rules that meet.

One `ServiceManager` per row in `services`, holding whichever transport that row asked
for. Everything order-dependent lives here, because getting the order wrong is not an
error anybody sees — it is a window during which traffic goes unfiltered.

Starting, outside in: the datapath first, which is what decides the queue number or the
port, then the nftables rules that point at it. Stopping is the exact reverse, so nothing
is ever steered at something that has already gone. There used to be a step before both
— nginx, brought up for a service behind TLS so that the plaintext port existed before
anything attached to it. The engine terminates TLS itself now, so a certificate is
something it is started with rather than something arranged around it; what is left
before the datapath is the capture interface, which has to exist before the process that
opens a socket to it.
"""

import asyncio
import base64
import os
import time
import traceback

from modules.services import mirror
from modules.services import transports
from modules.services import stats
from modules.services.logs import LEVEL, forget as forget_log, log_for
from modules.services.models import KIND, STATUS, Address, Filter, Regex, Service
from modules.services.nftables import FiregexTables
from utils.sqlite import SQLite

nft = FiregexTables()

#: The user's Python, one file per filter.
CODE_DIR = "db/service_filters"

#: How long between two log lines about the connection limit. Being at the limit means
#: connections are arriving faster than they leave, so a line each would be the flood
#: arriving twice — once at the service and once in the operator's log.
OVER_LIMIT_QUIET = 30


def code_path(filter_id: str) -> str:
    return os.path.join(CODE_DIR, f"{filter_id}.py")


def read_code(filter_id: str) -> str:
    try:
        with open(code_path(filter_id)) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def write_code(filter_id: str, code: str) -> None:
    os.makedirs(CODE_DIR, exist_ok=True)
    with open(code_path(filter_id), "w") as f:
        f.write(code)


def clear_code(filter_id: str) -> None:
    try:
        os.remove(code_path(filter_id))
    except FileNotFoundError:
        pass


class ServiceNotFoundException(Exception):
    pass


class ServiceManager:
    def __init__(self, srv: Service, db: SQLite):
        self.srv = srv
        self.db = db
        self.active = False
        self.transport: transports.Transport | None = None
        self.lock = asyncio.Lock()
        self.log = log_for(srv.id)
        #: When the limit was last mentioned in the log, so a flood is reported rather
        #: than reproduced.
        self._over_limit_told = 0.0
        #: What the running datapath needs the rules to point at — a queue number per
        #: filter, or the port the proxy is listening on. Kept so an address added later
        #: can be steered at the same datapath instead of restarting it.
        self._steer: dict = {}
        #: Carried between lines so a multi-line traceback keeps its severity.
        self._in_traceback = False
        self._engine_level = LEVEL.INFO

    # --- reading the configuration -------------------------------------------

    def chain(self) -> list[transports.ChainLink]:
        """The filter chain as configured, in the operator's order."""
        links = []
        rows = self.db.query(
            "SELECT * FROM filters WHERE service_id = ? ORDER BY position ASC;", self.srv.id
        )
        for row in rows:
            flt = Filter.from_dict(row)
            if flt.kind == KIND.REGEX:
                regexes = [
                    Regex.from_dict(r)
                    for r in self.db.query(
                        "SELECT * FROM regexes WHERE filter_id = ?;", flt.id
                    )
                ]
                links.append(transports.ChainLink(flt, regexes=regexes))
            else:
                links.append(transports.ChainLink(
                    flt,
                    code_path=code_path(flt.id),
                    functions=self.db.query(
                        "SELECT name, active FROM pyfilters WHERE filter_id = ? "
                        "ORDER BY name ASC;",
                        flt.id,
                    ),
                ))
        return links

    def check(self) -> None:
        """Would this service start? Raises `UnsupportedChain` with the reason."""
        transports.TRANSPORTS[self.srv.transport].check(self.srv, self.chain())

    def reload_addresses(self) -> None:
        """Re-read where this service is reachable, without touching anything else."""
        self.srv.addresses = [
            Address.from_dict(row)
            for row in self.db.query(
                "SELECT * FROM service_addresses WHERE service_id = ? ORDER BY ip_int, port;",
                self.srv.id,
            )
        ]

    # --- callbacks from the datapath ------------------------------------------

    def _on_block(self, reported: str):
        # Either a regex rule id, or `<filter>/<function>` from a pyfilter — the one
        # token both network layers report. Split once, here, so there is a single place
        # that knows the format.
        rule_id, _, function = reported.partition("/")
        if function:
            self.db.query(
                "UPDATE pyfilters SET blocked = blocked + 1 WHERE filter_id = ? AND name = ?;",
                rule_id,
                function,
            )
        # What is left is a regex rule or a whole filter, depending on which refused.
        # Only one of these matches, and a blind update is cheaper than asking first.
        self.db.query(
            "UPDATE regexes SET blocked = blocked + 1 WHERE regex_id = ?;", rule_id
        )
        self.db.query(
            "UPDATE filters SET blocked = blocked + 1 WHERE filter_id = ? OR filter_id = "
            "(SELECT filter_id FROM regexes WHERE regex_id = ?);",
            rule_id,
            rule_id,
        )
        # The chart is attributed to the filter, not to the pattern or the function: it
        # is about which link in the chain is carrying the traffic, and a chain of twenty
        # patterns would be a chart nobody can read. The finer totals are listed
        # alongside it, and named in the log line below.
        # The whole token, not just the filter: keeping the finer key is what lets a
        # time range mean the same thing for the chart and for the tables beside it.
        stats.record(self.srv.id, self._owning_filter(rule_id), reported)
        stats.flush(self.db)
        self.log.add(LEVEL.BLOCK, f"connection refused by {self._describe(rule_id, function)}")

    def _owning_filter(self, rule_id: str) -> str:
        """Which filter a block belongs to. The id is a filter's or a pattern's."""
        found = self.db.query(
            "SELECT filter_id FROM regexes WHERE regex_id = ?;", rule_id
        )
        return found[0]["filter_id"] if found else rule_id

    def _describe(self, rule_id: str, function: str = "") -> str:
        """Name what refused a connection, rather than echoing an opaque id.

        One query per block, on a path that only runs when something was already
        refused — a block is rare compared to the traffic that is not blocked, and an
        operator reading `refused by 4f2a91c8` learns nothing.
        """
        if function:
            # A file holds several functions, so naming the file alone would leave the
            # operator to guess which of them refused the connection.
            found = self.db.query("SELECT name FROM filters WHERE filter_id = ?;", rule_id)
            return f"{found[0]['name']}: {function}()" if found else f"{function}()"
        found = self.db.query(
            "SELECT f.name fname, r.regex pattern FROM regexes r "
            "JOIN filters f ON r.filter_id = f.filter_id WHERE r.regex_id = ?;",
            rule_id,
        )
        if found:
            try:
                pattern = base64.b64decode(found[0]["pattern"]).decode(errors="replace")
            except Exception:
                pattern = "?"
            return f"{found[0]['fname']}: /{pattern}/"
        found = self.db.query("SELECT name FROM filters WHERE filter_id = ?;", rule_id)
        if found:
            return found[0]["name"]
        return rule_id

    def _on_output(self, _service_id: str, text: str):
        self.log.add(LEVEL.OUTPUT, text)

    def _on_exception(self, _service_id: str):
        self.log.add(LEVEL.ERROR, "a filter raised; the traffic was forwarded unfiltered")

    def _on_engine(self, text: str):
        """Whatever the datapath itself says about its own health.

        Worth surfacing rather than leaving on the backend's stderr: these are the lines
        that say a filter was disabled, or that source preservation fell back — things
        the operator would otherwise only notice from the outside, much later.
        """
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("["):
                # An engine line carries its own tag, and ends any traceback before it.
                self._engine_level = LEVEL.INFO
                if "[warn]" in stripped:
                    self._engine_level = LEVEL.WARN
                elif "[error]" in stripped or "[fatal]" in stripped:
                    self._engine_level = LEVEL.ERROR
                level = self._engine_level
                self._in_traceback = False
            elif stripped.startswith("Traceback (most recent call last)") or stripped.startswith(
                "thread '"
            ):
                # A traceback arrives one line at a time and only the first says what it
                # is. Reporting the rest as ordinary output would bury the failure in the
                # middle of a wall of grey.
                self._in_traceback = True
                level = LEVEL.ERROR
            elif self._in_traceback:
                level = LEVEL.ERROR
            else:
                # Everything the datapath says about itself is tagged, so an untagged
                # line came from the user's own code — their `print()`, which the worker
                # sends here precisely so it can be read.
                level = LEVEL.OUTPUT
            self.log.add(level, stripped)

    def _on_over_limit(self, refused: int) -> None:
        """The connection limit turned something away. Say so, and keep the count.

        Two records, because they answer different questions and one cannot do both. The
        log says it *now*, at warning level, so an operator watching a service under
        attack sees the reason its clients are failing rather than guessing. The database
        says it *later*: the live log is a bounded ring on purpose, so a burst at three
        in the morning would be gone by breakfast, and "did we ever hit the wall" is
        exactly the question asked the next day.

        The engine's own line is what explains the policy; this one carries the number,
        and is rate-limited for the same reason the engine's is — being at the limit
        means connections are arriving faster than they leave.
        """
        now = int(time.time())
        self.db.query(
            "UPDATE services SET over_limit_hits = over_limit_hits + ?, "
            "over_limit_first = COALESCE(over_limit_first, ?), over_limit_last = ? "
            "WHERE service_id = ?;",
            refused, now, now, self.srv.id,
        )
        if now - self._over_limit_told >= OVER_LIMIT_QUIET:
            self._over_limit_told = now
            self.log.add(
                LEVEL.WARN,
                f"the {self.srv.max_connections} connection limit turned away {refused} "
                f"more: they were "
                + ("forwarded with no filter in front of them"
                   if self.srv.over_limit_forwards else "refused")
                + ". Raise the limit, or find out who is holding connections open.",
            )

    # --- lifecycle ------------------------------------------------------------

    async def enable(self):
        if self.active:
            return
        async with self.lock:
            self.transport = transports.build(
                self.srv,
                on_block=self._on_block,
                on_output=self._on_output,
                on_exception=self._on_exception,
                on_engine=self._on_engine,
                on_over_limit=self._on_over_limit,
            )
            try:
                # Before the engine, which opens its socket to it at startup: an
                # interface that appears afterwards is one this process will not find
                # until it is restarted.
                if self.srv.terminates_tls:
                    mirror.ensure()
                steer = await self.transport.start(self.chain())
                self._steer = steer
                # Clear first: a stale rule from a crashed run would otherwise sit in
                # front of the new one and send traffic nowhere.
                nft.delete(self.srv)
                nft.add(self.srv, **steer)
            except Exception as e:
                self.log.add(LEVEL.ERROR, f"could not start: {e}")
                await self.transport.stop()
                self.transport = None
                raise
            self._set_status(True)
            self.log.add(
                LEVEL.INFO,
                f"started on the {self.srv.transport} layer, "
                f"{len([link for link in self.chain() if link.filter.active])} filter(s) active",
            )

    async def disable(self, persist: bool = True):
        if not self.active:
            return
        async with self.lock:
            nft.delete(self.srv)
            self._steer = {}
            if self.transport:
                await self.transport.stop()
                self.transport = None
            self._set_status(False, persist=persist)
            self.log.add(LEVEL.INFO, "stopped")

    async def restart(self):
        await self.disable()
        await self.enable()

    async def update_chain(self):
        """Push the current chain to a running datapath.

        Editing a rule costs nobody their connection: the datapath swaps its
        configuration underneath the traffic. A chain the transport cannot host is
        refused here, before it is pushed anywhere.

        Adding, removing or reordering a filter on the NFQUEUE layer is different, and
        the transport says so by raising: there, each filter is its own process at its
        own chain priority, so the shape of the chain *is* the arrangement of processes
        and rules. That has to be rebuilt, which is a visible interruption — better than
        silently enforcing the old order.
        """
        restart = False
        async with self.lock:
            if not self.active or not self.transport:
                return
            try:
                await self.transport.reload(self.chain())
            except transports.ChainShapeChanged:
                restart = True
        if restart:
            self.log.add(LEVEL.INFO, "the chain changed shape; rebuilding it")
            await self.restart()
            return
        self.log.add(
            LEVEL.INFO,
            f"filters reloaded, "
            f"{len([link for link in self.chain() if link.filter.active])} active "
            f"(no connection was dropped)",
        )

    async def address_added(self, address_id: str):
        """Steer one more address at the datapath that is already running.

        Deliberately not a restart. The chain is unchanged and the datapath is already
        enforcing it, so all that is missing are the rules that point the new address at
        it — and the connections on every other address stay up.

        The exception is a proxy service that had no IPv6 address until now: its
        listener was opened in a family that cannot accept one, so it has to be
        reopened. Saying so and rebuilding beats installing a rule that redirects
        traffic at a socket which will refuse it.
        """
        was_dual = self.srv.has_ipv6
        self.reload_addresses()
        if not self.active:
            return
        is_dual = getattr(self.transport, "is_dual_stack", False)
        if (
            self.srv.transport == transports.TRANSPORT.PROXY
            and str(self.srv.proto) != "udp"
            and self.srv.has_ipv6
            and not was_dual
            and not is_dual
        ):
            self.log.add(
                LEVEL.INFO,
                "the first IPv6 address needs a listener that can accept one; rebuilding",
            )
            await self.restart()
            return
        added = [addr for addr in self.srv.addresses if addr.id == address_id]
        if not added:
            return
        if self.srv.transport == transports.TRANSPORT.PROXY:
            from modules.services.nftables import one_address, ip_family
            from utils import is_ip_parse, get_interface_ips
            for addr in added:
                l4 = str(addr.proto or self.srv.proto)
                if l4 == "udp":
                    is_iface = not is_ip_parse(addr.ip_int)
                    if is_iface:
                        ips = get_interface_ips(addr.ip_int)
                        if not ips:
                            raise transports.UnsupportedChain(
                                f"interface '{addr.ip_int}' has no IP assigned for UDP proxy relay"
                            )
                        target_ip = one_address(ips[0])
                    else:
                        target_ip = one_address(addr.ip_int)
                    target_port = addr.port
                    family = ip_family(target_ip)
                    key = (
                        f"[{target_ip}]:{target_port}"
                        if family == "ip6" else f"{target_ip}:{target_port}"
                    )
                    if "udp_ports" not in self._steer:
                        self._steer["udp_ports"] = {}
                    if key not in self._steer["udp_ports"]:
                        port = await self.transport.add_udp_target(target_ip, target_port)
                        self._steer["udp_ports"][key] = port
        async with self.lock:
            nft.add(self.srv, added, **self._steer)
        self.log.add(
            LEVEL.INFO,
            f"also protecting {added[0].ip_int}:{added[0].port} (no connection was dropped)",
        )

    async def address_removed(self, address_id: str):
        """Stop steering one address, leaving the rest of the service running."""
        gone = [addr for addr in self.srv.addresses if addr.id == address_id]
        if gone:
            async with self.lock:
                if self.active:
                    nft.delete(self.srv, gone)
            if self.active:
                self.log.add(LEVEL.INFO, f"no longer protecting {gone[0].ip_int}:{gone[0].port}")
        # Dropped from the list here rather than re-read from the database, because the
        # row is still there: the caller takes the rules back before deleting it, so
        # that nothing is deleted while traffic is still being steered at it. Re-reading
        # would put the address straight back, and the next restart would re-protect an
        # address that no longer exists.
        self.srv.addresses = [addr for addr in self.srv.addresses if addr.id != address_id]

    def traffic(self) -> dict:
        """How much has arrived, and how much of it was refused.

        Two measures rather than one ratio, because they are in different units and
        dividing them would invent a number. The kernel counts **packets** on the rules
        that intercept this service — free, and nothing in userspace can skew it. The
        proxy engine counts **connections**, which is the same unit a block is in, so
        there the share is exact; the nfqueue layer works per packet and has no
        connection to count, which is a real difference between the two and is reported
        as one rather than papered over.
        """
        seen = nft.traffic(self.srv) if self.active else {"packets": 0, "bytes": 0}
        counters = self.transport.counters if self.transport else {}
        return {
            # Zero on the proxy layer, where no rule is walked per packet — see
            # `FiregexTables.traffic`. The engine's connection counters answer instead.
            "packets": seen["packets"],
            "bytes": seen["bytes"],
            "connections": counters.get("seen"),
            "connections_refused": counters.get("refused"),
        }

    async def refresh(self, srv: Service):
        """The service's own definition changed, which the datapath cannot absorb."""
        was_active = self.active
        if was_active:
            await self.disable()
        self.srv = srv
        if was_active:
            await self.enable()

    async def next(self, status: str):
        if status == STATUS.ACTIVE:
            await self.enable()
        else:
            await self.disable()

    def _set_status(self, active: bool, persist: bool = True):
        self.active = active
        self.srv.status = STATUS.ACTIVE if active else STATUS.STOP
        if persist:
            self.db.query(
                "UPDATE services SET status = ? WHERE service_id = ?;",
                self.srv.status,
                self.srv.id,
            )


class FirewallManager:
    def __init__(self, db: SQLite):
        self.db = db
        self.services: dict[str, ServiceManager] = {}
        self.lock = asyncio.Lock()

    async def init(self):
        nft.init()
        await self.reload()

    async def reload(self):
        async with self.lock:
            for row in self.db.query("SELECT * FROM services;"):
                srv = Service.from_dict(row)
                if srv.id in self.services:
                    continue
                self.services[srv.id] = ServiceManager(srv, self.db)
                # Where it is reachable, read here rather than in the constructor so
                # there is one place that knows how, and one that calls it.
                self.services[srv.id].reload_addresses()
                if srv.status == STATUS.ACTIVE:
                    try:
                        await self.services[srv.id].enable()
                    except Exception:
                        # One service that cannot come back must not stop the others:
                        # at a competition, most of the protection working beats none
                        # of it working.
                        traceback.print_exc()

    async def remove(self, srv_id: str, persist: bool = True):
        async with self.lock:
            if srv_id in self.services:
                await self.services[srv_id].disable(persist=persist)
                del self.services[srv_id]
                if persist:
                    # A deleted service's log has nothing left to be about.
                    forget_log(srv_id)
        self.release_capture_if_idle()

    def release_capture_if_idle(self) -> None:
        """Take the capture interface away once nothing is decrypting.

        Asked of the managers rather than of the database, because what matters is which
        services are *running*: a stopped one writes nothing, and an interface that is
        there while nothing is decrypting is one somebody points a capture at and watches
        stay empty.
        """
        if any(m.active and m.srv.terminates_tls for m in self.services.values()):
            return
        mirror.release()

    async def close(self):
        for key in list(self.services.keys()):
            try:
                await self.remove(key, persist=False)
            except Exception:
                self.services.pop(key, None)

    def get(self, srv_id: str) -> ServiceManager:
        if srv_id not in self.services:
            raise ServiceNotFoundException()
        return self.services[srv_id]
