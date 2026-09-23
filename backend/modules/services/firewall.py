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
from modules.services.models import (KIND, L4, STATUS, UPSTREAM, Address, Filter,
                                     Regex, Service)
from modules.services.nftables import (FiregexTables, NoRelayAddress,
                                       interface_addresses, udp_relay_host)
from utils.sqlite import SQLite

nft = FiregexTables()

#: The user's Python, one file per filter.
CODE_DIR = "db/service_filters"

#: How many times a datapath may be brought back before it is declared broken, and how
#: long without a crash puts the counter back to zero.
#:
#: Bounded, because the alternative to a budget is a restart loop: a binary that dies on
#: the first packet of every attempt would be restarted forever, and each attempt tears
#: the rules down and builds them again. Spending the budget stops the service outright,
#: which is the honest end state — the rules come off and the interface says stopped,
#: instead of a service that reports itself active and is filtering nothing.
MAX_RESTART_ATTEMPTS = 5
CRASH_COUNTER_RESET = 60

#: How long between two log lines about the connection limit. Being at the limit means
#: connections are arriving faster than they leave, so a line each would be the flood
#: arriving twice — once at the service and once in the operator's log.
OVER_LIMIT_QUIET = 30

#: How long between two reports that a filter is raising. Same reasoning as the line
#: above, for the same shape of problem: user code that throws usually throws on every
#: packet, so a line each is the fault arriving once per packet in a log that holds a
#: few hundred lines. What the operator needs is that it is happening, how often, and one
#: traceback — not the same traceback several hundred times, with everything else that
#: was in the log pushed out behind it.
RAISED_QUIET = 30


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
        self._raised_told = 0.0
        self._raised_since = 0
        #: What the running datapath needs the rules to point at — a queue number per
        #: filter, or the port the proxy is listening on. Kept so an address added later
        #: can be steered at the same datapath instead of restarting it.
        self._steer: dict = {}
        #: How many times this service's datapath has died on its own recently, and
        #: when the last one was.
        self._crash_count = 0
        self._last_crash = 0.0
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
                        "ORDER BY position ASC, name ASC;",
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
        """A filter threw, and the chunk went through unfiltered.

        Rate-limited, because code that throws throws on every packet: unthrottled this
        is the same sentence a few hundred times, and the log is a bounded ring — so the
        flood does not merely repeat itself, it evicts everything else, including the
        first report and whatever was there before the filter broke.

        The suppressed ones are counted rather than dropped. "it is still happening, 412
        times since" is the number that says whether this is one odd request or every
        request, which is the question the operator actually has.
        """
        now = time.time()
        self._raised_since += 1
        if now - self._raised_told < RAISED_QUIET:
            return
        first = self._raised_told == 0.0
        count, self._raised_since = self._raised_since, 0
        self._raised_told = now
        self.log.add(
            LEVEL.ERROR,
            "a filter raised; the traffic was forwarded unfiltered"
            if first and count == 1 else
            f"a filter is still raising: {count} more since, all forwarded unfiltered",
        )

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

    def _on_datapath_died(self, what: str, returncode: int) -> None:
        """A datapath process is gone and nobody asked it to go.

        Scheduled rather than awaited: this is called from the task that was watching the
        process, and the recovery below stops and starts the service — which cancels that
        very task. Doing it inline would have the watchdog cancel itself half way through.
        """
        #: A bare `create_task` swallows whatever the coroutine raises, and the first
        #: version of this recovery did exactly that: a wrong constant name meant the
        #: restart never ran, while the line reporting the crash still appeared — a
        #: watchdog that says the right thing and does nothing. Anything that goes wrong
        #: in here is the operator's business too.
        task = asyncio.create_task(self._recover_datapath(what, returncode))

        def _complain(done: asyncio.Task):
            if done.cancelled():
                return
            if done.exception():
                self.log.add(
                    LEVEL.ERROR,
                    f"could not recover the datapath: {done.exception()!r}",
                )

        task.add_done_callback(_complain)

    async def _recover_datapath(self, what: str, returncode: int) -> None:
        """Bring the datapath back, a bounded number of times.

        **The nftables rules outlive the process**, which is what makes this worth doing
        at all: when the binary dies the rules stay, so traffic keeps being steered at a
        queue nobody is reading and the interface goes on saying the service is active.
        What actually happens to that traffic is then decided by the `bypass` flag alone —
        accepted where the service is fail-open, dropped where it is not — and either way
        nothing filters it and nothing says so.

        Restarting rebuilds the processes *and* their rules. It is attempted a bounded
        number of times so that a binary dying on the first packet of every attempt does
        not become a restart loop; when the budget is spent the service is stopped for
        good, which takes the rules off and makes the failure visible.
        """
        if not self.active or self.transport is None:
            return  # already being stopped on purpose
        now = time.monotonic()
        if now - self._last_crash > CRASH_COUNTER_RESET:
            self._crash_count = 0
        self._last_crash = now
        self._crash_count += 1
        self.log.add(
            LEVEL.ERROR,
            f"{what} exited on its own with code {returncode} — its rules are still in "
            f"place, so nothing was filtering this service",
        )
        if self._crash_count > MAX_RESTART_ATTEMPTS:
            self.log.add(
                LEVEL.ERROR,
                f"it has done that {self._crash_count} times; stopping the service "
                f"instead of restarting it again",
            )
            await self.disable()
            return
        self.log.add(
            LEVEL.WARN,
            f"restarting it ({self._crash_count}/{MAX_RESTART_ATTEMPTS})",
        )
        try:
            await self.restart()
        except Exception as e:
            self.log.add(LEVEL.ERROR, f"could not restart it: {e}")
            await self.disable()

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
        # Asked under the lock, not before it. Asked first, two starts arriving together —
        # a double click, or an operator's start racing the watchdog's restart — both saw
        # a stopped service, and the second built a datapath of its own over the first:
        # the first engine was left running with nobody holding it.
        async with self.lock:
            if self.active:
                return
            self.transport = transports.build(
                self.srv,
                on_block=self._on_block,
                on_output=self._on_output,
                on_exception=self._on_exception,
                on_engine=self._on_engine,
                on_over_limit=self._on_over_limit,
                on_died=self._on_datapath_died,
            )
            try:
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
        # Under the lock for the same reason: a stop arriving while a start was still in
        # progress saw a service that was not active yet, returned at once, and the start
        # then finished — so the stop the operator asked for was simply lost.
        async with self.lock:
            if not self.active:
                return
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
        was_dual = self.srv.has_ipv6_tcp
        self.reload_addresses()
        if not self.active:
            return
        # Asked of the transport the kernel sees, not of what the service speaks: the
        # one listener that has a family to get wrong is the TCP one. Anything relayed
        # per address — datagrams, and QUIC — binds a socket for the new address when it
        # arrives, in whatever family that address is, so there is nothing to reopen.
        if (
            self.srv.transport == transports.TRANSPORT.PROXY
            and self.srv.carries(L4.TCP)
            and self.srv.has_ipv6_tcp
            and not was_dual
            and self.transport is not None
            and not self.transport.is_dual_stack
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
        async with self.lock:
            # Asked again under the lock: the service may have been stopped while this
            # was waiting for it, and there is then no datapath to point anything at.
            if not self.active or self.transport is None:
                return
            # UDP is relayed by one socket per address — and QUIC by one endpoint per
            # address, for the same reason — so a new address is a new relay, opened on
            # the engine that is already running, before the rule that will point traffic
            # at it exists. The engine owns the map of them: `_steer`
            # carries that same dict, so what is opened here is what the rule finds.
            if self.srv.transport == transports.TRANSPORT.PROXY:
                for addr in added:
                    if transports.fronted_by_the_listener(self.srv, addr):
                        # A TCP address is fronted by the one shared listener, which
                        # recovers where each connection was headed from conntrack — so
                        # the only thing it can need told is that this address fronts a
                        # service somewhere else. An address that is simply the service
                        # needs nothing at all, which is every address until one says so.
                        #
                        # Which of the two it is, and in exactly which words, is
                        # `transports.announcement`'s to decide: the startup list the
                        # engine is launched with (`FGEX_PROXY_TARGETS`) is built from the
                        # same function, so an address that was there when the service
                        # started and one added a minute later cannot mean two things.
                        said = transports.announcement(self.srv, addr)
                        if said is not None:
                            # One announcement per address, and an interface stands for
                            # every address it carries: the engine keys this map on what
                            # `SO_ORIGINAL_DST` hands back, which is never an interface
                            # name. Skipped instead, an HTTPS edge added on `eth0:443`
                            # was never announced and the engine dialled :443 instead of
                            # the service.
                            for host in interface_addresses(addr.ip_int):
                                await self.transport.publish(
                                    (host, addr.port),
                                    said.word,
                                    said.onward,
                                    (host, said.target_port) if said.target_port else None,
                                )
                        continue
                    try:
                        host = udp_relay_host(addr.ip_int)
                    except NoRelayAddress as e:
                        raise transports.UnsupportedChain(str(e)) from e
                    # The relay's upstream *is* the answer to the same question: what is
                    # bound here forwards to where the service is, which is the target
                    # when there is one and the address itself when there is not.
                    await self.transport.add_udp_target(
                        host, addr.target_port or addr.port, UPSTREAM.env(addr.upstream)
                    )
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
                    # And the engine's own note of where this address fronted, so its
                    # map cannot come to disagree with the rules that feed it.
                    for addr in gone:
                        if (self.srv.transport == transports.TRANSPORT.PROXY
                                and transports.fronted_by_the_listener(self.srv, addr)):
                            # Every address it was announced under, or the engine keeps
                            # fronting one this service no longer protects.
                            for host in interface_addresses(addr.ip_int):
                                try:
                                    await self.transport.withdraw((host, addr.port))
                                except Exception as e:
                                    self.log.add(
                                        LEVEL.WARN,
                                        f"could not withdraw {addr.ip_int}: {e}")
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
        # Before any engine, which opens its socket to it at startup: an interface that
        # appears afterwards is one that process will not find until it is restarted.
        # Once, here, rather than per service: a capture tool is attached to it for the
        # length of a round, and an interface that comes and goes with the services
        # takes the tool with it.
        mirror.ensure()
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

    async def close(self):
        """Stop every service. Deliberately *not* the end of the capture interface.

        `reset()` closes and re-initialises without the process going anywhere, so
        releasing here would make the device disappear and come back underneath whatever
        was capturing from it — the exact failure it was made persistent to avoid.
        """
        for key in list(self.services.keys()):
            try:
                await self.remove(key, persist=False)
            except Exception:
                self.services.pop(key, None)

    def release_capture(self) -> None:
        """Take the capture interface away, at process shutdown and nowhere else."""
        mirror.release()

    def get(self, srv_id: str) -> ServiceManager:
        if srv_id not in self.services:
            raise ServiceNotFoundException()
        return self.services[srv_id]
