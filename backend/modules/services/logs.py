"""What a running service is actually doing, as it does it.

Everything interesting a datapath has to say — a connection refused and by which rule,
a filter that printed something, a filter that raised, a warning about falling back —
used to go to the backend's own stderr, where nobody looks during a competition. This
keeps a bounded tail of it per service and pushes new lines to the browser.

Two properties matter more than the feature itself:

**It cannot grow.** A service under attack blocks thousands of connections a minute and
a filter in a print loop produces output as fast as the traffic arrives. The ring is
capped and the oldest lines fall off; nothing here can turn logging into an outage.

**It cannot flood the browser.** Lines are coalesced and flushed on a timer rather than
emitted one by one, and a flush that would carry more than it should says how many it
dropped instead of carrying them.

The same flush is also what tells the browser that the **counters** moved. A block bumps
a filter's total, a pattern's, a function's and the bucketed history, and the interface
holds all of those with `staleTime: Infinity` — nothing refetches on its own, so without
a signal the numbers and the chart sit still while the log scrolls past underneath them.
Riding the flush that already exists beats a second timer, and it is exactly true: the
lines that carry a block are the events that change a counter. It is throttled harder
than the log, because invalidating every query of a service is a heavier thing to ask of
the browser than appending a line.
"""

import asyncio
import time
from collections import deque

import utils

#: Lines kept per service. Enough to see what just happened, small enough that a
#: hundred services cost a few megabytes between them.
HISTORY = 500

#: How long lines are allowed to pile up before the browser is told. Long enough that a
#: burst becomes one message, short enough to still read as live.
FLUSH_INTERVAL = 0.25

#: Most lines carried in a single flush. Beyond this the browser is told the count
#: rather than the content — a thousand identical block lines inform nobody.
FLUSH_LIMIT = 50

#: How often a service may tell the browser its counters are stale. Much slower than the
#: log's own flush: this one invalidates every query of the service — its filters, its
#: patterns, its functions, its statistics — and doing that four times a second under
#: attack would be its own kind of flood.
COUNTER_INTERVAL = 2.0


class LEVEL:
    INFO = "info"
    BLOCK = "block"
    OUTPUT = "output"
    WARN = "warn"
    ERROR = "error"


class ServiceLog:
    """One service's rolling tail, and the pending batch on its way to the browser."""

    def __init__(self, service_id: str):
        self.service_id = service_id
        self.history: deque[dict] = deque(maxlen=HISTORY)
        self._pending: list[dict] = []
        self._dropped = 0
        self._flush_task: asyncio.Task | None = None
        #: When the browser was last told that this service's counters had moved, and
        #: the emit waiting for the current window to close.
        self._counters_told = 0.0
        self._counters_task: asyncio.Task | None = None
        #: Counts every line ever added, so the frontend can tell "nothing new" from
        #: "the tail happens to look the same".
        self.seq = 0

    def add(self, level: str, text: str) -> None:
        for line in text.splitlines() or [""]:
            line = line.rstrip()
            if not line:
                continue
            self.seq += 1
            entry = {"at": int(time.time() * 1000), "level": level, "text": line, "seq": self.seq}
            self.history.append(entry)
            if len(self._pending) < FLUSH_LIMIT:
                self._pending.append(entry)
            else:
                self._dropped += 1
        self._schedule()

    def _schedule(self) -> None:
        if self._flush_task and not self._flush_task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no loop to emit on; the history still has the lines
        self._flush_task = loop.create_task(self._flush_later())

    async def _flush_later(self) -> None:
        await asyncio.sleep(FLUSH_INTERVAL)
        entries, dropped = self._pending, self._dropped
        self._pending, self._dropped = [], 0
        if not entries:
            return
        if dropped:
            # A number of its own. It used to reuse the last line's, which the browser
            # dedupes on: whichever of the two arrived second was thrown away, and it was
            # usually this one — the only line saying how much had not been shown.
            self.seq += 1
            entries.append({
                "at": int(time.time() * 1000),
                "level": LEVEL.WARN,
                "text": f"... and {dropped} more line(s) in the same instant",
                "seq": self.seq,
            })
        # Reached through the module rather than imported by value: `utils.socketio` is
        # assigned when the app starts, so a direct import would capture the `None` it
        # holds at import time and silently never emit anything.
        try:
            if utils.socketio is not None:
                await utils.socketio.emit(
                    "log", {"service_id": self.service_id, "entries": entries}
                )
                await self._tell_counters_moved(entries)
        except Exception:
            pass  # a browser that is not listening is not a reason to disturb the datapath

    async def _tell_counters_moved(self, entries: list[dict]) -> None:
        """Say that the totals and the chart are out of date, at most every so often.

        Only for blocks: they are the lines that come with a counter having changed. A
        filter's `print()` or a warning moves nothing, and invalidating every query of
        the service for one would be work done for no reason.

        Rate-limited with a **trailing** emit rather than by dropping what falls inside
        the window. Dropping was the first version and it left the interface frozen on
        stale numbers: a burst emitted once at its start, every flush after that was
        discarded, and when the traffic stopped there was no further flush to carry the
        final count — so the chart sat at whatever it happened to reach two seconds in.
        The last block of a burst is precisely the one worth hearing about.
        """
        # A warning or an error changes the service list too: it carries the latest one
        # (`last_problem`).
        if not any(entry["level"] in (LEVEL.BLOCK, LEVEL.WARN, LEVEL.ERROR)
                   for entry in entries):
            return
        waited = time.monotonic() - self._counters_told
        if waited >= COUNTER_INTERVAL:
            await self._emit_counters()
            return
        # Inside the window: one emit is scheduled for when it closes, and further
        # blocks arriving before then fold into it.
        if self._counters_task and not self._counters_task.done():
            return
        self._counters_task = asyncio.get_running_loop().create_task(
            self._emit_counters_after(COUNTER_INTERVAL - waited)
        )

    async def _emit_counters_after(self, delay: float) -> None:
        await asyncio.sleep(delay)
        try:
            await self._emit_counters()
        except Exception:
            pass  # a browser that is not listening is not a reason to raise here

    async def _emit_counters(self) -> None:
        self._counters_told = time.monotonic()
        if utils.socketio is not None:
            await utils.socketio_emit(["services"])

    def entries(self) -> list[dict]:
        return list(self.history)

    def last_problem(self) -> dict | None:
        """The newest warning or error still in the tail, for the service list to show.

        The live log is on the service's own page, and a warning nobody has that page open
        for is a warning nobody reads: a datapath that died and came back, a filter that
        raised, a fallback that lost the client's address. The list carries the latest one
        beside the service, and clearing the log is how it is acknowledged.
        """
        for entry in reversed(self.history):
            if entry["level"] in (LEVEL.WARN, LEVEL.ERROR):
                return entry
        return None

    def clear(self) -> None:
        self.history.clear()
        self._pending.clear()
        self._dropped = 0


_logs: dict[str, ServiceLog] = {}


def log_for(service_id: str) -> ServiceLog:
    log = _logs.get(service_id)
    if log is None:
        log = _logs[service_id] = ServiceLog(service_id)
    return log


def forget(service_id: str) -> None:
    """Drop a deleted service's tail, so nothing outlives what it was about."""
    _logs.pop(service_id, None)
