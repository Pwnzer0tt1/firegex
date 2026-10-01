"""A proxy engine taken out of service carries its connections until they close.

The proxy terminates every connection it carries, so a stop or a restart that killed it
cut them all. `ProxyTransport.retire` lets it go on instead, and ends it as soon as it
reports none left — or at `DRAIN_LIMIT`, or when too many engines of one service are
draining at once. Driven here against a stand-in process, because the interesting part
is the bookkeeping, and the integration suite cannot wait ten minutes.
"""

import asyncio
import time

import pytest

from modules.services import transports
from modules.services.models import TRANSPORT, Service


class _Process:
    def __init__(self):
        self.returncode = None

    def kill(self):
        self.returncode = -9

    async def wait(self):
        return self.returncode


@pytest.fixture
def engine(monkeypatch):
    monkeypatch.setattr(transports, "DRAIN_FRESH_AFTER", 0)
    monkeypatch.setattr(transports, "_draining", {})
    said: list[str] = []

    def _build(live: int):
        srv = Service(service_id="drain", name="n", status="active", proto="tcp",
                      transport=TRANSPORT.PROXY)
        t = transports.ProxyTransport(srv, on_engine=said.append)
        t.process = _Process()
        t.counters["live"] = live
        return t

    return _build, said


def _report(t, live: int):
    """What a `STATS` line arriving now does."""
    t.counters["live"] = live
    t._stats_at = time.monotonic()


def test_it_goes_as_soon_as_its_last_connection_does(engine):
    build, said = engine
    gone = []

    async def run():
        t = build(live=2)
        process = t.process
        await t.retire(keep_filtering=True, then=lambda: gone.append(True))
        _report(t, 2)
        await asyncio.sleep(1.2)
        assert process.returncode is None, "killed while it still carried connections"
        _report(t, 0)
        await asyncio.sleep(1.2)
        assert process.returncode is not None, "left running with nothing to carry"

    asyncio.run(run())
    assert gone == [True], "its ports were never released"
    assert any("under the filters they started with" in line for line in said), said
    assert any("have all closed" in line for line in said), said


def test_a_count_from_before_it_was_taken_out_does_not_end_it(engine, monkeypatch):
    """`live=0` said before the rules came off says nothing about what arrived since."""
    build, _ = engine
    monkeypatch.setattr(transports, "DRAIN_FRESH_AFTER", 60)

    async def run():
        t = build(live=0)
        _report(t, 0)
        await t.retire(keep_filtering=False)
        await asyncio.sleep(1.2)
        assert t.process.returncode is None
        await t._end_drain(None)

    asyncio.run(run())


def test_connections_that_never_close_are_closed_at_the_limit(engine, monkeypatch):
    build, said = engine
    monkeypatch.setattr(transports, "DRAIN_LIMIT", 1)

    async def run():
        t = build(live=3)
        process = t.process
        await t.retire(keep_filtering=True)
        _report(t, 3)
        await asyncio.sleep(2)
        assert process.returncode is not None

    asyncio.run(run())
    assert any(line.startswith("[warn]") and "still open" in line for line in said), said


def test_only_so_many_engines_of_a_service_drain_at_once(engine):
    build, said = engine

    async def run():
        engines = [build(live=1) for _ in range(transports.MAX_DRAINING + 1)]
        processes = [t.process for t in engines]
        for t in engines:
            await t.retire(keep_filtering=True)
            _report(t, 1)
        assert processes[0].returncode is not None, "the oldest was kept"
        assert all(p.returncode is None for p in processes[1:])
        assert len(transports._draining["drain"]) == transports.MAX_DRAINING
        await transports.stop_draining()
        assert all(p.returncode is not None for p in processes)
        assert not transports._draining

    asyncio.run(run())
    assert any("were closed" in line for line in said), said


def test_an_engine_already_dead_is_simply_cleaned_up(engine):
    build, _ = engine
    gone = []

    async def run():
        t = build(live=0)
        t.process.returncode = 1
        await t.retire(keep_filtering=True, then=lambda: gone.append(True))
        assert not transports._draining

    asyncio.run(run())
    assert gone == [True]
