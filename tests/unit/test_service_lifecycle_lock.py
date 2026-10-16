"""Two starts, or two stops, arriving at one service together.

A double click does it, and so does an operator's start racing the watchdog's restart.
`active` used to be asked before the lock was taken, so both calls saw a stopped service
and the second built a datapath of its own over the first — whose engine was left running
with nobody holding it. Two stops, likewise, both saw it running.
"""

import asyncio

import pytest

from modules.services import firewall
from modules.services.models import TRANSPORT, Service


class _Transport:
    def __init__(self, seen: dict):
        self.seen = seen

    async def start(self, chain):
        self.seen["start"] += 1
        await asyncio.sleep(0.05)
        return {}

    async def stop(self):
        self.seen["stop"] += 1
        await asyncio.sleep(0.05)

    async def retire(self, keep_filtering, then=None):
        await self.stop()
        if then:
            then()


class _Quiet:
    """Stands in for the rules, the log and the database: none of them is the question."""

    def add(self, *args, **kwargs):
        pass

    def delete(self, *args, **kwargs):
        return set()

    def release_guards(self, *args, **kwargs):
        pass

    def query(self, *args, **kwargs):
        return []


@pytest.fixture
def manager(monkeypatch):
    seen = {"start": 0, "stop": 0}
    monkeypatch.setattr(firewall, "nft", _Quiet())
    monkeypatch.setattr(firewall, "log_for", lambda service_id: _Quiet())
    monkeypatch.setattr(firewall.transports, "build", lambda srv, **kw: _Transport(seen))
    srv = Service(service_id="s", name="n", status="stop", proto="tcp",
                  transport=TRANSPORT.PROXY)
    return firewall.ServiceManager(srv, _Quiet()), seen


def test_two_starts_at_once_build_one_datapath(manager):
    service, seen = manager

    async def run():
        await asyncio.gather(service.enable(), service.enable())

    asyncio.run(run())
    assert seen["start"] == 1, "the second start built a datapath over the first"
    assert service.active


def test_two_stops_at_once_take_it_down_once(manager):
    service, seen = manager

    async def run():
        await service.enable()
        await asyncio.gather(service.disable(), service.disable())

    asyncio.run(run())
    assert seen["stop"] == 1, "the second stop tore down a datapath that was already gone"
    assert not service.active


class _Rules(_Quiet):
    """The rules, counted: how many times each service was steered, and un-steered."""

    def __init__(self):
        self.added = 0
        self.deleted = 0

    def add(self, *args, **kwargs):
        self.added += 1

    def delete(self, *args, **kwargs):
        self.deleted += 1
        return set()


def test_rules_are_not_put_back_behind_a_stop(manager, monkeypatch):
    """The table watchdog and a stop, at once.

    A stop takes the rules away before the datapath, and is suspended in between. Put
    back in that gap, they would outlive the stop — steering traffic at an engine that is
    gone — so putting them back waits for the same lock and finds nothing running.
    """
    service, _ = manager
    rules = _Rules()
    monkeypatch.setattr(firewall, "nft", rules)

    async def run():
        await service.enable()
        stopping = asyncio.create_task(service.disable())
        await asyncio.sleep(0.01)  # inside `disable`, waiting on the datapath
        await service.put_rules_back()
        await stopping

    asyncio.run(run())
    assert not service.active
    assert rules.added == 1, "the rules were put back behind the stop"


def test_rules_put_back_on_a_running_service_say_so(manager, monkeypatch):
    service, _ = manager
    rules = _Rules()
    monkeypatch.setattr(firewall, "nft", rules)
    said = []
    service.log = type("Log", (), {"add": lambda self, level, text: said.append((level, text))})()

    async def run():
        await service.enable()
        await service.put_rules_back()
        await service.put_rules_back()

    asyncio.run(run())
    assert rules.added == 3
    errors = [text for level, text in said if level == firewall.LEVEL.ERROR]
    assert len(errors) == 1, f"said once per quiet period, not once per time: {errors}"
