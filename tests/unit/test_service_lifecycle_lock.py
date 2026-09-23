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


class _Quiet:
    """Stands in for the rules, the log and the database: none of them is the question."""

    def add(self, *args, **kwargs):
        pass

    def delete(self, *args, **kwargs):
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
