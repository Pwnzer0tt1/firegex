"""An edit refused by a rebuild, and a service that could not start at all.

Both used to leave the same thing behind: a service that was not running, while what the
operator was shown said otherwise. An edit whose rebuild failed was answered "refused" —
which reads as "nothing happened" — after the rebuild had already stopped the service. And
a service that could not come back at boot kept `active` in the database, which is what
the list showed, with nothing filtering it.
"""

import asyncio
from types import SimpleNamespace

import pytest

from modules.services import firewall
from modules.services.models import STATUS, TRANSPORT, Service


def _link(name: str):
    return SimpleNamespace(name=name, filter=SimpleNamespace(name=name, active=True))


class _Queued:
    """Stands in for the NFQUEUE layer: a new shape cannot be pushed, only rebuilt, and a
    chain holding the filter called `broken` does not start."""

    def __init__(self, started: list):
        self.started = started

    async def start(self, chain):
        names = [link.name for link in chain]
        self.started.append(names)
        if "broken" in names:
            raise Exception("the nfqueue binary rejected the filters")
        return {}

    async def reload(self, chain):
        raise firewall.transports.ChainShapeChanged()

    async def stop(self):
        pass

    async def retire(self, keep_filtering, then=None):
        if then:
            then()


class _Quiet:
    """The rules and the log: none of them is the question."""

    def add(self, *args, **kwargs):
        pass

    def delete(self, *args, **kwargs):
        return set()

    def release_guards(self, *args, **kwargs):
        pass


class _Db:
    def __init__(self):
        self.written = []

    def query(self, sql, *args):
        if sql.startswith("UPDATE"):
            self.written.append((sql, args))
        return []


@pytest.fixture
def service(monkeypatch):
    started = []
    state = {"chain": ["ok"]}
    monkeypatch.setattr(firewall, "nft", _Quiet())
    monkeypatch.setattr(firewall, "log_for", lambda service_id: _Quiet())
    monkeypatch.setattr(firewall.transports, "build", lambda srv, **kw: _Queued(started))
    srv = Service(service_id="s", name="n", status=STATUS.STOP, proto="tcp",
                  transport=TRANSPORT.NFQUEUE)
    db = _Db()
    manager = firewall.ServiceManager(srv, db)
    manager.chain = lambda: [_link(name) for name in state["chain"]]
    return manager, state, started, db


def test_a_rebuild_the_edit_cannot_survive_starts_the_service_again_as_it_was(service):
    manager, state, started, _ = service

    async def run():
        await manager.enable()
        state["chain"] = ["ok", "broken"]
        with pytest.raises(Exception):
            await manager.update_chain(lambda: state.update(chain=["ok"]))

    asyncio.run(run())
    assert manager.active, "an edit that was refused left the service stopped"
    assert started == [["ok"], ["ok", "broken"], ["ok"]], started


def test_the_undo_is_run_once_whoever_asks_for_it():
    """The manager runs it before starting the service again; the router's own `except`,
    which has always run it, now arrives second."""
    from routers.services import _once

    ran = []
    undo = _once(lambda: ran.append(1))
    undo()
    undo()
    assert ran == [1]
    _once(None)()  # nothing to undo is not an error


def test_stopping_a_service_that_could_not_start_is_remembered(service):
    """It is not running, so stopping it changed nothing in the kernel — but it is still
    a decision, and kept as `active` the next boot would try to start it again."""
    manager, state, _, db = service
    manager.srv.status = STATUS.ACTIVE  # what the database says: meant to run
    state["chain"] = ["broken"]

    async def run():
        with pytest.raises(Exception):
            await manager.enable()
        assert not manager.active
        await manager.disable()

    asyncio.run(run())
    assert manager.srv.status == STATUS.STOP
    assert any(args[0] == STATUS.STOP for _, args in db.written), db.written


def test_the_list_says_whether_a_service_is_running_not_whether_it_is_meant_to(monkeypatch):
    import routers.services as router

    class Manager:
        active = False

    monkeypatch.setitem(router.firewall.services, "x", Manager())
    assert router._running_status({"service_id": "x", "status": STATUS.ACTIVE}) == STATUS.STOP
    Manager.active = True
    assert router._running_status({"service_id": "x", "status": STATUS.STOP}) == STATUS.ACTIVE
    assert router._running_status({"service_id": "nobody", "status": STATUS.ACTIVE}) \
        == STATUS.ACTIVE, "a service the firewall does not know keeps what it stored"
