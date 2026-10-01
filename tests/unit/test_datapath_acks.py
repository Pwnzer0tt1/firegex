"""What a datapath process's answer to a configuration push leaves running.

Both NFQUEUE binaries answer `ACK FAIL` with the filters they had still in force, so a
refusal is an error for the operator and nothing more. A push that is not answered at all
is different: whatever the process ends up doing is unknown, and its answer, if it comes,
would be read as the answer to the next command.
"""

import asyncio

import pytest

from modules.services import transports
from modules.services.models import KIND, Filter, Service, TRANSPORT
from modules.services.transports import ChainLink, NfqueueTransport, _QueueStage


class _Stdin:
    def write(self, data: bytes) -> None:
        self.data = data

    async def drain(self) -> None:
        pass


class _Process:
    def __init__(self):
        self.returncode = None
        self.stdin = _Stdin()
        self.killed = False

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def _stage() -> tuple[_QueueStage, _Process, list[str]]:
    said: list[str] = []
    srv = Service(service_id="s", name="n", status="active", proto="tcp",
                  transport=TRANSPORT.NFQUEUE)
    owner = NfqueueTransport(srv, on_engine=said.append)
    flt = Filter(filter_id="f1", service_id="s", position=0, kind=KIND.REGEX, name="p",
                 active=True)
    stage = _QueueStage(srv, ChainLink(flt), owner)
    stage.process = _Process()
    return stage, stage.process, said


def test_a_refused_push_leaves_the_binary_running():
    """It used to be stopped, and stopped *on purpose*, so its watchdog said nothing: the
    service went on reading active with no process behind its queue."""
    stage, process, _ = _stage()

    async def run():
        pushing = asyncio.create_task(stage._push(b"payload\n"))
        await asyncio.sleep(0)
        stage._ack.set_result((False, "Failed to compile hyperscan db"))
        with pytest.raises(Exception, match="rejected the filters"):
            await pushing

    asyncio.run(run())
    assert not process.killed
    assert stage.process is process and not stage._stopped


def test_an_unanswered_push_hands_the_binary_to_its_watchdog(monkeypatch):
    """Killed, and **not** marked stopped: its watchdog is what rebuilds the service from
    the saved configuration, and what the process had applied cannot be known."""
    monkeypatch.setattr(transports, "LOAD_TIMEOUT", 0.05)
    stage, process, said = _stage()

    async def run():
        with pytest.raises(Exception, match="did not acknowledge"):
            await stage._push(b"payload\n")

    asyncio.run(run())
    assert process.killed
    assert not stage._stopped
    assert any("restarting it" in line for line in said), said
