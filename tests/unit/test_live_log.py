"""The live log's batches, as the browser receives them.

The browser dedupes lines on `seq` across reconnects, so every line it is sent needs a
number of its own — including the one the flush writes itself to say how many lines did
not fit.
"""

import asyncio

from modules.services import logs


class _Socket:
    def __init__(self):
        self.sent = []

    async def emit(self, event, payload):
        self.sent.append((event, payload))


def test_the_line_saying_what_was_dropped_has_a_number_of_its_own(monkeypatch):
    """It used to reuse the last line's, and the browser kept whichever arrived first."""
    import utils

    socket = _Socket()
    monkeypatch.setattr(utils, "socketio", socket)
    monkeypatch.setattr(logs, "FLUSH_INTERVAL", 0)

    async def run():
        log = logs.ServiceLog("s")
        for n in range(logs.FLUSH_LIMIT + 5):
            log.add(logs.LEVEL.OUTPUT, f"line {n}")
        await log._flush_task
        return log

    log = asyncio.run(run())
    entries = [e for event, payload in socket.sent if event == "log"
               for e in payload["entries"]]
    seqs = [e["seq"] for e in entries] + [e["seq"] for e in log.entries()]
    summary = [e for e in entries if "more line(s)" in e["text"]]
    assert summary, "nothing said how many lines were dropped"
    assert seqs.count(summary[0]["seq"]) == 1, "the summary shares its number with a line"
