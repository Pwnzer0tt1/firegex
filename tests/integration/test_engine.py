"""The proxy engine as a process: a way in nobody configured, and a death nobody asked for.

Both are about what surrounds the datapath rather than what it does to traffic. The
engine listens on an ephemeral port every local process can dial, and it runs as a
process that can die while the rules steering traffic at it stay where they are.
"""

import socket
import time

import pytest

from integration.conftest import add_regex_filter, start_and_settle
from helpers.host import as_root, engine_port, listening_pid
from helpers.traffic import Channel

pytestmark = [pytest.mark.instance, pytest.mark.root]


def _listener(port: int) -> int:
    found = engine_port(port)
    if found is None:
        pytest.skip("cannot read the nftables ruleset from here: not Linux, no root and no "
                    "passwordless sudo, or the instance under test is on another host")
    return found


def test_a_connection_dialled_straight_at_the_engine_is_turned_away(api, protected,
                                                                   proxy_layer):
    """Nothing redirected it, so it has nowhere to go but back into the engine.

    `SO_ORIGINAL_DST` on a connection no rule rewrote is the address it was accepted on —
    the engine's own port. The check against dialling ourselves compared with the address
    the listener was *bound* to, the wildcard, which no connection is ever accepted on:
    so it dialled itself, and that connection dialled itself, for as long as there were
    descriptors to spend. Any local process could set it off with one `connect`.
    """
    service_id, server, port = protected(proxy_layer, name="selfdial")
    start_and_settle(api, service_id)
    listener = _listener(port)

    with socket.create_connection((proxy_layer.ip, listener), timeout=5) as sock:
        sock.settimeout(5)
        try:
            closed = sock.recv(1) == b""
        except ConnectionResetError:
            closed = True
        except socket.timeout:
            closed = False
    assert closed, "the engine held a connection that could only have gone back into itself"

    channel = Channel(server, port, proxy_layer.ipv6)
    assert channel.gets_through(b"still answering"), \
        "the service stopped working after somebody dialled the engine directly"


def test_the_engine_killed_is_brought_back_with_its_filters(api, protected, proxy_layer):
    """The proxy layer's half of the watchdog the queued layer already had.

    Nothing watched the engine. Killed or crashed, it left its redirect in place, pointing
    at a port nobody listened on any more: every client of the service was refused, while
    the interface went on saying the service was active. The rules outlive the process on
    both layers, which is why the recovery restarts the service rather than the process.
    """
    service_id, server, port = protected(proxy_layer, name="enginedies")
    add_regex_filter(api, service_id, "BLOCK_ME_ENGINE")
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)
    assert channel.gets_through(b"harmless"), "the service was not working to begin with"

    pid = listening_pid(_listener(port))
    if pid is None:
        pytest.skip("cannot name the process behind the engine's port from here")
    as_root("kill", "-9", str(pid))

    deadline = time.monotonic() + 10
    said: list[str] = []
    while time.monotonic() < deadline:
        said = [e["text"] for e in api.services_logs(service_id)]
        restarted = [i for i, text in enumerate(said) if "restarting it" in text]
        if restarted and any("started on the" in text for text in said[restarted[-1]:]):
            break
        time.sleep(0.3)
    else:
        pytest.fail(f"the engine was not brought back: {said[-5:]}")

    assert any("exited on its own" in text for text in said), said[-5:]
    assert api.services_get(service_id)["status"] == "active"
    assert channel.gets_through(b"after the engine was killed"), \
        "the service was reported restarted and still refused its clients"
    assert channel.is_blocked(b"carrying BLOCK_ME_ENGINE"), \
        "the engine came back without the filters it had"
