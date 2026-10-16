"""Holding up under load: the connection cap, and the deadline the cap cannot be.

The proxy layer only. NFQUEUE hands the kernel a verdict on packets already in flight; it
accepts nothing and dials nothing, so there is nothing for a limit to count.

Say what the cap buys and no more. **It does not save the service being attacked** — it
cannot tell a connection that is silent because it is an attack from one that is silent
because the client is slow, so an attacker who fills the limit still fills it. What it
buys is that one service's attacker stops being everyone's.
"""

import socket
import time

import pytest

from integration.conftest import start_and_settle
from helpers.net import loopback
from helpers.traffic import Channel

pytestmark = [pytest.mark.instance, pytest.mark.slow]


def _hold(host: str, port: int, count: int, ipv6: bool = False) -> list:
    """Open connections and say nothing on them, which is the shape of the attack.

    Two descriptors each — one from the client, one to the service, because the upstream
    is dialled on accept. About 505 of them exhausted a container's 1024 and took *every*
    service down, which is what the cap exists for.
    """
    held = []
    for _ in range(count):
        try:
            held.append(socket.create_connection((host, port), timeout=3))
        except OSError:
            break
    return held


def test_a_service_reports_the_limit_it_was_given(api, protected, proxy_layer):
    service_id, _, _ = protected(proxy_layer, name="cap", max_connections=4)
    start_and_settle(api, service_id, wait=1.5)
    listed = [s for s in api.services_list() if s["service_id"] == service_id][0]
    assert listed["max_connections"] == 4, str(listed)
    assert listed["over_limit_hits"] == 0, "it has turned something away already"


def test_the_limit_turns_away_what_does_not_fit_and_leaves_a_trace(api, protected,
                                                                   proxy_layer):
    """The trace is deliberately in two places.

    The log answers "why are clients failing right now" and is a bounded ring, so a burst
    at three in the morning is gone by breakfast. The columns answer "did we ever hit the
    wall", which is asked the next day.
    """
    service_id, _, port = protected(proxy_layer, name="capfull", max_connections=4)
    start_and_settle(api, service_id, wait=1.5)

    held = _hold(loopback(proxy_layer.ipv6), port, 12, proxy_layer.ipv6)
    try:
        time.sleep(3)
        listed = [s for s in api.services_list() if s["service_id"] == service_id][0]
        assert listed["over_limit_hits"] > 0, "the limit turned nothing away"
        assert listed["over_limit_first"] is not None, str(listed)
        assert listed["over_limit_last"] is not None, str(listed)
        assert any("limit" in e["text"].lower() for e in api.services_logs(service_id)), \
            str([e["text"] for e in api.services_logs(service_id)][-3:])
    finally:
        for connection in held:
            connection.close()


def test_the_count_outlives_the_engine_that_made_it(api, protected, proxy_layer):
    """The engine's counter is cumulative *per process*, so the transport hands up only
    the increase — passing the absolute number would reset the durable count on every
    restart of the service."""
    service_id, _, port = protected(proxy_layer, name="captrace", max_connections=4)
    start_and_settle(api, service_id, wait=1.5)

    held = _hold(loopback(proxy_layer.ipv6), port, 12, proxy_layer.ipv6)
    time.sleep(3)
    for connection in held:
        connection.close()
    time.sleep(1.5)

    was = [s for s in api.services_list() if s["service_id"] == service_id][0]
    assert was["over_limit_hits"] > 0, "nothing was turned away, so this proves nothing"

    api.services_stop(service_id)
    start_and_settle(api, service_id, wait=1.5)
    now = [s for s in api.services_list() if s["service_id"] == service_id][0]
    assert now["over_limit_hits"] >= was["over_limit_hits"], \
        f'{was["over_limit_hits"]} -> {now["over_limit_hits"]}'


def test_one_services_attacker_does_not_become_everyones(api, protected, proxy_layer):
    """The measured claim, and the only one the cap actually supports.

    400 silent connections against a limited service left the service beside it
    answering. Without the cap they exhausted the container's descriptors and took every
    service down.
    """
    victim_id, _, victim_port = protected(proxy_layer, name="victim", max_connections=4)
    neighbour_id, neighbour, neighbour_port = protected(proxy_layer, name="neighbour")
    start_and_settle(api, victim_id)
    start_and_settle(api, neighbour_id, wait=1.5)

    held = _hold(loopback(proxy_layer.ipv6), victim_port, 12, proxy_layer.ipv6)
    try:
        time.sleep(1.0)
        channel = Channel(neighbour, neighbour_port, proxy_layer.ipv6)
        assert channel.gets_through(b"NEIGHBOUR_ALIVE"), \
            "one service's attacker took its neighbour down"
    finally:
        for connection in held:
            connection.close()


def test_the_first_byte_deadline_frees_slots_while_the_attacker_still_holds_them(
        api, protected, proxy_layer):
    """What the cap cannot be.

    A cap contains a phantom flood; a deadline ends it. With the limit full and the
    attacker still holding every socket, clients get back in once it passes.
    """
    service_id, server, port = protected(proxy_layer, name="deadline",
                                         max_connections=4, first_byte_timeout=3)
    start_and_settle(api, service_id, wait=1.5)
    channel = Channel(server, port, proxy_layer.ipv6)

    held = _hold(loopback(proxy_layer.ipv6), port, 8, proxy_layer.ipv6)
    try:
        time.sleep(1)
        assert not channel.gets_through(b"knock knock", attempts=2), \
            "the limit let a client in while it was supposedly full"
        time.sleep(5)
        assert channel.gets_through(b"knock knock"), \
            "the deadline did not free the slots the attacker was holding"
    finally:
        for connection in held:
            connection.close()


def test_the_deadline_is_satisfied_by_whichever_end_speaks_first(api, protected,
                                                                 proxy_layer):
    """A service that greets its client — SMTP, SSH, most game protocols — satisfies it
    with its banner. Requiring the *client* to speak would hang every server-speaks-first
    protocol, and the failure would look like firegex breaking them at random."""
    service_id, server, port = protected(proxy_layer, name="firstbyte",
                                         first_byte_timeout=2)
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)
    assert channel.gets_through(b"the client spoke first")


def test_the_deadline_closes_a_connection_that_says_nothing_at_all(api, protected,
                                                                   proxy_layer):
    """And only until the first byte, never again: a connection that has spoken and gone
    quiet is a session, and sessions think. Making this an idle timeout would close
    long-lived connections that are legitimately waiting."""
    service_id, _, port = protected(proxy_layer, name="silent", first_byte_timeout=1)
    start_and_settle(api, service_id)

    client = socket.create_connection((loopback(proxy_layer.ipv6), port), timeout=5)
    try:
        time.sleep(2.5)
        assert client.recv(1024) == b"", \
            "a connection that said nothing was left open past the deadline"
    finally:
        client.close()


def test_a_connection_limit_is_not_offered_on_a_layer_that_cannot_count_one(
        api, service, stand_in):
    """Stored settings that do nothing are the trap this whole model argues against.

    NFQUEUE accepts nothing and dials nothing, so it is absent from the form there and
    reset when the layer changes.
    """
    server = stand_in()
    service_id = service(f"nfqcap-{server.port}", "127.0.0.1", server.port, "nfqueue",
                         max_connections=4)
    start_and_settle(api, service_id)
    listed = [s for s in api.services_list() if s["service_id"] == service_id][0]
    assert listed["over_limit_hits"] == 0, \
        "the queued layer reported turning connections away, which it cannot do"
