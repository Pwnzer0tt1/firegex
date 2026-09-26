"""Creating a service, starting it, and what it says about itself.

Parametrised over every layer, because a service is a service whichever one it is on —
the layer is a choice inside it, not a different kind of object.
"""

import time

import pytest

from integration.conftest import RELOAD, add_regex_filter, start_and_settle
from helpers.traffic import Channel

pytestmark = pytest.mark.instance


def test_a_created_service_is_listed_with_its_layer(api, protected, any_layer):
    service_id, _, port = protected(any_layer, name="listed")
    listed = [s for s in api.services_list() if s["service_id"] == service_id]
    assert len(listed) == 1, "the service was created but is not listed"
    assert listed[0]["transport"] == any_layer.transport
    assert listed[0]["proto"] == any_layer.proto


def test_a_created_service_is_stopped_until_it_is_started(api, protected, any_layer):
    service_id, _, _ = protected(any_layer, name="stopped")
    assert api.services_get(service_id)["status"] == "stop"


def test_a_started_service_carries_benign_traffic(api, protected, filtering_layer):
    service_id, server, port = protected(filtering_layer, name="benign")
    start_and_settle(api, service_id)
    channel = Channel(server, port, filtering_layer.ipv6, filtering_layer.tls)
    assert channel.gets_through(b"harmless traffic"), \
        "a service with no filter at all refused traffic"


def test_the_log_records_the_start(api, protected, any_layer):
    service_id, _, _ = protected(any_layer, name="logged")
    start_and_settle(api, service_id)
    entries = api.services_logs(service_id)
    assert any(entry["level"] == "info" and "started on the" in entry["text"]
               for entry in entries), str(entries[:3])


def test_a_stopped_service_stops_filtering_and_can_start_again(api, protected, proxy_layer):
    service_id, server, port = protected(proxy_layer, name="cycle")
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)
    assert channel.gets_through(b"before")

    assert api.services_stop(service_id)
    assert api.services_get(service_id)["status"] == "stop"

    start_and_settle(api, service_id)
    assert channel.gets_through(b"after"), "the service did not come back"


def test_a_tls_service_occupies_no_port_of_its_own(api, protected, tls_layer):
    """The engine decrypts at the address the world dials.

    There used to be two derived loopback ports per protected address — one for nginx to
    terminate on and one to re-encrypt from — chosen by hashing `ip:port`, which meant
    they could collide with something real. A TLS service now costs exactly what a plain
    one costs.
    """
    service_id, _, _ = protected(tls_layer, name="tlsport")
    start_and_settle(api, service_id)
    address = api.services_addresses(service_id)[0]
    assert "ssl_port" not in address and "clear_port" not in address, str(address)


def _held_open(server, payload: bytes) -> bytes | bool:
    try:
        server.send_packet(payload)
    except OSError:
        return False
    return server.recv_packet()


def _log_says(api, service_id: str, words: str, wait: float = 10) -> bool:
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if any(words in e["text"] for e in api.services_logs(service_id)):
            return True
        time.sleep(0.3)
    return False


def test_stopping_a_proxied_service_does_not_cut_its_connections(api, protected, proxy_layer):
    """Stopping takes the filters away, not the service.

    The proxy terminates every connection it carries, so killing it — which a stop did —
    cut them all: a download, a websocket, a request half answered. It is taken out of the
    rules instead, and carries what it already has until it closes. Unfiltered: a stop is
    how a filter that is hurting the service is taken out of the way, and it would not be
    if it went on judging the connections already open. New ones go straight to the service.
    """
    service_id, server, port = protected(proxy_layer, name="drain-stop")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)

    server.connect_client(timeout=3)
    try:
        assert _held_open(server, b"hello") == b"hello", "the connection did not work to begin with"
        assert api.services_stop(service_id)
        assert _held_open(server, b"still here") == b"still here", \
            "stopping the service cut a connection it was carrying"
        assert _held_open(server, b"carrying BLOCKME") == b"carrying BLOCKME", \
            "a stopped service went on filtering the connections it had"
        time.sleep(3)
        assert _held_open(server, b"a while later") == b"a while later"
        assert _log_says(api, service_id, "carry on unfiltered"), \
            "the log did not say connections were still being carried"
    finally:
        server.close_client()
    assert _log_says(api, service_id, "have all closed"), \
        "the stopped engine did not notice its last connection had closed"
    channel = Channel(server, port, proxy_layer.ipv6)
    assert channel.gets_through(b"carrying BLOCKME"), "a new connection did not reach the service"


def test_a_restart_hands_over_without_cutting_connections(api, protected, proxy_layer):
    """A change that rebuilds the engine starts a new one beside the old.

    New connections go to the new engine; the ones the old engine carries stay with it,
    under the filters they started with, until they close. Killing it — which a restart
    did — cut them all for an edit as small as the connection limit.
    """
    service_id, server, port = protected(proxy_layer, name="drain-restart")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)

    server.connect_client(timeout=3)
    try:
        assert _held_open(server, b"hello") == b"hello", "the connection did not work to begin with"
        assert api.services_edit(service_id, max_connections=100)
        time.sleep(RELOAD)
        assert _held_open(server, b"still here") == b"still here", \
            "a restart cut a connection the old engine was carrying"
        assert _held_open(server, b"carrying BLOCKME") != b"carrying BLOCKME", \
            "a connection carried through a restart lost its filters"
    finally:
        server.close_client()
    channel = Channel(server, port, proxy_layer.ipv6)
    assert channel.gets_through(b"harmless"), "the new engine did not take new connections"
    assert channel.is_blocked(b"carrying BLOCKME"), "the new engine came up without the filters"
