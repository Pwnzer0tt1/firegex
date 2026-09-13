"""Creating a service, starting it, and what it says about itself.

Parametrised over every layer, because a service is a service whichever one it is on —
the layer is a choice inside it, not a different kind of object.
"""

import pytest

from integration.conftest import start_and_settle
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
