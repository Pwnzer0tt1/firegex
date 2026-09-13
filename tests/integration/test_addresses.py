"""Where a service is reachable, and changing that while it runs.

A service is one thing to protect and one way of intercepting it; *where* it answers is a
list. One daemon routinely answers on more than one address — a v4 and a v6 one, a public
and an internal one — and all of them deserve the same chain. Two services with
hand-copied chains is how one of them silently stops being protected.
"""

import time

import pytest

from integration.conftest import RELOAD, add_regex_filter, start_and_settle
from helpers.net import free_port
from helpers.traffic import Channel

pytestmark = pytest.mark.instance


@pytest.fixture
def running(api, protected, filtering_layer):
    service_id, server, port = protected(filtering_layer, name="addr")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    channel = Channel(server, port, filtering_layer.ipv6, filtering_layer.tls)
    return service_id, server, port, channel


def test_a_service_reports_where_it_is_reachable(api, running, filtering_layer):
    service_id, _, port, _ = running
    addresses = api.services_addresses(service_id)
    assert len(addresses) == 1 and addresses[0]["port"] == port, str(addresses)


def test_the_only_address_cannot_be_removed_and_the_refusal_says_why(api, running):
    """A service with nowhere to answer is not a service, it is a row."""
    service_id, _, _, _ = running
    only = api.services_addresses(service_id)[0]["address_id"]
    why = api.services_delete_address_error(service_id, only)
    assert why is not None, "the last address was removed"
    assert "only address" in why, why


def test_adding_an_address_to_a_running_service_drops_nothing(
        api, running, stand_in, certificate, filtering_layer):
    """Not a restart.

    The datapath is already up and already enforcing the chain, so this installs the
    rules that point one more address at it. The connections on the other addresses are
    untouched.
    """
    service_id, first, first_port, first_channel = running
    cert = certificate(filtering_layer.ip) if filtering_layer.tls else None
    second = stand_in(filtering_layer.ipv6, tls=cert)

    why = api.services_add_address_error(service_id, filtering_layer.ip, second.port)
    assert why is None, why
    assert len(api.services_addresses(service_id)) == 2
    time.sleep(1.0)

    second_channel = Channel(second, second.port, filtering_layer.ipv6, filtering_layer.tls)
    assert second_channel.gets_through(b"harmless traffic"), \
        "the new address is not carrying traffic"
    assert second_channel.is_blocked(b"carrying BLOCKME"), \
        "the same chain is not filtering the new address"
    assert first_channel.gets_through(b"harmless traffic"), \
        "the original address stopped working"


def test_the_log_says_an_address_was_added_without_dropping_anything(
        api, running, stand_in, certificate, filtering_layer):
    service_id, _, _, _ = running
    cert = certificate(filtering_layer.ip) if filtering_layer.tls else None
    second = stand_in(filtering_layer.ipv6, tls=cert)
    assert api.services_add_address_error(service_id, filtering_layer.ip, second.port) is None
    time.sleep(RELOAD)
    entries = api.services_logs(service_id)
    assert any("also protecting" in entry["text"] for entry in entries), str(entries[-4:])


def test_a_removed_address_stops_being_filtered_and_the_rest_keeps_going(
        api, running, stand_in, certificate, filtering_layer):
    """`address_removed` drops the address from the service's own list rather than
    re-reading the table, because the caller takes the rules back *before* deleting the
    row — re-reading would put it straight back, and the next restart would re-protect an
    address that no longer exists."""
    service_id, _, _, first_channel = running
    cert = certificate(filtering_layer.ip) if filtering_layer.tls else None
    second = stand_in(filtering_layer.ipv6, tls=cert)
    assert api.services_add_address_error(service_id, filtering_layer.ip, second.port) is None
    time.sleep(1.0)

    gone = [a for a in api.services_addresses(service_id)
            if a["port"] == second.port][0]["address_id"]
    assert api.services_delete_address(service_id, gone)
    time.sleep(1.0)

    second_channel = Channel(second, second.port, filtering_layer.ipv6, filtering_layer.tls)
    assert second_channel.gets_through(b"carrying BLOCKME"), \
        "the removed address is still being filtered"
    assert first_channel.is_blocked(b"carrying BLOCKME"), \
        "removing one address stopped the others being protected"


def test_an_address_can_be_a_network_interface_name(api, running):
    """An interface instead of a fixed IP or CIDR.

    Matched with `meta iifname` inbound and `meta oifname` outbound, so the traffic is
    intercepted on the interface without firegex needing to know an address for it.
    """
    service_id, _, _, _ = running
    port = free_port()
    why = api.services_add_address_error(service_id, "lo", port)
    assert why is None, why
    listed = [a for a in api.services_addresses(service_id) if a["ip_int"] == "lo"]
    assert len(listed) == 1, str(api.services_addresses(service_id))
    assert api.services_delete_address(service_id, listed[0]["address_id"])


def test_an_interface_is_refused_on_the_hand_off_layer(api, protected, external_layer):
    """The return rule rewrites the source address, which needs a concrete IP.

    Refused when the address is added rather than accepted and broken at start time.
    """
    service_id, _, _ = protected(external_layer, name="iface")
    why = api.services_add_address_error(service_id, "lo", free_port(),
                                         proxy_ip=external_layer.ip,
                                         proxy_port=free_port())
    assert why is not None, "an interface was accepted on the hand-off layer"
    assert "interface" in why.lower(), why


def test_two_services_cannot_claim_the_same_address_and_protocol(
        api, protected, service, inspecting_layer):
    """`(ip, port, proto)` is the uniqueness key, which is why the protocol is
    denormalised onto each address: a TCP service and a UDP one may share an address,
    exactly as the kernel allows, and two TCP ones may not."""
    _, _, port = protected(inspecting_layer, name="claim")
    clash = api.services_add_error(
        name=f"clash-{port}", transport=inspecting_layer.transport, proto="tcp",
        addresses=[{"ip_int": inspecting_layer.ip, "port": port}],
    )
    assert clash is not None, "two services claimed the same address and protocol"
