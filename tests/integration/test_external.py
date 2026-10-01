"""The hand-off: firegex steers traffic into a proxy the operator wrote, and runs nothing.

Note the shape of these tests. Linux refuses a loopback connection to a port with no
listener *without emitting a packet*, so no rule can rescue it — a hand-off test has to
keep the real service listening and tell the two apart by their replies, not by which one
fails to answer. The stand-in proxy answers with a marker; the real service echoes.
"""

import pytest

from integration.conftest import EXTERNAL_MARKER, start_and_settle
from helpers.traffic import reaches

pytestmark = pytest.mark.instance


def test_traffic_aimed_at_the_service_reaches_your_proxy_instead(api, protected,
                                                                 external_layer):
    service_id, server, _ = protected(external_layer, name="ext")
    start_and_settle(api, service_id)
    assert reaches(server.external, EXTERNAL_MARKER), \
        "the traffic reached the real service instead of the operator's proxy"


def test_the_log_records_the_hand_off(api, protected, external_layer):
    service_id, _, _ = protected(external_layer, name="extlog")
    start_and_settle(api, service_id)
    entries = api.services_logs(service_id)
    assert any("started on the external layer" in e["text"] for e in entries), \
        str(entries[-3:])


def test_attaching_a_filter_to_a_running_hand_off_is_refused_naming_the_reason(
        api, protected, external_layer):
    """A filter here would be one that never runs.

    No firegex process is in the path — the rules rewrite the destination and change it
    back — so a filter attached to this layer is not a slow filter or a weak one, it is a
    filter that is never consulted. Refused at the moment it is attached rather than
    accepted and broken later.
    """
    service_id, _, _ = protected(external_layer, name="extflt")
    start_and_settle(api, service_id)
    why = api.services_add_filter_error(service_id, "regex", "patterns")
    assert why is not None, "a filter was attached to a running hand-off"
    assert "would never run" in why, why


def test_a_filter_stored_while_stopped_refuses_the_start_with_the_same_reason(
        api, protected, external_layer):
    """Stopped, the service is only configuration, so the filter is stored — and then
    starting is what refuses. A row that is created happily and then refuses to start
    every time is a trap, so the reason is the same one either way."""
    service_id, _, _ = protected(external_layer, name="extstop")
    assert api.services_add_filter(service_id, "regex", "patterns")
    filter_id = api.services_filters(service_id)[0]["filter_id"]

    why = api.services_start_error(service_id)
    assert why is not None, "a hand-off with a filter started"
    assert "would never run" in why, why

    assert api.services_delete_filter(service_id, filter_id)
    start_and_settle(api, service_id)


def test_two_addresses_cannot_share_one_proxy_endpoint(api, protected, external_layer):
    """The return rule recognises the operator's proxy by address and port to put the
    original port back, so two addresses behind one endpoint could not be told apart on
    the way out."""
    from helpers.net import free_port

    service_id, server, _ = protected(external_layer, name="extdup")
    why = api.services_add_address_error(
        service_id, external_layer.ip, free_port(external_layer.ipv6),
        proxy_ip=external_layer.ip, proxy_port=server.external.port)
    assert why is not None, "two addresses were allowed to share one proxy endpoint"
    # The *reason*, not just a refusal. Asserting only that something was refused is what
    # let this pass for as long as the sentence naming the endpoint was unreachable: the
    # operator was told one of their addresses was taken, which points at the service
    # address while the thing colliding is their proxy's port.
    assert "proxy endpoint" in why, why


def test_an_endpoint_nobody_typed_is_still_an_endpoint(api, protected, external_layer):
    """Two addresses cannot share a proxy endpoint, including when neither named one.

    `proxy_ip` may be left out — such a proxy is normally on loopback, and that is what
    the rules used when nothing said otherwise. But the uniqueness rule is a partial
    index on `(proxy_ip, proxy_port)` and SQLite counts every NULL as **distinct**, so
    leaving it out used to mean any number of addresses could sit behind one endpoint:
    stored apart, resolved to the same loopback port, and indistinguishable to the return
    rule that has to put the original port back.
    """
    from helpers.net import free_port

    service_id, _, _ = protected(external_layer, name="extnull")
    shared = free_port(external_layer.ipv6)

    assert api.services_add_address(
        service_id, external_layer.ip, free_port(external_layer.ipv6),
        proxy_port=shared), "an address with an unstated proxy address was refused"

    why = api.services_add_address_error(
        service_id, external_layer.ip, free_port(external_layer.ipv6),
        proxy_port=shared)
    assert why is not None, \
        "two addresses were allowed to share one endpoint by not naming it"
    assert "proxy endpoint" in why, why
