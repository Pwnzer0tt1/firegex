"""Combinations that are refused *before* anything starts, and the reasons given.

`Transport.check()` is where an impossible combination is turned away, and it is asked
twice: at creation with an empty chain, for what the *service* alone makes impossible,
and again whenever a chain is pushed, for what the *chain* makes impossible. A row that
is created happily and then refuses to start every time is a trap.

A refused edit must also change nothing. `_apply_chain(service_id, undo)` rolls the write
back when the transport rejects the resulting chain — without it an operator is told
their filter was rejected and then finds it in the list, and the next start fails for the
reason they thought they had avoided.
"""

import pytest

from integration.conftest import add_regex_filter, start_and_settle

pytestmark = pytest.mark.instance

#: One binary and one pair of base chains per filter position, at `-307 + position` and
#: `107 + position`. That is what makes the ceiling real rather than arbitrary: each
#: filter costs a process and a reassembly pass.
MAX_CHAIN_POSITIONS = 8


def _fill_chain(api, service_id: str, count: int):
    for position in range(count):
        assert api.services_add_filter(service_id, "regex", f"f{position}"), \
            f"could not attach filter {position} while the service was stopped"


def test_a_queued_chain_longer_than_the_ceiling_refuses_the_start(api, protected):
    """A stopped service is only configuration, so the filters are stored.

    The refusal arrives when there is a chain to push — which for a stopped service is
    the moment it is started. That is the "asked twice" design: at creation, with an
    empty chain, for what the *service* makes impossible, and again whenever a chain is
    pushed, for what the *chain* does.
    """
    from integration.conftest import Layer

    service_id, _, _ = protected(Layer("nfqueue"), name="long")
    _fill_chain(api, service_id, MAX_CHAIN_POSITIONS + 1)

    why = api.services_start_error(service_id)
    assert why is not None, \
        f"a chain of {MAX_CHAIN_POSITIONS + 1} filters started on the queued layer"
    assert str(MAX_CHAIN_POSITIONS) in why, why


def test_the_ceiling_counts_active_filters_so_switching_one_off_lets_it_start(
        api, protected):
    """Deactivating is the way out the refusal itself offers, so it has to work."""
    from integration.conftest import Layer

    service_id, _, _ = protected(Layer("nfqueue"), name="deact")
    _fill_chain(api, service_id, MAX_CHAIN_POSITIONS + 1)
    assert api.services_start_error(service_id) is not None

    spare = api.services_filters(service_id)[-1]["filter_id"]
    assert api.services_edit_filter(service_id, spare, active=False)
    assert api.services_start_error(service_id) is None, \
        "switching a filter off did not bring the chain under the ceiling"


def test_a_refused_chain_change_leaves_the_chain_as_it_was(api, protected):
    """Told it was rejected, and then finding it in the list, is the failure this prevents.

    Asked of a *running* service, which is where a chain is pushed as it is edited:
    `_apply_chain(service_id, undo)` rolls the write back when the transport refuses the
    resulting chain. Without it the next start fails for the reason the operator thought
    they had avoided.
    """
    from integration.conftest import Layer

    service_id, _, _ = protected(Layer("nfqueue"), name="undo")
    _fill_chain(api, service_id, MAX_CHAIN_POSITIONS)
    start_and_settle(api, service_id)
    before = api.services_filters(service_id)
    assert len(before) == MAX_CHAIN_POSITIONS

    why = api.services_add_filter_error(service_id, "regex", "one-too-many")
    assert why is not None, "a filter past the ceiling was attached to a running service"
    after = api.services_filters(service_id)
    assert len(after) == len(before), \
        f"a refused filter was stored anyway: {len(before)} -> {len(after)}"
    assert [f["name"] for f in after] == [f["name"] for f in before], str(after)


def test_the_chain_can_be_reordered_and_the_order_is_what_runs(api, protected,
                                                               inspecting_layer):
    """`parse_ruleset` groups patterns by their filter id and keeps the positions the
    backend sent. An earlier version grouped every block and then the Python, which turned
    the chain into a set — a filter placed after another could run before it, and nothing
    said so."""
    service_id, _, _ = protected(inspecting_layer, name="order")
    add_regex_filter(api, service_id, "FIRST", name="alpha")
    add_regex_filter(api, service_id, "SECOND", name="beta")
    chain = api.services_filters(service_id)
    assert [link["name"] for link in chain] == ["alpha", "beta"], str(chain)

    reversed_ids = [link["filter_id"] for link in reversed(chain)]
    assert api.services_reorder_filters(service_id, reversed_ids)
    assert [link["name"] for link in api.services_filters(service_id)] == ["beta", "alpha"]


def test_editing_a_pattern_inside_a_running_chain_costs_nobody_their_connection(
        api, protected, inspecting_layer):
    """Changing the *shape* of a queued chain cannot be pushed — the shape is the
    arrangement of processes and rules, so `NfqueueTransport.reload` raises
    `ChainShapeChanged` and the service is rebuilt, saying so. Editing a pattern inside an
    existing filter is a different thing entirely."""
    import base64
    import time

    from helpers.traffic import Channel

    service_id, server, port = protected(inspecting_layer, name="live")
    filter_id, pattern_id = add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)

    server.connect_client()
    try:
        server.send_packet(b"hello")
        assert server.recv_packet() == b"hello"
        assert api.services_edit_regex(service_id, filter_id, pattern_id,
                                       regex=base64.b64encode(b"STOPME").decode())
        time.sleep(1.0)
        server.send_packet(b"still here")
        assert server.recv_packet() == b"still here", \
            "a pattern edit dropped a connection the filter was holding"
    finally:
        server.close_client()
    assert channel.is_blocked(b"carrying STOPME")
