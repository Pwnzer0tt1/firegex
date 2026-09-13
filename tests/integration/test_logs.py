"""The live log.

Two properties are load-bearing and easy to lose: the ring is capped, and the flush is on
a timer with a per-batch cap. A service refusing thousands of connections a minute must
not be able to take the backend or the browser down through its own logging.
"""

import time

import pytest

from integration.conftest import add_regex_filter, start_and_settle
from helpers.traffic import Channel

pytestmark = pytest.mark.instance


@pytest.fixture
def noisy(api, protected, inspecting_layer):
    service_id, server, port = protected(inspecting_layer, name="log")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    channel.is_blocked(b"carrying BLOCKME")
    time.sleep(0.8)
    return service_id, channel


def test_the_log_names_what_refused_the_connection(api, noisy):
    """An operator reading an opaque id mid-round learns nothing, which is the same as
    having no log. Both layers report `<filter>/<function>` or the pattern itself."""
    service_id, _ = noisy
    blocks = [e for e in api.services_logs(service_id) if e["level"] == "block"]
    assert blocks, "nothing was logged as a block"
    assert any("BLOCKME" in e["text"] for e in blocks), str(blocks[:3])


def test_the_log_is_bounded(api, noisy):
    service_id, channel = noisy
    for _ in range(40):
        channel.is_blocked(b"carrying BLOCKME")
    time.sleep(1.5)
    entries = api.services_logs(service_id)
    assert len(entries) <= 500, f"the ring grew to {len(entries)}"


def test_clearing_drops_what_came_before_and_nothing_after(api, noisy):
    """Not "empty": the service is still running, and a line arriving a millisecond later
    belongs in the log. What has to be gone is everything from before."""
    service_id, _ = noisy
    before = api.services_logs(service_id)
    assert before, "there was nothing to clear"

    assert api.services_clear_logs(service_id)
    after = api.services_logs(service_id)
    assert len(after) < len(before), f"{len(before)} -> {len(after)}"
    oldest_kept = min((e["seq"] for e in after), default=None)
    assert oldest_kept is None or oldest_kept > max(e["seq"] for e in before), \
        "an entry from before the clear survived it"


def test_every_entry_carries_a_monotonic_sequence_number(api, noisy):
    """The browser dedupes on it across reconnects."""
    service_id, _ = noisy
    entries = api.services_logs(service_id)
    seqs = [e["seq"] for e in entries]
    assert seqs == sorted(seqs), "the log came back out of order"
    assert len(set(seqs)) == len(seqs), "two entries share a sequence number"
