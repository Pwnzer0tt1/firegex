"""What each filter has refused, and when.

A cumulative counter answers "which rule is doing the work". The bucketed history answers
the other question — *when did this start* — which a cumulative counter cannot. Both are
on one page, so the load-bearing property is that **everything on that page counts the
same window**: a chart that honours a range with a table beside it reporting all of time
is a page that contradicts itself.
"""

import base64
import time

import pytest

from integration.conftest import add_regex_filter, start_and_settle
from helpers.traffic import Channel

pytestmark = pytest.mark.instance


@pytest.fixture
def with_blocks(api, protected, inspecting_layer):
    """A service that has refused something, on whichever inspecting layer."""
    service_id, server, port = protected(inspecting_layer, name="stats")
    filter_id, pattern_id = add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    for _ in range(3):
        channel.is_blocked(b"carrying BLOCKME")
    time.sleep(1.0)
    return service_id, filter_id, pattern_id, channel


def test_the_stats_name_every_filter_in_the_chain(api, with_blocks):
    service_id, _, _, _ = with_blocks
    stats = api.services_stats(service_id)
    chain = api.services_filters(service_id)
    assert {f["id"] for f in stats["filters"]} == {f["filter_id"] for f in chain}, \
        str(stats["filters"])


def test_the_totals_agree_with_the_per_pattern_counters(api, with_blocks):
    service_id, _, _, _ = with_blocks
    stats = api.services_stats(service_id)
    assert stats["total"] >= 1
    assert any(p["blocked"] >= 1 for p in stats["patterns"]), str(stats["patterns"])


def test_every_bucket_is_drawn_including_the_quiet_ones(api, with_blocks):
    """A chart with the quiet minutes missing lies about the shape of a burst.

    Every series is as long as the axis, and the steps are evenly spaced.
    """
    service_id, _, _, _ = with_blocks
    stats = api.services_stats(service_id)
    assert len(stats["buckets"]) >= 1
    assert all(len(s["counts"]) == len(stats["buckets"]) for s in stats["series"])
    assert all(b - a == stats["bucket_seconds"]
               for a, b in zip(stats["buckets"], stats["buckets"][1:])), str(stats["buckets"])
    assert sum(sum(s["counts"]) for s in stats["series"]) >= 1


def test_a_narrow_range_is_answered_by_the_chart_and_the_tables_alike(api, with_blocks):
    service_id, _, _, _ = with_blocks
    now = int(time.time())
    recent = api.services_stats(service_id, range_from=now - 900, range_to=now)
    assert recent["total"] >= 1
    assert recent["range_to"] - recent["range_from"] <= 900
    assert sum(f["blocked"] for f in recent["filters"]) == recent["total"], \
        str([(f["name"], f["blocked"]) for f in recent["filters"]])


def test_the_lifetime_figure_is_reported_beside_the_window_not_instead_of_it(
        api, with_blocks):
    """So a narrow window showing nothing is not read as a contradiction against the
    cards above it."""
    service_id, _, _, _ = with_blocks
    now = int(time.time())
    recent = api.services_stats(service_id, range_from=now - 900, range_to=now)
    assert recent["all_time"] >= recent["total"]


def test_a_range_that_ended_before_any_of_it_sees_nothing(api, with_blocks):
    """And is answered exactly as asked.

    Dragging its start forward to the service's own beginning would report the current
    minute's blocks under a range an hour old — buckets are minute-aligned, so a
    zero-width range is not an empty one.
    """
    service_id, _, _, _ = with_blocks
    now = int(time.time())
    old = api.services_stats(service_id, range_from=now - 7200, range_to=now - 3600)
    assert old["total"] == 0
    assert all(f["blocked"] == 0 for f in old["filters"])
    assert old["range_from"] < old["range_to"], str(old)


def test_a_wider_range_widens_the_bars_rather_than_multiplying_them(api, with_blocks):
    """Everything is an aggregate of the one-minute rows, so twelve hours costs the same
    rows as one and is drawn in the same handful of bars."""
    service_id, _, _, _ = with_blocks
    now = int(time.time())
    recent = api.services_stats(service_id, range_from=now - 900, range_to=now)
    wide = api.services_stats(service_id, range_from=now - 24 * 3600, range_to=now,
                              buckets=20)
    assert wide["bucket_seconds"] >= recent["bucket_seconds"]
    assert len(wide["buckets"]) <= 24, str(len(wide["buckets"]))


def test_the_step_can_be_asked_for_instead_of_derived(api, with_blocks):
    """Five minutes is five minutes whether you are looking at an hour or at a day, which
    is what makes two ranges comparable by eye."""
    service_id, _, _, _ = with_blocks
    now = int(time.time())
    stepped = api.services_stats(service_id, range_from=now - 6 * 3600, range_to=now,
                                 step=300)
    assert stepped["bucket_seconds"] == 300, str(stepped["bucket_seconds"])
    assert sum(sum(s["counts"]) for s in stepped["series"]) == stepped["total"]


def test_a_step_finer_than_the_history_is_widened_never_refused(api, with_blocks):
    """The request is reasonable, the chart it would draw is not — and the answer says
    which step it actually used rather than which was asked for."""
    service_id, _, _, _ = with_blocks
    now = int(time.time())
    melting = api.services_stats(service_id, range_from=now - 48 * 3600, range_to=now,
                                 step=1)
    assert melting["bucket_seconds"] >= 60
    assert len(melting["buckets"]) <= 400, str(len(melting["buckets"]))


def test_no_range_starts_before_the_service_began_filtering(api, with_blocks):
    """The hours before a service was running with a filter are not quiet hours.

    A chart of them reads as "nothing is happening" when it means "this did not exist
    yet". Every window is floored there, exactly as it is floored at what is still kept,
    and the range actually served says so.
    """
    service_id, _, _, _ = with_blocks
    now = int(time.time())
    wide = api.services_stats(service_id, range_from=now - 24 * 3600, range_to=now)
    began = wide["filtering_since"]
    assert began is not None and began <= now, str(began)
    assert wide["range_from"] == began
    assert api.services_stats(service_id, range_from=0,
                              range_to=now)["range_from"] == began


def test_asking_beyond_what_is_kept_is_clamped_and_says_how_far_back_that_is(
        api, with_blocks):
    service_id, _, _, _ = with_blocks
    now = int(time.time())
    wide = api.services_stats(service_id, range_from=now - 24 * 3600, range_to=now)
    assert api.services_stats(service_id, range_from=0,
                              range_to=now)["range_from"] >= wide["kept_from"]


def test_every_rule_reports_its_share_of_the_blocking(api, with_blocks):
    """Raw counts hide a chain where one pattern accounts for nearly everything.

    Computed in the backend, so a chart and the table beside it cannot disagree about
    what a rule accounts for.
    """
    service_id, _, _, _ = with_blocks
    stats = api.services_stats(service_id)
    assert any(f["blocked"] > 0 for f in stats["filters"])
    assert abs(sum(f["share"] for f in stats["filters"]) - 100) < 1.5, \
        str([(f["name"], f["blocked"], f["share"]) for f in stats["filters"]])
    assert all("share" in p for p in stats["patterns"])
    assert "functions" in stats, str(list(stats))


# --- editing a pattern hands its history to the filter --------------------------------


def test_editing_a_pattern_keeps_the_timeline_and_credits_the_new_text_with_nothing(
        api, with_blocks):
    """Those connections were refused, by that filter, in those minutes.

    The chart is answering *when this service was under attack*, and a later typo fix has
    nothing to say about that. Deleting the rows — which is what this used to do — took a
    bite out of the timeline on every correction, and on a filter holding one pattern it
    emptied the chart. They are re-keyed to the filter instead.
    """
    service_id, filter_id, pattern_id, _ = with_blocks
    before = api.services_stats(service_id)
    assert before["total"] >= 1, "nothing was blocked, so this proves nothing"

    assert api.services_edit_regex(service_id, filter_id, pattern_id,
                                   regex=base64.b64encode(b"STOPME").decode())
    after = api.services_stats(service_id)

    assert (sum(sum(s["counts"]) for s in after["series"])
            == sum(sum(s["counts"]) for s in before["series"])), \
        f"{before['series']} -> {after['series']}"
    assert after["total"] == before["total"]
    assert ([f["blocked"] for f in after["filters"]]
            == [f["blocked"] for f in before["filters"]])


def test_the_breakdown_names_what_no_rule_accounts_for_any_more(api, with_blocks):
    """Otherwise the per-pattern list quietly adds up to less than the chart above it,
    and the operator is left hunting for the difference."""
    service_id, filter_id, pattern_id, _ = with_blocks
    assert api.services_edit_regex(service_id, filter_id, pattern_id,
                                   regex=base64.b64encode(b"STOPME").decode())
    after = api.services_stats(service_id)
    assert any(row.get("residual") for row in after["patterns"]), str(after["patterns"])
    assert (sum(row["blocked"] for row in after["patterns"] + after["functions"])
            == after["total"]), f"{after['patterns']} + {after['functions']} vs {after['total']}"


# --- how much traffic arrived, in the unit each layer can honestly produce -------------


def test_the_kernels_own_counters_say_how_much_reached_a_queued_service(api, with_blocks,
                                                                        inspecting_layer):
    """Free, kernel-side, and unskewable, because no userspace filter produces them.

    Read from one inbound chain per transport: the nfqueue layer installs a rule pair per
    filter position all seeing the same packets, so summing them would multiply the
    answer by the length of the chain.
    """
    if inspecting_layer.transport != "nfqueue":
        pytest.skip("this is the packet-counting layer's claim")
    service_id, _, _, _ = with_blocks
    traffic = api.services_stats(service_id)["traffic"]
    assert traffic["packets"] > 0 and traffic["bytes"] > 0, str(traffic)


def test_the_proxy_layer_reports_no_packet_count_rather_than_a_wrong_one(
        api, with_blocks, inspecting_layer):
    """Its rule lives in a `nat` chain, and conntrack translates a connection once —
    every packet after the first is handled without the rule being walked again. That
    counter is new connections wearing a packet label, so it is dropped."""
    if inspecting_layer.transport != "proxy":
        pytest.skip("this is the connection-counting layer's claim")
    service_id, _, _, _ = with_blocks
    traffic = api.services_stats(service_id)["traffic"]
    assert traffic["packets"] == 0, str(traffic)


def test_the_proxy_layer_counts_connections_so_the_refused_share_is_exact(
        api, with_blocks, inspecting_layer):
    """The engine reports its counters on a timer, so this is a number that *arrives*
    rather than one that is there. Waiting for it is the test being correct about the
    contract, not lenient about it."""
    if inspecting_layer.transport != "proxy":
        pytest.skip("this is the connection-counting layer's claim")
    service_id, _, _, _ = with_blocks
    traffic = {}
    for _ in range(20):
        traffic = api.services_stats(service_id)["traffic"]
        if traffic.get("connections"):
            break
        time.sleep(0.5)
    assert traffic["connections"] is not None, str(traffic)
    assert traffic["refused_share"] is not None
    assert 0 < traffic["refused_share"] <= 100, str(traffic)


def test_the_per_packet_layer_reports_no_connection_share_rather_than_a_made_up_one(
        api, with_blocks, inspecting_layer):
    """Not a hole in the reporting: this layer inspects packets and has no connection to
    take a share of. Inventing one would mean dividing refused connections by a packet
    count. The asymmetry is the difference between the layers showing through."""
    if inspecting_layer.transport != "nfqueue":
        pytest.skip("this is the packet-counting layer's claim")
    service_id, _, _, _ = with_blocks
    traffic = api.services_stats(service_id)["traffic"]
    assert traffic["connections"] is None and traffic["refused_share"] is None, str(traffic)
