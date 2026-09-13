"""Patterns: what they refuse, how they are checked, and editing one in place.

Parametrised over every layer that inspects traffic. Running both is the whole point — a
pattern that only works on one of them is exactly the failure the unified model exists to
prevent. The two get there very differently (the proxy walks a list inside one process,
NFQUEUE chains one process per filter by base-chain priority), and none of that
difference is allowed to reach the operator.
"""

import base64
import time

import pytest

from integration.conftest import RELOAD, add_regex_filter, start_and_settle
from helpers.traffic import Channel

pytestmark = pytest.mark.instance


@pytest.fixture
def blocking(api, protected, filtering_layer):
    """A running service refusing anything carrying BLOCKME."""
    service_id, server, port = protected(filtering_layer, name="rx")
    filter_id, pattern_id = add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    channel = Channel(server, port, filtering_layer.ipv6, filtering_layer.tls)
    return service_id, filter_id, pattern_id, channel


def test_a_matching_pattern_blocks_and_a_clean_payload_does_not(blocking):
    _, _, _, channel = blocking
    assert channel.gets_through(b"harmless traffic")
    assert channel.is_blocked(b"carrying BLOCKME")


def test_a_pattern_split_across_two_writes_is_still_caught(blocking):
    """Why the matcher keeps per-connection state.

    Hyperscan runs in stream mode, so a pattern that lands across two writes is still the
    pattern however far apart the halves are — and one client's bytes can never decide
    another client's verdict.
    """
    _, _, _, channel = blocking
    got = channel.split_across_writes(b"split BLOC", b"KME here")
    assert not got or b"KME here" not in got, repr(got)


def test_the_block_is_counted_against_the_pattern_that_made_it(api, blocking):
    service_id, filter_id, _, channel = blocking
    assert channel.is_blocked(b"carrying BLOCKME")
    time.sleep(0.5)
    patterns = api.services_regexes(service_id, filter_id)
    assert any(p["blocked"] >= 1 for p in patterns), str(patterns)


def test_a_pattern_that_will_not_compile_is_refused_with_the_engines_own_reason(
        api, protected, inspecting_layer):
    """The engine that will run it is the one that validates it.

    Refused here rather than at start time, which is when an operator would find out
    otherwise — with the service already carrying traffic.
    """
    service_id, _, _ = protected(inspecting_layer, name="badrx")
    filter_id, _ = add_regex_filter(api, service_id, "BLOCKME")
    why = api.services_add_regex_error(service_id, filter_id, "(unclosed")
    assert why is not None, "a pattern that cannot compile was accepted"
    assert "parenthesis" in why.lower(), why


def test_a_refused_edit_leaves_the_rule_exactly_as_it_was(api, blocking):
    """A refusal that changes something is worse than no refusal.

    The operator is told their edit was rejected, and then finds it applied.
    """
    service_id, filter_id, pattern_id, channel = blocking
    assert channel.is_blocked(b"carrying BLOCKME")
    time.sleep(0.5)
    before = [p for p in api.services_regexes(service_id, filter_id)
              if p["regex_id"] == pattern_id][0]
    assert before["blocked"] >= 1, "nothing was counted, so this proves nothing"

    why = api.services_edit_regex_error(
        service_id, filter_id, pattern_id,
        regex=base64.b64encode(b"(unclosed").decode())
    assert why is not None, "a broken edit was accepted"
    after = [p for p in api.services_regexes(service_id, filter_id)
             if p["regex_id"] == pattern_id][0]
    assert after["regex"] == before["regex"]
    assert after["blocked"] == before["blocked"]


def test_editing_a_pattern_keeps_the_rule_and_drops_its_counters(api, blocking):
    """A typo is found while the service is running.

    Retyping the rule as a new one loses its place in the chain and drops the connections
    the filter is holding; editing keeps both. What it does not keep is the counters —
    those numbers were about the text that used to be there, and carrying them over would
    credit blocks to a matcher that never made them.
    """
    service_id, filter_id, pattern_id, channel = blocking
    assert channel.is_blocked(b"carrying BLOCKME")
    time.sleep(0.5)

    assert api.services_edit_regex(service_id, filter_id, pattern_id,
                                   regex=base64.b64encode(b"STOPME").decode())
    edited = [p for p in api.services_regexes(service_id, filter_id)
              if p["regex_id"] == pattern_id][0]
    assert edited["regex_id"] == pattern_id, "the rule lost its identity"
    assert edited["blocked"] == 0, str(edited)


def test_an_edit_reaches_the_datapath_not_only_the_table(api, blocking):
    service_id, filter_id, pattern_id, channel = blocking
    assert api.services_edit_regex(service_id, filter_id, pattern_id,
                                   regex=base64.b64encode(b"STOPME").decode())
    time.sleep(1.0)
    assert channel.is_blocked(b"carrying STOPME"), "the new pattern is not being enforced"
    assert channel.gets_through(b"carrying BLOCKME"), "the old pattern is still blocking"


def test_two_identical_patterns_in_one_filter_are_refused(api, blocking):
    """The second could never be the reason for anything, and the list would say otherwise."""
    service_id, filter_id, pattern_id, _ = blocking
    assert api.services_add_regex(service_id, filter_id, "OTHERONE")
    other = [p for p in api.services_regexes(service_id, filter_id)
             if base64.b64decode(p["regex"]) == b"OTHERONE"][0]
    why = api.services_edit_regex_error(
        service_id, filter_id, other["regex_id"],
        regex=base64.b64encode(b"BLOCKME").decode())
    assert why is not None, "one pattern was edited onto another"


def test_a_pattern_added_to_a_running_service_is_already_in_force(api, blocking):
    service_id, filter_id, _, channel = blocking
    assert api.services_add_regex(service_id, filter_id, "SECOND", mode="B")
    time.sleep(RELOAD)
    assert channel.is_blocked(b"carrying SECOND")
    assert channel.gets_through(b"harmless traffic"), "the rest of the traffic stopped too"


def test_case_sensitivity_is_honoured_per_pattern(api, protected, inspecting_layer):
    service_id, server, port = protected(inspecting_layer, name="case")
    filter_id, _ = add_regex_filter(api, service_id, "CaseExact", case_sensitive=True)
    assert api.services_add_regex(service_id, filter_id, "anycase", case_sensitive=False)
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)

    assert channel.gets_through(b"caseexact"), "a case-sensitive pattern matched the wrong case"
    assert channel.is_blocked(b"CaseExact")
    assert channel.is_blocked(b"ANYCASE"), "a case-insensitive pattern missed the wrong case"


def test_direction_decides_which_half_of_the_traffic_is_matched(
        api, protected, inspecting_layer):
    """A leaked flag shows up on the way out; an exploit on the way in.

    The stand-in echoes, so a pattern watching only the way *out* refuses a payload the
    client sent — but only once the service has sent it back.
    """
    service_id, server, port = protected(inspecting_layer, name="dir")
    add_regex_filter(api, service_id, "LEAKED", mode="S")
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    assert channel.is_blocked(b"carrying LEAKED")


def test_switching_a_pattern_off_stops_it_deciding(api, blocking):
    service_id, filter_id, pattern_id, channel = blocking
    assert api.services_edit_regex(service_id, filter_id, pattern_id, active=False)
    time.sleep(RELOAD)
    assert channel.gets_through(b"carrying BLOCKME"), "an inactive pattern still blocked"
    assert api.services_edit_regex(service_id, filter_id, pattern_id, active=True)
    time.sleep(RELOAD)
    assert channel.is_blocked(b"carrying BLOCKME"), "it did not start deciding again"
