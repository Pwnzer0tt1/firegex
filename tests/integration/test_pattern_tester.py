"""The in-app pattern tester, which runs the engine that will enforce the answer.

That is the entire point. A tester built on Python's `re` or JavaScript's `RegExp` would
accept backreferences and lookarounds hyperscan rejects, and would disagree about what
matches — so a pattern would be tuned against it and found mid-round never to have been
valid. Here, a pattern the tester accepts is one that can be saved, and one it rejects
says why in hyperscan's own words.
"""

import pytest

pytestmark = pytest.mark.instance


def test_the_tester_finds_a_match_where_it_is(api):
    result = api.services_debug_regex(
        [{"id": "a", "expr": r"FLAG\{[a-z0-9]+\}", "case_sensitive": True}],
        b"give me FLAG{abc123} please")
    hits = {(m["id"], m["start"], m["end"]) for m in result.get("matches", [])}
    assert ("a", 8, 20) in hits, str(hits)


def test_the_tester_names_the_pattern_that_will_not_compile(api):
    """And only that one: a broken pattern beside a working one must not hide it."""
    result = api.services_debug_regex(
        [{"id": "a", "expr": "FLAG", "case_sensitive": True},
         {"id": "b", "expr": "(broken", "case_sensitive": True}],
        b"here is a FLAG")
    assert [e["id"] for e in result.get("errors", [])] == ["b"], str(result.get("errors"))
    assert any(m["id"] == "a" for m in result.get("matches", [])), str(result)


def test_case_sensitivity_is_honoured_by_the_tester_too(api):
    sensitive = api.services_debug_regex(
        [{"id": "a", "expr": "NeEdLe", "case_sensitive": True}], b"needle")
    assert sensitive.get("matches") == [], str(sensitive)
    insensitive = api.services_debug_regex(
        [{"id": "a", "expr": "NeEdLe", "case_sensitive": False}], b"needle")
    assert insensitive.get("matches"), str(insensitive)


def test_the_tester_agrees_with_what_can_actually_be_saved(api, protected,
                                                           inspecting_layer):
    """The property that makes the tester worth trusting: what it blesses, saving accepts,
    and what it refuses, saving refuses."""
    from integration.conftest import add_regex_filter

    service_id, _, _ = protected(inspecting_layer, name="tester")
    filter_id, _ = add_regex_filter(api, service_id, "PLACEHOLDER")

    blessed = r"FLAG\{[a-z0-9]+\}"
    assert api.services_debug_regex(
        [{"id": "a", "expr": blessed, "case_sensitive": True}], b"x").get("errors") == []
    assert api.services_add_regex(service_id, filter_id, blessed), \
        "the tester blessed a pattern that could not be saved"

    refused = "(unclosed"
    assert api.services_debug_regex(
        [{"id": "a", "expr": refused, "case_sensitive": True}], b"x").get("errors"), \
        "the tester accepted a pattern the engine rejects"
    assert api.services_add_regex_error(service_id, filter_id, refused) is not None, \
        "a pattern the tester refused was saved anyway"
