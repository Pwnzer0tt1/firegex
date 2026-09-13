"""`firegex.regex`, and the promise that trying a ruleset there means something.

The library exists so a ruleset can be tried before it reaches a running instance. That
is only worth anything if the answers match, so these are mostly about agreement with the
datapath: the same engine, the same validity, the same precedence. Nothing here needs a
firegex instance — only libhs, which is the same library the product loads, bound through
ctypes rather than reimplemented.
"""

import pytest

regex = pytest.importorskip("firegex.regex")

pytestmark = pytest.mark.skipif(
    not regex.available(),
    reason="libhs is not installed here, so there is no engine to agree with",
)


def test_a_good_pattern_validates():
    assert regex.validate(regex.Rule(id="a", pattern="FLAG")) is None


def test_a_broken_pattern_reports_the_engines_own_words():
    why = regex.validate(regex.Rule(id="b", pattern="(unclosed"))
    assert why is not None
    assert "parenthesis" in why.lower(), why


def test_a_bounded_repeat_is_judged_by_the_mode_it_will_run_in():
    """`a{1,1000}b` streams but does not block-scan.

    A pattern is compiled for stream matching, because that is how it follows a
    connection across chunk boundaries. Judging it by the other mode would refuse a rule
    that works — the same class of lie as a tester that disagrees with the engine.
    """
    assert regex.validate(regex.Rule(id="c", pattern="a{1,1000}b")) is None


def test_a_matching_chunk_is_refused_naming_the_rule():
    rules = regex.Ruleset([regex.Rule(id="block-me", pattern="BLOCKME")])
    assert rules.apply(b"carrying BLOCKME", True) == "block-me"


def test_a_clean_chunk_passes():
    rules = regex.Ruleset([regex.Rule(id="block-me", pattern="BLOCKME")])
    assert rules.apply(b"nothing here", True) is None


def test_direction_is_honoured_both_ways():
    directed = regex.Ruleset(
        [regex.Rule(id="out", pattern="FLAG", direction=regex.Direction.S2C)])
    assert directed.apply(b"where is the FLAG", True) is None
    assert directed.apply(b"here: FLAG", False) == "out"


def test_case_insensitivity_is_per_rule():
    insensitive = regex.Ruleset(
        [regex.Rule(id="any", pattern="NeEdLe", case_sensitive=False)])
    assert insensitive.apply(b"needle", True) == "any"


def test_patterns_match_bytes_that_are_not_text():
    raw = regex.Ruleset([regex.Rule(id="bin", pattern=r"\x00\xff\xfe")])
    assert raw.apply(bytes([0x41, 0x00, 0xFF, 0xFE, 0x42]), True) == "bin"


def test_a_firegex_shaped_ruleset_loads_and_keeps_what_it_said():
    loaded = regex.load_rules([
        {"id": "r1", "pattern": "x", "direction": "c2s"},
        {"id": "r2", "pattern": "y", "case_sensitive": False},
    ])
    assert len(loaded) == 2
    assert loaded[0].direction is regex.Direction.C2S
    assert loaded[1].case_sensitive is False


def test_a_ruleset_asking_to_rewrite_is_refused_rather_than_quietly_blocking():
    """Rewriting was withdrawn from firegex, so it has to be withdrawn here too.

    A simulator that accepted a rule the product cannot express — and then blocked on it
    instead — would be exactly the disagreement this library exists to make impossible.
    Silently treating `rewrite` as `block` is the worse failure of the two, because the
    ruleset would look like it had been understood.
    """
    with pytest.raises(ValueError, match="can only block"):
        regex.load_rules([
            {"id": "r", "pattern": "FLAG", "action": "rewrite", "with": "redacted"},
        ])


def test_an_explicit_block_action_is_still_accepted():
    """Old ruleset files carry it, and it says exactly what happens."""
    assert regex.load_rules([{"id": "r", "pattern": "x", "action": "block"}])[0].id == "r"
