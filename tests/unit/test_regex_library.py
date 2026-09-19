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


# --- the two answers a pattern can get, and why they are two ------------------


def test_an_empty_pattern_is_refused():
    """It compiles, and then it blocks everything.

    The flags have to allow a pattern that *can* match an empty buffer, because real
    ones like `a*` need it — so hyperscan accepts the empty pattern itself and then
    matches every buffer it is shown. A service whose chain holds one refuses all of its
    traffic, which on a CTF service reads as "firegex broke it". There is no legitimate
    way to ask for that and exactly one way to arrive at it by accident, which is an
    empty field in the form.
    """
    why = regex.validate(regex.Rule(id="e", pattern="", direction=regex.Direction.BOTH,
                                    case_sensitive=True))
    assert why is not None
    assert "empty" in why


def test_a_real_pattern_is_still_accepted():
    assert regex.validate(regex.Rule(id="r", pattern="FLAG\\{[a-z]+\\}",
                                     direction=regex.Direction.BOTH,
                                     case_sensitive=True)) is None


#: Valid, will run on a real service, and cannot be block-scanned. The asymmetry is
#: hyperscan's: reporting *where* a match started is a different mode from following a
#: stream, and it accepts slightly less.
STREAM_ONLY = "a{1,1000}b"


def test_a_pattern_can_be_valid_and_still_not_testable_here():
    rule = regex.Rule(id="big", pattern=STREAM_ONLY, direction=regex.Direction.BOTH,
                      case_sensitive=True)
    assert regex.validate(rule) is None, "it follows a stream perfectly well"
    assert regex.scannable(rule) is not None, "and cannot be matched against a sample"


def test_one_untestable_pattern_does_not_take_the_whole_ruleset_down():
    """`check` said the ruleset was valid and `test` raised a ValueError out of ctypes.

    Both answers were right and they were about different modes, which is precisely the
    kind of disagreement this module exists to prevent — so the ruleset now matches with
    the rules it can and says which ones it had to leave out.
    """
    rules = [
        regex.Rule(id="big", pattern=STREAM_ONLY, direction=regex.Direction.BOTH,
                   case_sensitive=True),
        regex.Rule(id="easy", pattern="FLAG", direction=regex.Direction.BOTH,
                   case_sensitive=True),
    ]
    ruleset = regex.Ruleset(rules)
    assert ruleset.apply(b"xx FLAG xx", True) == "easy"
    assert ruleset.apply(b"nothing here", True) is None
    assert list(ruleset.unscannable) == ["big"]


def test_a_ruleset_of_nothing_but_untestable_patterns_still_answers():
    ruleset = regex.Ruleset([
        regex.Rule(id="big", pattern=STREAM_ONLY, direction=regex.Direction.BOTH,
                   case_sensitive=True),
    ])
    assert ruleset.apply(b"aaab", True) is None
    assert list(ruleset.unscannable) == ["big"]


def test_an_ordinary_ruleset_leaves_nothing_out():
    """The reporting must stay empty for the normal case, or it means nothing."""
    ruleset = regex.Ruleset([
        regex.Rule(id="r", pattern="FLAG", direction=regex.Direction.BOTH,
                   case_sensitive=True),
    ])
    assert ruleset.apply(b"FLAG", True) == "r"
    assert ruleset.unscannable == {}
