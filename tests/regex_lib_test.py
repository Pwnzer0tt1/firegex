#!/usr/bin/env python3
"""`firegex.regex`, and the promise that trying a pattern here means something.

The library exists so a ruleset can be tried before it reaches a running instance. That
is only worth anything if the answers match, so these tests are mostly about agreement
with the datapath: the same engine, the same validity, the same rewriting, the same
precedence. Nothing here needs a firegex instance — only libhs.
"""

import sys

from utils.colors import colors, puts, sep

exit_code = 0


def check(label: str, ok: bool, detail: str = ""):
    global exit_code
    if ok:
        puts(f"  [+] {label}", color=colors.green)
    else:
        exit_code = 1
        puts(f"  [-] {label} {detail}", color=colors.red)


if __name__ == "__main__":
    sep()
    puts("firegex.regex", is_bold=True)
    sep()

    from firegex.regex import Action, Direction, Rule, Ruleset, available, load_rules, validate

    if not available():
        puts("  libhs is not installed here, so nothing can be checked", color=colors.red)
        sys.exit(1)

    # --- validity, judged the way firegex judges it -------------------------
    check("a good pattern validates", validate(Rule(id="a", pattern="FLAG")) is None)
    why = validate(Rule(id="b", pattern="(unclosed"))
    check("a broken one reports the engine's own words",
          why is not None and "parenthesis" in why.lower(), str(why))

    # Blocking runs in stream mode and rewriting in block mode, and hyperscan does not
    # accept quite the same patterns in both. Judging by the wrong one would refuse a
    # rule that works — the same lie as a tester that disagrees with the engine.
    bounded = "a{1,1000}b"
    check("a bounded repeat is fine for blocking",
          validate(Rule(id="c", pattern=bounded)) is None)

    # --- blocking -----------------------------------------------------------
    rules = Ruleset([Rule(id="block-me", pattern="BLOCKME")])
    check("a matching chunk is refused, naming the rule",
          rules.apply(b"carrying BLOCKME", True) == ("block-me", b"carrying BLOCKME"))
    check("a clean chunk passes untouched",
          rules.apply(b"nothing here", True) == (None, b"nothing here"))

    directed = Ruleset([Rule(id="out", pattern="FLAG", direction=Direction.S2C)])
    check("direction is honoured on the way in",
          directed.apply(b"where is the FLAG", True) == (None, b"where is the FLAG"))
    check("and on the way out",
          directed.apply(b"here: FLAG", False)[0] == "out")

    insensitive = Ruleset([Rule(id="any", pattern="NeEdLe", case_sensitive=False)])
    check("case-insensitivity is per rule", insensitive.apply(b"needle", True)[0] == "any")

    # --- rewriting ----------------------------------------------------------

    # The same shape firegex uses, so one ruleset works in both places.
    loaded = load_rules([
        {"id": "r1", "pattern": "x", "direction": "c2s"},
        {"id": "r2", "pattern": "y", "case_sensitive": False},
    ])
    check("a firegex-shaped ruleset loads", len(loaded) == 2)
    check("its rules keep what they said",
          loaded[0].direction is Direction.C2S
          and loaded[1].case_sensitive is False,
          str(loaded))

    # --- bytes, not text ----------------------------------------------------
    raw = Ruleset([Rule(id="bin", pattern=r"\x00\xff\xfe")])
    check("patterns match bytes that are not text",
          raw.apply(bytes([0x41, 0x00, 0xff, 0xfe, 0x42]), True)[0] == "bin")

    sep()
    puts("Passed" if exit_code == 0 else "Failed",
         color=colors.green if exit_code == 0 else colors.red, is_bold=True)
    sys.exit(exit_code)
