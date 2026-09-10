"""Matching with the engine firegex actually matches with.

`fgex` exists so a filter can be tried before it ever reaches a running instance, and
that is only worth anything if the answer is the same one. For Python filters that is
easy — `fgex pyfilters` runs the very library the datapath runs. For patterns it means
hyperscan, because that is what both datapaths use, and a tester built on Python's `re`
would accept backreferences and lookarounds hyperscan rejects and disagree about what
matches. You would tune a pattern here and find out mid-round that it was never valid.

So this binds `libhs` directly, through ctypes: no build step, no wheel to go stale, and
by construction the same library the product loads. When it is not installed, the tools
say so and stop rather than quietly answering with a different engine.
"""

import ctypes
import ctypes.util
from dataclasses import dataclass
from enum import Enum

HS_SUCCESS = 0
HS_SCAN_TERMINATED = -3

HS_FLAG_CASELESS = 1
HS_FLAG_SINGLEMATCH = 8
HS_FLAG_ALLOWEMPTY = 16
HS_FLAG_SOM_LEFTMOST = 256

HS_MODE_BLOCK = 1
HS_MODE_STREAM = 2


class HyperscanMissing(RuntimeError):
    """libhs is not installed, and nothing here will guess in its place."""

    def __init__(self):
        super().__init__(
            "hyperscan (vectorscan) is not installed, and matching without it would "
            "give you answers firegex does not agree with.\n"
            "  Fedora:  dnf install vectorscan\n"
            "  Debian:  apt install libvectorscan5\n"
            "  Arch:    pacman -S vectorscan"
        )


class _CompileError(ctypes.Structure):
    _fields_ = [("message", ctypes.c_char_p), ("expression", ctypes.c_int)]


_MATCH_HANDLER = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_uint,  # id
    ctypes.c_ulonglong,  # from
    ctypes.c_ulonglong,  # to
    ctypes.c_uint,  # flags
    ctypes.c_void_p,  # context
)

_lib = None


def _hs():
    """Load libhs once, or explain why it cannot be."""
    global _lib
    if _lib is not None:
        return _lib
    name = ctypes.util.find_library("hs")
    candidates = [name] if name else []
    # find_library needs a toolchain to be reliable; the sonames are stable enough to
    # try directly when it comes back empty.
    candidates += ["libhs.so.5", "libhs.so", "libhs.dylib"]
    for candidate in candidates:
        try:
            lib = ctypes.CDLL(candidate)
        except OSError:
            continue
        lib.hs_compile_multi.restype = ctypes.c_int
        lib.hs_compile_multi.argtypes = [
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.POINTER(_CompileError)),
        ]
        lib.hs_free_database.argtypes = [ctypes.c_void_p]
        lib.hs_free_compile_error.argtypes = [ctypes.POINTER(_CompileError)]
        lib.hs_alloc_scratch.restype = ctypes.c_int
        lib.hs_alloc_scratch.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        lib.hs_free_scratch.argtypes = [ctypes.c_void_p]
        lib.hs_scan.restype = ctypes.c_int
        lib.hs_scan.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
            _MATCH_HANDLER,
            ctypes.c_void_p,
        ]
        _lib = lib
        return _lib
    raise HyperscanMissing()


def available() -> bool:
    """Whether matching is possible at all here."""
    try:
        _hs()
        return True
    except HyperscanMissing:
        return False


class Direction(str, Enum):
    """Which half of the traffic a rule looks at."""

    BOTH = "both"
    C2S = "c2s"
    S2C = "s2c"

    def covers(self, is_input: bool) -> bool:
        if self is Direction.BOTH:
            return True
        return (self is Direction.C2S) == is_input


class Action(str, Enum):
    BLOCK = "block"


@dataclass
class Rule:
    """One pattern, in the same shape firegex stores it."""

    id: str
    pattern: str
    direction: Direction = Direction.BOTH
    case_sensitive: bool = True
    action: Action = Action.BLOCK

    @classmethod
    def from_dict(cls, raw: dict) -> "Rule":
        return cls(
            id=str(raw.get("id", raw.get("regex_id", "?"))),
            pattern=raw["pattern"] if "pattern" in raw else raw["regex"],
            direction=Direction(raw.get("direction", "both")),
            case_sensitive=bool(raw.get("case_sensitive", True)),
            action=Action(raw.get("action", "block")),
        )


@dataclass
class Match:
    """Where a rule matched, and which one."""

    rule: Rule
    start: int
    end: int


class Database:
    """A compiled set of patterns. Immutable once built."""

    def __init__(self, rules: list[Rule], mode: int):
        lib = _hs()
        self.rules = list(rules)
        self._db = ctypes.c_void_p()
        self._scratch = ctypes.c_void_p()
        if not rules:
            raise ValueError("no patterns to compile")

        expressions = (ctypes.c_char_p * len(rules))(
            *[r.pattern.encode() for r in rules]
        )
        base = HS_FLAG_ALLOWEMPTY | (
            HS_FLAG_SINGLEMATCH if mode == HS_MODE_STREAM else HS_FLAG_SOM_LEFTMOST
        )
        flags = (ctypes.c_uint * len(rules))(
            *[base | (0 if r.case_sensitive else HS_FLAG_CASELESS) for r in rules]
        )
        ids = (ctypes.c_uint * len(rules))(*range(len(rules)))
        error = ctypes.POINTER(_CompileError)()
        rc = lib.hs_compile_multi(
            expressions, flags, ids, len(rules), mode, None,
            ctypes.byref(self._db), ctypes.byref(error),
        )
        if rc != HS_SUCCESS:
            message = "hyperscan could not compile the patterns"
            if error:
                if error.contents.message:
                    message = error.contents.message.decode(errors="replace")
                lib.hs_free_compile_error(error)
            raise ValueError(message)
        if lib.hs_alloc_scratch(self._db, ctypes.byref(self._scratch)) != HS_SUCCESS:
            raise RuntimeError("hyperscan could not allocate scratch space")

    def __del__(self):
        try:
            lib = _hs()
        except Exception:
            return
        if getattr(self, "_scratch", None):
            lib.hs_free_scratch(self._scratch)
        if getattr(self, "_db", None):
            lib.hs_free_database(self._db)

    def scan(self, data: bytes, limit: int = 1000) -> list[Match]:
        """Every match in one buffer, with where it started."""
        if not data:
            return []
        hits: list[Match] = []

        def on_match(rule_id, start, end, _flags, _ctx):
            hits.append(Match(self.rules[rule_id], int(start), int(end)))
            return -1 if len(hits) >= limit else 0

        rc = _hs().hs_scan(
            self._db, data, len(data), 0, self._scratch,
            _MATCH_HANDLER(on_match), None,
        )
        if rc not in (HS_SUCCESS, HS_SCAN_TERMINATED):
            raise RuntimeError(f"hyperscan scan failed ({rc})")
        return hits


def validate(rule: Rule) -> str | None:
    """Would firegex accept this rule? Returns hyperscan's own message if not.

    Checked against the mode it would actually run in: a blocking pattern is compiled
    for stream matching and a rewriting one for block scanning, and hyperscan does not
    accept quite the same patterns in both.
    """
    mode = HS_MODE_STREAM
    try:
        Database([rule], mode)
    except ValueError as e:
        return str(e)
    return None


class Ruleset:
    """A compiled ruleset, ready to be run over chunk after chunk.

    Compiled once and kept: hyperscan merges the automata of a whole set, so scanning
    for fifty patterns costs about what scanning for one costs — but only if the set is
    built once. Rebuilding per chunk would throw that away and make the cost of a rule
    proportional to the traffic.
    """

    def __init__(self, rules: list[Rule]):
        self.rules = list(rules)
        self._cache: dict[tuple[bool, Action], Database | None] = {}

    def _db(self, is_input: bool, action: Action) -> Database | None:
        key = (is_input, action)
        if key not in self._cache:
            selected = [
                r for r in self.rules
                if r.action is action and r.direction.covers(is_input)
            ]
            self._cache[key] = Database(selected, HS_MODE_BLOCK) if selected else None
        return self._cache[key]

    def apply(self, data: bytes, is_input: bool) -> tuple[str | None, bytes]:
        """Run the ruleset over one chunk, as the proxy datapath would.

        Returns the id of the rule that refused it, or `None` and the payload to
        forward — rewritten if any rewriting rule matched. Blocking is decided before
        rewriting, so a chunk that is going to be refused is not rewritten on its way
        there.

        One caveat this cannot hide: matching here is per chunk, while a *blocking* rule
        on a real service matches across the whole stream. A pattern split over two
        reads is caught there and not here, so a rule that does not fire in the
        simulator may still fire in production. Rewriting has the same scope in both,
        because bytes already forwarded cannot be taken back either way.
        """
        blocking = self._db(is_input, Action.BLOCK)
        if blocking:
            hits = blocking.scan(data, limit=1)
            if hits:
                return hits[0].rule.id, data
        return None, data


def load_rules(raw: list[dict]) -> list[Rule]:
    """Read a ruleset in the shape firegex itself uses, so one file works in both."""
    return [Rule.from_dict(item) for item in raw]
