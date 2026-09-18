"""The block history: what is counted, how it is bucketed, and what an edit does to it.

The backend's own module against a real SQLite file — no instance, no root, no datapath.
`integration/test_stats.py` asks the product whether the numbers come out; this asks the
arithmetic underneath, which is where the subtle part is.

The subtle part is `disown_rule`. Editing a pattern has to take its counts away from it —
they belonged to the text that used to be there — **without taking them off the chart**,
because those connections really were refused, by that filter, in those minutes, and the
chart is answering *when was this service under attack*. It used to delete the rows, which
bit a hole in the timeline on every correction and, on a filter holding one pattern,
emptied it. So the rows are re-keyed to the filter, and the invariant worth pinning is
that the per-filter view does not move at all while the per-pattern view forgets.

The schema comes from `routers/services.py` rather than being written out here. A second
copy of a table definition is a thing that drifts, and this is the one place it could
drift without anybody noticing: the test would go on passing against a shape the product
no longer has.
"""

import pytest

from modules.services import stats
from routers.services import db as services_db
from utils.sqlite import SQLite

SERVICE = "svc-1"
FILTER = "flt-1"
OTHER_FILTER = "flt-2"


@pytest.fixture
def db(tmp_path):
    """A database holding just the table this module writes to."""
    schema = {
        "block_history": services_db.schema["block_history"],
        "QUERY": [q for q in services_db.schema["QUERY"] if "block_history" in q],
    }
    handle = SQLite(str(tmp_path / "stats.db"), schema)
    handle.connect()
    handle.create_schema(schema)
    yield handle
    handle.disconnect()


@pytest.fixture(autouse=True)
def _no_leftovers():
    """Counts live in module globals until they are flushed, so a test must not inherit
    another's. Without this the first test to record something makes every later one
    depend on the order they ran in."""
    stats._pending.clear()
    stats._last_flush = 0.0
    yield
    stats._pending.clear()
    stats._last_flush = 0.0


def rows(db):
    return db.query("SELECT * FROM block_history ORDER BY rule_id, bucket;")


# --- bucketing ---------------------------------------------------------------


def test_a_bucket_is_a_whole_minute():
    edge = stats.bucket_of(1_700_000_000)
    assert edge % stats.BUCKET_SECONDS == 0
    assert stats.bucket_of(edge) == edge
    assert stats.bucket_of(edge + stats.BUCKET_SECONDS - 1) == edge
    assert stats.bucket_of(edge + stats.BUCKET_SECONDS) == edge + stats.BUCKET_SECONDS


def test_retention_starts_a_whole_window_back():
    span = stats.retention_start()
    assert span % stats.BUCKET_SECONDS == 0
    assert stats.bucket_of() - span == (stats.HISTORY_BUCKETS - 1) * stats.BUCKET_SECONDS


def test_a_wider_range_widens_the_bar_rather_than_adding_bars():
    """Twelve hours costs the same rows as one and is drawn in the same handful of bars."""
    hour = stats.bucket_width(0, 3600, target=60)
    half_day = stats.bucket_width(0, 12 * 3600, target=60)
    assert half_day > hour
    for span, width in ((3600, hour), (12 * 3600, half_day)):
        assert (span // width) + 1 <= 60 + 1


def test_an_explicit_step_is_rounded_to_whole_buckets():
    assert stats.bucket_width(0, 3600, target=60, want=300) == 300
    # 90s is a bucket and a half; nothing can be drawn at that resolution, so it lands on
    # the nearest whole number of them rather than being refused.
    assert stats.bucket_width(0, 3600, target=60, want=90) % stats.BUCKET_SECONDS == 0
    # Below one bucket is still one bucket: that is the resolution the rows have.
    assert stats.bucket_width(0, 3600, target=60, want=5) == stats.BUCKET_SECONDS


def test_a_step_fine_enough_to_melt_the_chart_is_widened_not_refused():
    span = stats.MAX_STEPS * 4 * stats.BUCKET_SECONDS
    width = stats.bucket_width(0, span, target=60, want=stats.BUCKET_SECONDS)
    assert width > stats.BUCKET_SECONDS
    assert (span // width) + 1 <= stats.MAX_STEPS + 1


# --- recording and flushing --------------------------------------------------


def test_nothing_reaches_the_database_until_it_is_flushed(db):
    stats.record(SERVICE, FILTER, "rule-a")
    assert rows(db) == []
    stats.flush(db, force=True)
    assert len(rows(db)) == 1


def test_repeated_blocks_in_one_minute_are_one_row(db):
    """The property the whole module exists for: a service refusing thousands of
    connections a minute must not be able to take the backend down through its own
    bookkeeping, which one row per block would do."""
    when = stats.bucket_of() + 1
    for _ in range(500):
        stats.record(SERVICE, FILTER, "rule-a", when=when)
    stats.flush(db, force=True)
    written = rows(db)
    assert len(written) == 1
    assert written[0]["blocked"] == 500


def test_two_flushes_of_the_same_bucket_add_up(db):
    when = stats.bucket_of()
    stats.record(SERVICE, FILTER, "rule-a", when=when)
    stats.flush(db, force=True)
    stats.record(SERVICE, FILTER, "rule-a", when=when)
    stats.flush(db, force=True)
    assert rows(db)[0]["blocked"] == 2


def test_flushing_prunes_what_has_aged_out(db):
    db.query(
        "INSERT INTO block_history (service_id, filter_id, rule_id, bucket, blocked) "
        "VALUES (?, ?, ?, ?, ?);",
        SERVICE, FILTER, "ancient", stats.retention_start() - stats.BUCKET_SECONDS, 7,
    )
    stats.record(SERVICE, FILTER, "rule-a")
    stats.flush(db, force=True)
    assert [r["rule_id"] for r in rows(db)] == ["rule-a"]


# --- reading it back ---------------------------------------------------------


def test_a_window_has_a_step_for_every_minute_including_the_quiet_ones(db):
    """A chart with the quiet minutes missing is a chart that lies about the shape of a
    burst."""
    now = stats.bucket_of()
    start = now - 4 * stats.BUCKET_SECONDS
    stats.record(SERVICE, FILTER, "rule-a", when=start)
    stats.record(SERVICE, FILTER, "rule-a", when=now)
    stats.flush(db, force=True)

    win = stats.window(db, SERVICE, start, now, target=60)
    assert win["width"] == stats.BUCKET_SECONDS
    assert len(win["edges"]) == 5
    assert win["series"][FILTER] == [1, 0, 0, 0, 1]


def test_a_wider_step_sums_the_minutes_inside_it(db):
    now = stats.bucket_of()
    start = now - 4 * stats.BUCKET_SECONDS
    for offset in range(5):
        stats.record(SERVICE, FILTER, "rule-a", when=start + offset * stats.BUCKET_SECONDS)
    stats.flush(db, force=True)

    win = stats.window(db, SERVICE, start, now, target=60, want=5 * stats.BUCKET_SECONDS)
    assert win["width"] == 5 * stats.BUCKET_SECONDS
    assert sum(win["series"][FILTER]) == 5


def test_a_window_asked_for_backwards_is_answered_forwards(db):
    now = stats.bucket_of()
    start = now - 2 * stats.BUCKET_SECONDS
    stats.record(SERVICE, FILTER, "rule-a", when=start)
    stats.flush(db, force=True)
    assert stats.window(db, SERVICE, now, start) == stats.window(db, SERVICE, start, now)


def test_totals_are_per_rule_and_per_filter_at_the_same_time(db):
    now = stats.bucket_of()
    stats.record(SERVICE, FILTER, "rule-a", when=now)
    stats.record(SERVICE, FILTER, "rule-b", when=now)
    stats.record(SERVICE, OTHER_FILTER, "rule-c", when=now)
    stats.flush(db, force=True)

    assert stats.totals(db, SERVICE, now, now) == {"rule-a": 1, "rule-b": 1, "rule-c": 1}
    assert stats.totals_by_filter(db, SERVICE, now, now) == {FILTER: 2, OTHER_FILTER: 1}


def test_another_services_blocks_are_not_counted(db):
    now = stats.bucket_of()
    stats.record(SERVICE, FILTER, "rule-a", when=now)
    stats.record("svc-2", "flt-9", "rule-z", when=now)
    stats.flush(db, force=True)
    assert stats.totals(db, SERVICE, now, now) == {"rule-a": 1}


# --- what an edit does to the history ----------------------------------------


def test_editing_a_pattern_hands_its_history_to_the_filter(db):
    """The per-filter view must not move, and the per-pattern view must forget."""
    now = stats.bucket_of()
    stats.record(SERVICE, FILTER, "rule-a", when=now)
    stats.record(SERVICE, FILTER, "rule-a", when=now - stats.BUCKET_SECONDS)
    stats.record(SERVICE, FILTER, "rule-b", when=now)
    stats.flush(db, force=True)

    start = now - stats.BUCKET_SECONDS
    before_chart = stats.window(db, SERVICE, start, now)
    before_filters = stats.totals_by_filter(db, SERVICE, start, now)

    stats.disown_rule(db, FILTER, "rule-a")

    # The chart and the per-filter totals are the same answer as before: those blocks
    # happened, and a later typo fix has nothing to say about when.
    assert stats.window(db, SERVICE, start, now) == before_chart
    assert stats.totals_by_filter(db, SERVICE, start, now) == before_filters

    # The pattern itself is credited with nothing, and the difference is now held under
    # the filter's own id — which is already the token the datapath reports when nothing
    # finer named itself, and is what the stats route reports as `residual`.
    counted = stats.totals(db, SERVICE, start, now)
    assert "rule-a" not in counted
    assert counted == {"rule-b": 1, FILTER: 2}


def test_disowning_merges_into_a_bucket_the_filter_already_had(db):
    now = stats.bucket_of()
    stats.record(SERVICE, FILTER, FILTER, when=now)      # the filter named itself
    stats.record(SERVICE, FILTER, "rule-a", when=now)
    stats.flush(db, force=True)

    stats.disown_rule(db, FILTER, "rule-a")
    assert stats.totals(db, SERVICE, now, now) == {FILTER: 2}


def test_the_pending_batch_moves_with_the_rule(db):
    """Counts still in memory belong to the old text too: flushed afterwards under the
    new one, they would credit a matcher that never made them."""
    now = stats.bucket_of()
    stats.record(SERVICE, FILTER, "rule-a", when=now)   # deliberately not flushed
    stats.disown_rule(db, FILTER, "rule-a")
    stats.flush(db, force=True)
    assert stats.totals(db, SERVICE, now, now) == {FILTER: 1}


def test_disowning_a_filters_own_id_is_a_no_op(db):
    now = stats.bucket_of()
    stats.record(SERVICE, FILTER, FILTER, when=now)
    stats.flush(db, force=True)
    stats.disown_rule(db, FILTER, FILTER)
    assert stats.totals(db, SERVICE, now, now) == {FILTER: 1}


# --- forgetting --------------------------------------------------------------


def test_a_deleted_filter_takes_its_history_with_it(db):
    now = stats.bucket_of()
    stats.record(SERVICE, FILTER, "rule-a", when=now)
    stats.record(SERVICE, OTHER_FILTER, "rule-c", when=now)
    stats.flush(db, force=True)

    stats.forget_filter(db, FILTER)
    assert stats.totals(db, SERVICE, now, now) == {"rule-c": 1}


def test_a_deleted_service_takes_its_history_with_it(db):
    now = stats.bucket_of()
    stats.record(SERVICE, FILTER, "rule-a", when=now)
    stats.record("svc-2", "flt-9", "rule-z", when=now)
    stats.flush(db, force=True)

    stats.forget(db, SERVICE)
    assert stats.totals(db, SERVICE, now, now) == {}
    assert stats.totals(db, "svc-2", now, now) == {"rule-z": 1}


def test_forgetting_drops_what_has_not_been_flushed_yet(db):
    now = stats.bucket_of()
    stats.record(SERVICE, FILTER, "rule-a", when=now)
    stats.forget(db, SERVICE)
    stats.flush(db, force=True)
    assert stats.totals(db, SERVICE, now, now) == {}
