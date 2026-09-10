"""What each rule has actually refused, and when.

The service list carries a running total per filter, per pattern and per function, which
answers "is this rule doing anything at all". It does not answer the question an operator
asks during a competition — *when* did this start, and which rule is carrying it right
now — because a cumulative counter looks the same whether a filter blocked a thousand
connections an hour ago or is blocking them this minute.

So blocks are also counted into fixed time buckets, **per rule** rather than per filter.
Keeping the finer key is what lets every number on the page answer the same question: ask
for the last fifteen minutes and the chart, the totals and the shares all mean the last
fifteen minutes. Storing only per filter would have left the chart honouring the range
and the table beside it quietly reporting all of time.

Two properties keep that from becoming a liability of its own, and they are the same two
the live log has:

* **Bounded.** Only the last `HISTORY_BUCKETS` are kept, and older rows are pruned as new
  ones are written. A service that has been refusing traffic for a week stores the same
  amount as one that started an hour ago.
* **Coalesced.** A block bumps a counter in memory, and memory is written out at most
  every `FLUSH_INTERVAL` seconds. A service refusing thousands of connections a minute
  must not be able to take the backend down through its own bookkeeping — which is
  exactly what one row per block would do.

There is deliberately no background task. Flushing happens on the next write once the
interval has passed, and always on a read, so what the interface shows is current without
anything having to be started, cancelled or waited for at shutdown.
"""

import math
import time

#: The finest resolution anything is stored at. Every range the interface offers is an
#: aggregate of these, so a wider window costs no more rows — only wider bars.
BUCKET_SECONDS = 60

#: How far back the history goes. Two days at a minute each: long enough to cover a
#: competition and the night before it, small enough to stay a few thousand rows.
HISTORY_BUCKETS = 48 * 60

#: How long counts may sit in memory before being written out.
FLUSH_INTERVAL = 5

_pending: dict[tuple[str, str, str, int], int] = {}
_last_flush = 0.0


def bucket_of(when: float | None = None) -> int:
    return int((when if when is not None else time.time()) // BUCKET_SECONDS) * BUCKET_SECONDS


def retention_start() -> int:
    """The oldest instant anything is still known about."""
    return bucket_of() - (HISTORY_BUCKETS - 1) * BUCKET_SECONDS


def record(service_id: str, filter_id: str, rule_id: str, when: float | None = None) -> None:
    """Count one refusal. Cheap on purpose: this runs on the block path.

    `rule_id` is whatever the datapath reported — a pattern, or `<filter>/<function>`,
    or the filter itself. `filter_id` is carried alongside it so the chart can group by
    filter without a join back to a table the rule may have been deleted from.
    """
    key = (service_id, filter_id, rule_id, bucket_of(when))
    _pending[key] = _pending.get(key, 0) + 1


def flush(db, force: bool = False) -> None:
    """Write the counts out, and drop whatever has aged out of the window."""
    global _last_flush
    now = time.time()
    if not force and now - _last_flush < FLUSH_INTERVAL:
        return
    _last_flush = now
    if not _pending:
        return
    batch = list(_pending.items())
    _pending.clear()
    queries = [
        (
            "INSERT INTO block_history (service_id, filter_id, rule_id, bucket, blocked) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(rule_id, bucket) "
            "DO UPDATE SET blocked = blocked + excluded.blocked;",
            service_id,
            filter_id,
            rule_id,
            bucket,
            count,
        )
        for (service_id, filter_id, rule_id, bucket), count in batch
    ]
    # Pruning rides along with the write rather than being scheduled: there is no moment
    # at which rows can accumulate without something also having written one.
    queries.append(("DELETE FROM block_history WHERE bucket < ?;", retention_start()))
    db.queries(queries)


def forget(db, service_id: str) -> None:
    """A deleted service's history has nothing left to be about."""
    for key in [k for k in _pending if k[0] == service_id]:
        del _pending[key]
    db.query("DELETE FROM block_history WHERE service_id = ?;", service_id)


def forget_filter(db, filter_id: str) -> None:
    for key in [k for k in _pending if k[1] == filter_id]:
        del _pending[key]
    db.query("DELETE FROM block_history WHERE filter_id = ?;", filter_id)


def disown_rule(db, filter_id: str, rule_id: str) -> None:
    """Take a rule's history away from it without taking it off the chart.

    Editing a pattern keeps the row — its place in the filter, and whatever else was set
    on it — but the counts belonged to the text that used to be there, so the new text
    must not inherit them: a per-pattern table that carried them over would credit blocks
    to a matcher that never made them.

    What it must *not* do is delete them. Those connections were refused, by this filter,
    in those minutes, and the chart is answering *when this service was under attack* —
    a question a later typo fix has nothing to say about. Dropping the rows took a bite
    out of the timeline every time a pattern was corrected, which on a filter holding one
    pattern emptied it. So they are re-keyed to the filter itself, which is already the
    token the datapath reports when nothing finer named itself: the chart and the
    per-filter totals group by filter and do not change at all, while the per-pattern
    table correctly credits the new text with nothing.

    The pending batch moves with them, or the old pattern's last few hits would be
    flushed under the new one.
    """
    if filter_id == rule_id:
        return  # already the filter's own; there is nothing to take it away from
    for key in [k for k in _pending if k[2] == rule_id]:
        service_id, held_by, _, bucket = key
        moved = (service_id, held_by, filter_id, bucket)
        _pending[moved] = _pending.get(moved, 0) + _pending.pop(key)
    db.queries([
        (
            "INSERT INTO block_history (service_id, filter_id, rule_id, bucket, blocked) "
            "SELECT service_id, filter_id, ?, bucket, blocked FROM block_history "
            "WHERE rule_id = ? ON CONFLICT(rule_id, bucket) "
            "DO UPDATE SET blocked = blocked + excluded.blocked;",
            filter_id,
            rule_id,
        ),
        ("DELETE FROM block_history WHERE rule_id = ?;", rule_id),
    ])


#: Most bars any chart may hold, whatever step is asked for. Past this a plot stops
#: being a shape and becomes a texture, and the browser is drawing a rectangle per bar.
MAX_STEPS = 400


def bucket_width(start: int, end: int, target: int, want: int | None = None) -> int:
    """How wide one bar has to be for a range to stay readable.

    Two ways to say it, and both end at the same place. Without `want`, the window is
    shown in roughly `target` bars whatever it spans: twelve hours at one-minute
    resolution is seven hundred bars in a few hundred pixels. With `want`, the operator
    has picked the step themselves — five minutes is five minutes whether they are
    looking at an hour or at a day, which is what makes two ranges comparable by eye.

    Either way the answer is a whole number of stored buckets, so widening is addition
    and never interpolation, and either way it is floored at `MAX_STEPS` bars: a step
    fine enough to melt the chart is refused by widening it, not by refusing the request,
    and the width actually used is reported back so the interface can say what it drew.
    """
    span = max(BUCKET_SECONDS, end - start + BUCKET_SECONDS)
    least = math.ceil(span / BUCKET_SECONDS / MAX_STEPS)
    if want:
        steps = max(1, round(want / BUCKET_SECONDS))
    else:
        steps = max(1, math.ceil(span / BUCKET_SECONDS / max(1, target)))
    return BUCKET_SECONDS * max(1, steps, least)


def window(db, service_id: str, start: int, end: int, target: int = 60,
           want: int | None = None) -> dict:
    """What was refused between two instants, per filter, in even steps.

    Every step is present whether or not anything happened in it, because a chart with
    the quiet minutes missing is a chart that lies about the shape of a burst.
    """
    flush(db, force=True)
    start, end = bucket_of(start), bucket_of(end)
    if end < start:
        start, end = end, start
    width = bucket_width(start, end, target, want)
    # Aligned to the step, so the same range always lands on the same edges and a
    # refresh does not shuffle every bar sideways.
    first = (start // width) * width
    edges = list(range(first, end + width, width))
    index = {edge: i for i, edge in enumerate(edges)}

    series: dict[str, list[int]] = {}
    rows = db.query(
        "SELECT filter_id, bucket, SUM(blocked) blocked FROM block_history "
        "WHERE service_id = ? AND bucket >= ? AND bucket <= ? "
        "GROUP BY filter_id, bucket;",
        service_id,
        first,
        end,
    )
    for row in rows:
        slot = index.get((int(row["bucket"]) // width) * width)
        if slot is None:
            continue
        counts = series.setdefault(row["filter_id"], [0] * len(edges))
        counts[slot] += int(row["blocked"])
    return {"edges": edges, "width": width, "series": series}


def totals_by_filter(db, service_id: str, start: int, end: int) -> dict[str, int]:
    """What each filter refused in the range, summed over the rules inside it.

    Not a lookup of the filter's own id: that token only appears when a whole filter
    refused something without naming a rule. A regex block is reported by its pattern
    and a Python one by `<filter>/<function>`, so a filter's total is the sum of what
    its rules did — which is also what makes the per-filter figures add up to the total.
    """
    flush(db, force=True)
    start, end = bucket_of(start), bucket_of(end)
    if end < start:
        start, end = end, start
    return {
        row["filter_id"]: int(row["blocked"])
        for row in db.query(
            "SELECT filter_id, SUM(blocked) blocked FROM block_history "
            "WHERE service_id = ? AND bucket >= ? AND bucket <= ? GROUP BY filter_id;",
            service_id,
            start,
            end,
        )
    }


def totals(db, service_id: str, start: int, end: int) -> dict[str, int]:
    """What each rule refused in the range, keyed by whatever the datapath reported."""
    flush(db, force=True)
    start, end = bucket_of(start), bucket_of(end)
    if end < start:
        start, end = end, start
    return {
        row["rule_id"]: int(row["blocked"])
        for row in db.query(
            "SELECT rule_id, SUM(blocked) blocked FROM block_history "
            "WHERE service_id = ? AND bucket >= ? AND bucket <= ? GROUP BY rule_id;",
            service_id,
            start,
            end,
        )
    }
