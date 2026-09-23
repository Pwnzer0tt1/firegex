"""What the filter library offers, read out of the library itself.

The editor needs to know which models exist, what each one can be asked for, and which
of those can be written to. All of that is already stated once — in the classes the
library exposes and in `type_annotations_associations`, the table that decides when a
filter is called — so it is introspected rather than described a second time.

A hand-written list would have been quicker and would be wrong within a release: a
property added to `HttpRequest` would be missing from the hints, and one renamed would
be offered under a name that no longer resolves. Autocompletion that lies is worse than
none, for the same reason a regex tester that disagrees with the engine is.
"""

import inspect

#: Members every object has and nobody wants offered.
_SKIP = {"count", "index"}


def _clean(doc: str | None) -> str:
    return inspect.cleandoc(doc or "").strip()


def _members(cls) -> list[dict]:
    """The public properties of a model, with what they are for and whether they change.

    Writability is reported rather than assumed: the boundary the filter API rests on is
    that a filter reads and answers with a verdict, and an editor that says so while you
    type teaches it better than a paragraph in the documentation. Nothing is writable
    today — the payload was, for `UNSTABLE_MANGLE`, and stopped being with it.
    """
    out = []
    for name, member in inspect.getmembers(cls, lambda m: isinstance(m, property)):
        if name.startswith("_") or name in _SKIP:
            continue
        out.append({
            "name": name,
            "doc": _clean(member.__doc__),
            "writable": member.fset is not None,
        })
    for name, member in inspect.getmembers(cls, inspect.isfunction):
        if name.startswith("_") or name in _SKIP:
            continue
        try:
            signature = f"{name}{inspect.signature(member)}"
        except (TypeError, ValueError):
            signature = f"{name}(...)"
        out.append({"name": name, "doc": _clean(member.__doc__),
                    "writable": False, "signature": signature})
    return sorted(out, key=lambda m: m["name"])


def describe() -> dict:
    """Everything the editor is allowed to suggest, built from the live library."""
    from firegex.pyfilters import (
        ACCEPT, DROP, REJECT,  ExceptionAction, FullStreamAction,
    )
    from firegex.pyfilters.models import type_annotations_associations

    models: dict[str, dict] = {}
    for proto, types in type_annotations_associations.items():
        for cls in types:
            entry = models.setdefault(cls.__name__, {
                "name": cls.__name__,
                "doc": _clean(cls.__doc__),
                "members": _members(cls),
                "protocols": [],
            })
            entry["protocols"].append(proto)
    for entry in models.values():
        entry["protocols"].sort()

    verdicts = [
        {"name": "ACCEPT", "value": ACCEPT.value,
         "doc": "Forward this chunk. Returning None means the same thing."},
        {"name": "REJECT", "value": REJECT.value,
         "doc": "Refuse the connection. Everything still in the stream goes with it."},
        {"name": "DROP", "value": DROP.value,
         "doc": "Stop the connection's traffic. On NFQUEUE this chunk and every one after "
                "it are dropped without closing anything; on the proxy layer, where a "
                "stream cannot skip bytes, the connection is closed as REJECT does."},
    ]

    settings = [
        {"name": "FGEX_STREAM_MAX_SIZE",
         "doc": "Bytes of one stream a model may accumulate before "
                "FGEX_FULL_STREAM_ACTION decides what to do."},
        {"name": "FGEX_FULL_STREAM_ACTION",
         "doc": "What happens when a stream reaches that size.",
         "values": [f"FullStreamAction.{name}" for name in FullStreamAction.__members__]},
        {"name": "FGEX_INVALID_ENCODING_ACTION",
         "doc": "What happens when a parser cannot read the traffic — a reply that is "
                "not valid HTTP, for instance.",
         "values": [f"ExceptionAction.{name}" for name in ExceptionAction.__members__]},
    ]

    return {
        "models": sorted(models.values(), key=lambda m: m["name"]),
        "verdicts": verdicts,
        "settings": settings,
    }
