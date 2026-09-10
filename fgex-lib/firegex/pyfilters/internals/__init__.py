from inspect import Parameter, signature
from itertools import product
from firegex.pyfilters.internals.models import Action, ExceptionAction, FullStreamAction
from firegex.pyfilters.internals.models import FilterHandler, PacketHandlerResult
import functools
from firegex.pyfilters.internals.data import DataStreamCtx
from firegex.pyfilters.internals.exceptions import NotReadyToRun, StreamFullReject, DropPacket, RejectConnection, StreamFullDrop
from firegex.pyfilters.internals.data import RawPacket

def _type_name(annotation) -> str:
    return getattr(annotation, "__name__", None) or str(annotation)


def _wanted_by(filters: list[str], glob: dict) -> list[tuple[str, object, list[object]]]:
    """`(name, func, annotations)` for each named filter, looked up once.

    Both passes below need the same three things, and reading them twice is how the two
    ended up disagreeing about what to say when an annotation is not a model — one
    complained that no protocol provides it, the other that this file's protocol does
    not. One reading, one message.
    """
    found = []
    for name in filters:
        if not isinstance(name, str):
            raise Exception("Invalid filter list: must be a list of strings")
        func = glob.get(name)
        if func is None:
            raise Exception(f"Filter {name} not found")
        if not callable(func):
            raise Exception(f"{func} is not a function")
        annotations = []
        for param, spec in signature(func).parameters.items():
            if spec.annotation is Parameter.empty:
                # The library decides when to call a filter from what it asks for, so a
                # parameter that asks for nothing leaves it with nothing to go on.
                raise Exception(
                    f"Parameter {param!r} of {name} has no type annotation. Annotate it "
                    f"with what the filter wants to be given — RawPacket, a TCP stream, "
                    f"an HTTP model — because that is what decides when it is called."
                )
            annotations.append(spec.annotation)
        found.append((name, func, annotations))
    return found


def infer_proto(wanted: list[tuple[str, object, list[object]]]) -> str:
    """Which application protocol a file speaks, read off what it asks for.

    A filter file does not declare its protocol; it shows it. Asking for an
    `HttpRequest` is what makes a file an HTTP filter, and asking only for a
    `RawPacket` or a TCP stream is what makes one protocol-agnostic — so the same file
    can hold both, and a TCP service can carry a filter that parses HTTP alongside one
    that does not.

    The one thing that cannot work is a file asking for two *different* application
    protocols, because a connection is only ever one of them. That is refused here,
    naming both functions, rather than being resolved by picking a winner.
    """
    from firegex.pyfilters.models import type_annotations_associations

    candidates = set(type_annotations_associations)
    # What actually narrowed the choice, kept so a conflict can be explained in terms
    # of the operator's own code instead of a protocol name they never typed.
    narrowing: list[tuple[str, object, set[str]]] = []

    for name, _func, annotations in wanted:
        for annotation in annotations:
            protos = {
                proto
                for proto, types in type_annotations_associations.items()
                if annotation in types
            }
            if not protos:
                known = sorted({
                    _type_name(t)
                    for types in type_annotations_associations.values()
                    for t in types
                })
                raise Exception(
                    f"Invalid type annotation {_type_name(annotation)} for function "
                    f"{name}: no protocol provides it. Available: " + ", ".join(known)
                )
            if not candidates & protos:
                clash = next((n for n in narrowing if not n[2] & protos), None)
                if clash:
                    raise Exception(
                        f"{name} asks for {_type_name(annotation)}, which only "
                        f"{'/'.join(sorted(protos))} provides, while {clash[0]} asks for "
                        f"{_type_name(clash[1])}, which only "
                        f"{'/'.join(sorted(clash[2]))} does. A connection speaks one "
                        f"application protocol, so one file cannot filter both: split "
                        f"them into two filters on the same service."
                    )
                raise Exception(
                    f"{name} asks for {_type_name(annotation)}, which no protocol in "
                    f"this file can provide"
                )
            if candidates & protos != candidates:
                narrowing.append((name, annotation, protos))
            candidates &= protos

    return simplest_proto(candidates)


def simplest_proto(candidates=None) -> str:
    """The least specific protocol among `candidates` — all of them by default.

    A file that only wants raw payloads is a TCP filter, not an HTTP one that happens
    never to parse, so "fewest models" is what "simplest" means.
    """
    from firegex.pyfilters.models import type_annotations_associations
    return min(
        candidates if candidates else type_annotations_associations,
        key=lambda p: (len(type_annotations_associations[p]), p),
    )


def generate_filter_structure(filters: list[str], proto: str | None, glob: dict) -> list[FilterHandler]:
    """One `FilterHandler` per filter, in the order given, for one protocol."""
    from firegex.pyfilters.models import type_annotations_associations

    wanted = _wanted_by(filters, glob)
    if proto is None:
        proto = infer_proto(wanted)
    if proto not in type_annotations_associations:
        raise Exception("Invalid protocol")
    provides = type_annotations_associations[proto]

    handlers = []
    for name, func, annotations in wanted:
        for annotation in annotations:
            if annotation not in provides:
                raise Exception(
                    f"Invalid type annotation {_type_name(annotation)} for function "
                    f"{name}: this file speaks {proto}, which does not provide it"
                )
        handlers.append(FilterHandler(
            func=func,
            name=func.__name__,
            params={a: provides[a] for a in annotations},
            proto=proto,
        ))
    return handlers


def get_filters_info(code:str, proto:str|None = None) -> list[FilterHandler]:
    """The filters a file defines. `proto` is inferred from the code when not given.

    Only the operator's own source is `exec`ed. Everything around it used to be too —
    the import, the registry reset before and after — which was a string compiled at
    runtime for each step of what a plain call does, and which existed only because the
    registry was global state that had to be cleared around every use.
    """
    from firegex.pyfilters import collect_pyfilters

    glob: dict = {}
    exec(code, glob, glob)
    return generate_filter_structure(collect_pyfilters(glob), proto, glob)


def get_filter_names(code:str, proto:str|None = None) -> list[str]:
    return [ele.name for ele in get_filters_info(code, proto)]    


def get_code_proto(code:str) -> str:
    """Which application protocol a file speaks, for a caller that needs to say so.

    Raises the same errors `get_filters_info` does, so a file that mixes two protocols
    is reported here with the reason rather than silently classified as one of them.
    """
    from firegex.pyfilters.models import type_annotations_associations
    infos = get_filters_info(code)
    if infos:
        return infos[0].proto
    # A file with no filters yet speaks the simplest protocol there is: it asks for
    # nothing, so nothing is ruled out.
    return min(
        type_annotations_associations,
        key=lambda p: (len(type_annotations_associations[p]), p),
    )

#: What a model raises while being built, and the verdict it means. `NotReadyToRun` is
#: not here: it is the ordinary "there is nothing to give this filter yet", handled by
#: skipping the call rather than by ending the packet.
_RAISED_VERDICT = {
    StreamFullDrop: (Action.DROP, "@MAX_STREAM_SIZE_REACHED"),
    StreamFullReject: (Action.REJECT, "@MAX_STREAM_SIZE_REACHED"),
    DropPacket: (Action.DROP, None),
    RejectConnection: (Action.REJECT, None),
}


def handle_packet(glob: dict) -> None:
    """Run every enabled filter over the chunk in `glob`, and leave a verdict there.

    The first filter to answer anything but ACCEPT ends the packet — every verdict
    there is now terminal. `UNSTABLE_MANGLE` used to be the exception: it was remembered
    and the walk carried on, because a later filter might still refuse the rewritten
    chunk. It is gone, and so is that branch: see the note on `Action` in `models.py`.
    """
    internal_data = DataStreamCtx(glob)
    result = PacketHandlerResult(glob)

    # Built once per packet and shared by every filter that asks for the same thing: two
    # filters both taking an `HttpRequest` parse the chunk once between them.
    built = {RawPacket: internal_data.current_pkt}

    for filter in internal_data.filter_call_info:
        args = []
        for data_type, build in filter.params.items():
            if data_type not in built:
                try:
                    built[data_type] = build(internal_data)
                except NotReadyToRun:
                    built[data_type] = None
                except tuple(_RAISED_VERDICT) as raised:
                    action, matched_by = _RAISED_VERDICT[type(raised)]
                    result.action = action
                    result.matched_by = matched_by or filter.name
                    return result.set_result()
            if built[data_type] is None:
                args = None  # nothing to give this filter yet; it is not called
                break
            args.append(built[data_type])

        if args is None:
            continue

        # A model may hand back several of itself — a chunk carrying three HTTP requests
        # is three calls, not one call with a list. Where more than one parameter does
        # that, the filter sees every combination.
        for call_args in product(*(a if isinstance(a, list) else [a] for a in args)):
            res = filter.func(*call_args)
            if res is None or res == Action.ACCEPT:
                continue
            if not isinstance(res, Action):
                raise Exception(f"Invalid return type {type(res)} for function {filter.name}")
            result.matched_by = filter.name
            result.action = res
            return result.set_result()

    return result.set_result()  # nothing refused it: ACCEPT


#: The knobs a filter file may set, and what each one is kept as. Three copies of "if
#: the name is there and the value is the right type, store it" differing only in the
#: name and the type; the one that was *not* a copy had drifted — it checked `Action`
#: where the setter and the documentation both said `ExceptionAction`, so the knob could
#: not be set at all, in either direction.
_SETTINGS = {
    "FGEX_STREAM_MAX_SIZE": ("stream_max_size", int),
    "FGEX_FULL_STREAM_ACTION": ("full_stream_action", FullStreamAction),
    "FGEX_INVALID_ENCODING_ACTION": ("invalid_encoding_action", ExceptionAction),
}


def compile(glob: dict) -> None:
    """Prepare a filter file's globals to be handed packets.

    Called once per connection, after the operator's source has been executed into
    `glob`: it resolves which functions run, in what order, over what models, and reads
    the file's settings.
    """
    internal_data = DataStreamCtx(glob, init_pkt=False)

    glob["print"] = functools.partial(print, flush=True)

    # Absent means "read it off the code", which is the normal case: the file shows
    # which protocol it speaks by what its filters ask for, so nothing has to be kept
    # in step with it by hand.
    internal_data.filter_call_info = generate_filter_structure(
        glob["__firegex_pyfilter_enabled"], glob.get("__firegex_proto"), glob
    )

    for name, (attribute, kind) in _SETTINGS.items():
        if name not in glob:
            continue
        value = glob[name]
        if kind is int:
            # A size is taken from anything that reads as one, and a nonsense size is
            # ignored rather than refused: the file has already loaded.
            value = int(value)
            if value <= 0:
                continue
        elif not isinstance(value, kind):
            continue
        setattr(internal_data, attribute, value)

    PacketHandlerResult(glob).reset_result()

    def fake_exit(*_a, **_k):
        print("WARNING: This function should not be called", flush=True)

    glob["exit"] = fake_exit
