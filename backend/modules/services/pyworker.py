#!/usr/bin/env python3
"""Runs a user's Python filters, one process away from the datapath.

Started by the engine, never by the backend: the engine is the one that has to kill it
when it stops answering, and something else owning its lifetime would defeat the point
of moving the code out of process at all.

The filters are run through the **real** `firegex.pyfilters` library — the same one the
NFQUEUE binary embeds, the same one `fgex pyfilters` simulates against, the same one the
documentation describes. An earlier version of this file defined its own look-alike
`@pyfilter` that took `(data, direction)`, and that was a mistake of exactly the kind a
regex engine written twice would be: a filter written from the docs loaded on one
transport and failed on the other, and the docs were right about neither.

Each connection gets its own set of module globals, which is what the API promises —
code at module level runs once per stream and the same globals are reused for every
packet of that stream. That is why every frame carries a connection id, and why the
engine sends a close frame: without one, a service would accumulate one set of globals
per connection for as long as it ran.

Frames are length-prefixed and binary:

    in    [u32 len][u8 kind][u64 connection][payload]
          kind: 0 client->server, 1 server->client,
                2 connection closed, 3 connection opened
    out   [u32 len][u8 verdict][u8 name len][name][payload]
          verdict: 0 accept, 1 reject, 2 replace

The name is the `@pyfilter` function that decided, so a block is attributed to one
function of a file rather than to the file as a whole — a file routinely holds several,
and "this filter blocked 900 connections" is not an answer when you are trying to find
out which of them is doing it.

Neither an open nor a close frame is answered. A close has no verdict to give about a
connection that is already over; an open carries that connection's metadata — the
addresses and ports, as JSON — which the filter reads and cannot change.

Nothing below the application layer crosses in the other direction. There used to be a
`FAKE:IP:TCP:HEADERS:` prefix here, handed to the library as `raw_packet` so that a
filter written against real headers would find something there. It found a lie: the
proxy terminates the connection and writes its own headers, so editing them changed
nothing, while the same filter on NFQUEUE edited a real packet. Metadata in, payload
out — that is the one contract both network layers can honestly keep.
"""

import json
import re
import struct
import sys
import traceback

VERDICT_ACCEPT = 0
VERDICT_REJECT = 1
VERDICT_REPLACE = 2
# Sent once, after the user's file has been compiled. It is what lets the engine refuse
# a ruleset whose code does not load, instead of discovering it later as traffic that
# quietly stopped being filtered.
READY = 0xFF

KIND_C2S = 0
KIND_S2C = 1
KIND_CLOSE = 2
KIND_OPEN = 3


def _build_filter_code(path: str, enabled: list[str] | None = None) -> str:
    """Turn the user's file into the module the library expects to execute.

    Identical in shape to what `firegex.pyfilters.proxysim` builds, because it has to be:
    the library decides which filters exist and when each one is callable from these
    trailing lines, and a different preamble would mean a different set of filters.

    `enabled` is the subset the operator left switched on; `None` means all of them. It
    is intersected with what the file actually defines rather than trusted, so a stale
    selection naming a function that has since been deleted cannot stop the file from
    loading — the library would refuse the whole module over one missing name.

    No protocol is written in. The file shows which one it speaks by what its filters
    ask for, so there is nothing here that could disagree with the code — an earlier
    version passed one in from the outside, and a filter asking for an `HttpRequest`
    under a file declared `tcp` was refused with an error about its own annotation.
    """
    from firegex.pyfilters.internals import get_filter_names

    with open(path) as f:
        source = f.read()

    names = get_filter_names(source)
    if enabled is not None:
        wanted = set(enabled)
        names = [name for name in names if name in wanted]
    return (
        source
        + "\n\n__firegex_pyfilter_enabled = ["
        + ", ".join(repr(name) for name in names)
        + "]\n"
        "import firegex.pyfilters.internals\n"
        "firegex.pyfilters.internals.compile(globals())\n"
    )


def _where_in_source(source: str, exc: BaseException, filename: str) -> dict:
    """Point at the line of the operator's own file, when there is one to point at.

    Three ways, in order of how directly they know:

    * a `SyntaxError` carries its own position, and the code never ran;
    * a traceback frame belonging to the file — the module body raised while loading.
      `<string>` counts as theirs: the library execs the source to find its filters
      before the module is built under its real name, and everything the library itself
      runs from has a real path, so an anonymous frame is the user's;
    * neither, which is the interesting case. The library refuses a filter by *name*
      ("Invalid type annotation X for function Y", "Parameter 'p' of Z has none"), from
      frames that are all its own, so any identifier in the message is looked back up
      among the file's own `def`s. Without this the operator is told which function is
      wrong and left to go and find it.
    """
    lines = source.splitlines()

    def at(line: int) -> dict:
        return {"line": line, "column": 0,
                "text": lines[line - 1].rstrip() if 0 < line <= len(lines) else ""}

    if isinstance(exc, SyntaxError) and exc.lineno:
        return {"line": exc.lineno, "column": exc.offset or 0,
                "text": (exc.text or "").rstrip()}

    mine = {filename, "<string>"}
    frames = [f for f in traceback.extract_tb(exc.__traceback__) if f.filename in mine]
    if frames:
        return at(frames[-1].lineno or 0)

    # The *last* definition of a name, because that is the one Python is left holding:
    # a file that defines `check` twice runs the second, and pointing at the first would
    # send the operator to a function that is not the one being complained about.
    defs = {}
    for number, text in enumerate(lines, start=1):
        found = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(", text)
        if found:
            defs[found.group(1)] = number
    for word in re.findall(r"\w+", str(exc)):
        if word in defs:
            return at(defs[word])
    return {"line": 0, "column": 0, "text": ""}


def check(path: str) -> dict:
    """Would this file load, and what does it define?

    Run by the backend before a save is accepted, in a process of its own — which is
    both why the answer can be trusted and why a filter with a `while True:` at module
    level cannot take the interface down with it. It is the *same* build and the same
    compile the datapath performs, so what is accepted here is what will run.
    """
    from firegex.pyfilters.internals import get_filters_info

    try:
        with open(path) as f:
            source = f.read()
    except OSError as e:
        return {"ok": False, "error": {"type": "OSError", "message": str(e),
                                       "line": 0, "column": 0, "text": "",
                                       "traceback": ""}}
    try:
        infos = get_filters_info(source) if source.strip() else []
        # Not just "does it parse": the whole module, exactly as the worker builds it,
        # so an error the library only raises at compile time is raised here too.
        Filters(_build_filter_code(path), path)
    except BaseException as e:  # noqa: BLE001 - anything the user's code can raise
        return {
            "ok": False,
            "error": {
                "type": type(e).__name__,
                # A SyntaxError's text carries "(<string>, line N)", which names a file
                # the operator never wrote and repeats a position reported separately.
                "message": re.sub(r"\s*\((?:<[^>]*>|[^()]*\.py), line \d+\)$", "",
                                  str(e) or type(e).__name__),
                **_where_in_source(source, e, path),
                "traceback": traceback.format_exc(),
            },
        }
    return {
        "ok": True,
        "proto": infos[0].proto if infos else "tcp",
        "filters": [info.name for info in infos],
        # Which models the file actually asks for. The protocol alone does not say: a
        # `tcp` file wanting only a RawPacket runs on datagrams too, while one wanting a
        # TCP stream cannot — and the difference decides whether attaching it to a UDP
        # service gives you a filter or a filter that never fires.
        "models": sorted({
            annotation.__name__
            for info in infos
            for annotation in info.params
        }),
    }


class Filters:
    """The compiled filter module, plus one set of globals per live connection."""

    def __init__(self, code: str, filename: str = "<filter>"):
        # Compiled once, under the operator's own file name: every connection reuses the
        # code object instead of re-parsing the source, and a traceback names the file
        # they wrote rather than `<string>`, with line numbers that match what they see
        # in the editor. The preamble is appended *after* their source precisely so
        # those numbers line up.
        self.code = compile(code, filename, "exec")
        self.contexts: dict[int, dict] = {}
        #: What the engine said about each live connection, kept so every chunk of it
        #: carries the same addresses without them being repeated on the wire.
        self.endpoints: dict[int, dict] = {}
        # Run once here so a file that cannot load is a startup failure, which the
        # engine turns into a refused ruleset rather than a service that silently stops
        # filtering.
        probe: dict = {}
        exec(self.code, probe, probe)  # noqa: S102 - running the user's filter is the feature

    def context(self, connection: int) -> dict:
        ctx = self.contexts.get(connection)
        if ctx is None:
            ctx = {}
            exec(self.code, ctx, ctx)  # noqa: S102
            self.contexts[connection] = ctx
        return ctx

    def opened(self, connection: int, payload: bytes) -> None:
        try:
            meta = json.loads(payload.decode())
        except (ValueError, UnicodeDecodeError):
            return
        if isinstance(meta, dict):
            self.endpoints[connection] = meta

    def close(self, connection: int) -> None:
        self.contexts.pop(connection, None)
        self.endpoints.pop(connection, None)

    def run(self, connection: int, data: bytes, is_input: bool) -> tuple[int, str, bytes]:
        """One chunk through the chain. Returns the verdict, who decided, and the payload."""
        from firegex.pyfilters import ACCEPT, DROP, REJECT

        ctx = self.context(connection)
        # Missing endpoints are empty strings and zeros rather than an error: the engine
        # sends them best-effort, and a filter losing the client's address is a worse
        # outcome than a filter that sees "" for it, but neither is a reason to stop
        # filtering the traffic.
        meta = self.endpoints.get(connection, {})
        client_ip = meta.get("client_ip", "")
        client_port = int(meta.get("client_port", 0))
        server_ip = meta.get("server_ip", "")
        server_port = int(meta.get("server_port", 0))
        ctx["__firegex_packet_info"] = {
            "data": data,
            "is_input": is_input,
            "is_ipv6": bool(meta.get("is_ipv6", False)),
            # Said by the engine rather than assumed: this worker serves TCP connections
            # and UDP flows alike, and the library's stream and HTTP models key off it.
            "is_tcp": bool(meta.get("is_tcp", True)),
            "src_ip": client_ip if is_input else server_ip,
            "src_port": client_port if is_input else server_port,
            "dst_ip": server_ip if is_input else client_ip,
            "dst_port": server_port if is_input else client_port,
        }
        try:
            exec(  # noqa: S102
                "firegex.pyfilters.internals.handle_packet(globals())", ctx, ctx
            )
        finally:
            ctx.pop("__firegex_packet_info", None)

        result = ctx.pop("__firegex_pyfilter_result", None)
        if not isinstance(result, dict):
            # The library did not answer. Saying nothing about a chunk is not a reason
            # to stop carrying it.
            print("[warn] [pyworker] no verdict from the filter chain", file=sys.stderr)
            return VERDICT_ACCEPT, "", b""

        action = result.get("action")
        # Which function decided, so the block lands on it rather than on the whole file.
        matched = result.get("matched_by")
        matched = matched if isinstance(matched, str) else ""
        if action == ACCEPT.value:
            return VERDICT_ACCEPT, "", b""
        if action == REJECT.value:
            return VERDICT_REJECT, matched, b""
        if action == DROP.value:
            # A proxy has no way to swallow one chunk and keep the stream coherent —
            # the application on the other side would be reading a hole. Closing is the
            # honest equivalent, and it is what the operator meant by dropping.
            return VERDICT_REJECT, matched, b""
        print(f"[warn] [pyworker] unknown action {action!r}", file=sys.stderr)
        return VERDICT_ACCEPT, "", b""


def _read_exactly(stream, count: int) -> bytes | None:
    buf = b""
    while len(buf) < count:
        chunk = stream.read(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _write(stream, verdict: int, matched: str, payload: bytes) -> None:
    # The name is length-prefixed with a single byte: a Python identifier fits, and a
    # separator would have to be one that cannot appear in one.
    name = matched.encode()[:255]
    stream.write(
        struct.pack(">I", len(payload) + len(name) + 2)
        + bytes([verdict, len(name)])
        + name
        + payload
    )
    stream.flush()


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: pyworker.py <filter file> [* | =fn,fn]   |   --check <filter file>",
              file=sys.stderr)
        return 2
    if sys.argv[1] == "--check":
        # One JSON object on stdout and nothing else, so the caller never has to guess
        # which part of the output was the answer.
        if len(sys.argv) < 3:
            print("usage: pyworker.py --check <filter file>", file=sys.stderr)
            return 2
        sys.stdout.write(json.dumps(check(sys.argv[2])))
        sys.stdout.flush()
        return 0
    # `*` (or nothing at all) means every function the file defines, which is what a
    # hand-run worker wants; `=a,b` means exactly those, and a bare `=` means none.
    # A marker rather than a bare list because "all" and "none" are both real answers
    # and an empty string cannot stand for both.
    enabled = None
    if len(sys.argv) > 2 and sys.argv[2].startswith("="):
        enabled = [name.strip() for name in sys.argv[2][1:].split(",") if name.strip()]

    try:
        filters = Filters(_build_filter_code(sys.argv[1], enabled), sys.argv[1])
    except Exception:
        traceback.print_exc()
        return 1

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    # The user's code shares this process, and `print()` is the most natural thing in
    # the world to reach for while debugging a filter. On stdout it would land in the
    # middle of a length-prefixed frame: the engine reads the text as a frame header,
    # sees an absurd length, and kills the worker — so the filter would be restarted on
    # every packet and the operator would be told nothing except that it stopped
    # working. Their output belongs on the diagnostics channel, which the backend now
    # captures into the service log, so it goes there and stdout stays the protocol.
    sys.stdout = sys.stderr

    stdout.write(struct.pack(">I", 2) + bytes([READY, 0]))
    stdout.flush()

    while True:
        header = _read_exactly(stdin, 4)
        if header is None:
            return 0  # the engine went away; so do we
        (length,) = struct.unpack(">I", header)
        body = _read_exactly(stdin, length)
        if body is None or len(body) < 9:
            return 0
        kind = body[0]
        (connection,) = struct.unpack(">Q", body[1:9])
        payload = body[9:]

        if kind == KIND_OPEN:
            filters.opened(connection, payload)
            continue  # deliberately unanswered

        if kind == KIND_CLOSE:
            filters.close(connection)
            continue  # deliberately unanswered

        try:
            verdict, matched, out = filters.run(connection, payload, kind == KIND_C2S)
        except Exception:
            # One connection's filter blowing up must not take the process down: the
            # other connections it is serving would lose their filtering with it.
            traceback.print_exc()
            verdict, matched, out = VERDICT_ACCEPT, "", b""
        _write(stdout, verdict, matched, out)


if __name__ == "__main__":
    sys.exit(main())
