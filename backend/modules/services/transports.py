"""The network layer: three ways to get hold of a service's traffic.

A transport knows how to intercept, and nothing about what the filters do. A filter
chain knows what to do, and nothing about how the bytes arrived. The service model
combines them, and this file is the seam.

The seam is not perfectly clean, and pretending otherwise would cost the operator
later. The NFQUEUE binaries fuse the two layers: `cppregex` is NFQUEUE *plus*
hyperscan, `cpproxy` is NFQUEUE *plus* an embedded interpreter, and neither can host
the other's filter. So a chain there is a chain of *processes*, one per filter, each at
its own base-chain priority — a packet a filter accepts carries on to the next chain in
the same hook, which is what makes order mean something. The proxy walks the same chain
as a list inside one process.

What is left of the asymmetry is priced and refused up front, in `check()`: at most
`MAX_CHAIN_POSITIONS` filters on NFQUEUE, because each one costs a process and a
reassembly pass; nothing at all on `external`, because firegex is not in that path and a
filter attached to it would never run.
"""

import asyncio
import json
import os
import sys
import traceback
from typing import NamedTuple

from modules.services.models import (KIND, L4, PROTO, TRANSPORT, UPSTREAM, Filter,
                                     Regex, quic_alpn, upstream_refusal)
from modules.services.nftables import (MAX_CHAIN_POSITIONS, NoRelayAddress,
                                       interface_addresses, service_at, udp_relay_host,
                                       udp_relay_key, udp_relay_slot)
from utils import DEBUG, nicenessify

MODULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

CPPREGEX = os.path.join(MODULES_DIR, "cppregex")
CPPROXY = os.path.join(MODULES_DIR, "cpproxy")
PROXY_ENGINE = os.getenv("FGEX_PROXY_BINARY", os.path.join(MODULES_DIR, "fgex-proxy"))

#: Where a TLS service's certificate and key are put for the engine to read. Not under
#: `db/`: the material is already in the database, and a second durable copy of a private
#: key is a second thing to remember to delete.
TLS_DIR = "/tmp/firegex_tls"
# The out-of-process worker the proxy engine runs the user's Python in. The engine
# spawns it, not us: it is the one that has to kill it when it stops answering.
PYWORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pyworker.py")
#: What `pyworker.py` writes to stderr when the user's code raises. Spelled here as well
#: as there on purpose: the worker is launched as a script and imports nothing from the
#: backend, which is what keeps the user's code from sharing this process's imports.
#: Kept in step by `tests/integration/test_resilience.py`, which asks for the sentence on
#: both network layers.
PYWORKER_EXCEPTION_MARK = "[exception] [filter]"

#: How long to wait for a binary to acknowledge a configuration push.
ACK_TIMEOUT = 3


class UnsupportedChain(Exception):
    """The chosen transport cannot host the chain that was asked of it."""


class ChainShapeChanged(Exception):
    """The chain is no longer the one the running datapath was started for.

    Not an error: it means the change cannot be pushed and has to be rebuilt. Only the
    NFQUEUE layer raises it, because only there is the chain made of separate processes
    at separate priorities rather than a list inside one.
    """


class ChainLink:
    """One filter, with everything needed to run it already resolved.

    The transports never touch the database: whoever builds the chain has already
    read the patterns and the code out of it, so a transport cannot accidentally
    enforce something other than what the caller decided to enforce.
    """

    def __init__(self, flt: Filter, regexes: list[Regex] | None = None,
                 code_path: str | None = None, functions: list | None = None):
        self.filter = flt
        self.regexes = regexes or []
        self.code_path = code_path
        #: The `@pyfilter` functions the operator left switched on, by name. `None`
        #: means every one the file defines — which is what a filter whose code has
        #: never been saved has, and what a hand-run worker assumes.
        self.functions = functions

    @property
    def enabled_functions(self) -> list[str] | None:
        """The names to hand the library, or `None` for "everything the file defines".

        No rows at all means the list was never derived — a filter whose code predates
        the per-function switches, or one whose code did not parse when it was saved.
        The safe reading there is to run what the file defines: the alternative is a
        file whose filters all silently stop running, which is the exact failure this
        whole module is arranged to prevent.

        Rows that all say `active = 0` are a different thing entirely — the operator
        switched every function off — and that stays representable as an empty list.
        """
        if not self.functions:
            return None
        return [fn["name"] for fn in self.functions if fn["active"]]

    @property
    def kind(self) -> str:
        return self.filter.kind

    @property
    def id(self) -> str:
        return self.filter.id


#: What an address's edge is called on the wire to the engine. Only `tls` has a name of
#: its own, because only it is a promise: this port is the encrypted one, and a client
#: opening it in the clear is refused. Everything else is "whatever the client turns out
#: to be speaking", which is what one listener fronting both a cleartext port and an
#: encrypted one has always had to do — and refusing TLS at a port nobody promised would
#: be a rule with nothing behind it.
_EDGE_WORD = {L4.TLS: "tls"}


class Announcement(NamedTuple):
    """What the engine is told about one TCP address, beyond that it exists."""

    #: `tls` where the address was declared as the encrypted one, `any` otherwise.
    word: str
    #: What the service behind it speaks: `same`, `plain` or `tls`.
    onward: str
    #: Where that service is, when it is not on the port the address names.
    target_port: int | None


def fronted_by_the_listener(srv, addr) -> bool:
    """Whether this address is one the single TCP listener answers for.

    Asked of the transport the **kernel** matches on, which is what decides whether an
    address gets a relay of its own: a UDP or QUIC address is bound to the service it
    fronts when the relay is opened, so there is nothing left to tell the engine about
    it. Written as one question because it was two — an edge test here and a `proto`
    test there — and two spellings of one rule are what this module spends most of its
    comments arguing against.
    """
    return L4.l4_of(addr.proto or srv.proto) == L4.TCP


def announcement(srv, addr) -> Announcement | None:
    """What the engine has to be told about one TCP address, or `None` for nothing.

    `None` is the ordinary answer and the important one: an address that is simply the
    service — dialled where it listens, carried as it arrives — is one the engine already
    handles correctly by knowing nothing about it, because that is what transparent
    means. Announcing it anyway would be a map entry restating the default.

    One function rather than two because there are two callers and they have to agree
    exactly: `ProxyTransport._published` builds the startup list (`FGEX_PROXY_TARGETS`)
    and `ServiceManager.address_added` sends `PUBLISH` for an address added to a service
    already running. They were the same three lines written twice, and the day they
    disagree the symptom is an address that behaves one way when the service starts with
    it and another way when it is added afterwards — which is as hard a bug to see as
    this module has produced.
    """
    if not fronted_by_the_listener(srv, addr):
        return None
    # Only ever *chosen* on an `http` service, because that is the only protocol whose
    # addresses are not all reached the same way; elsewhere it is the service's own.
    word = (_EDGE_WORD.get(str(addr.edge), "any")
            if str(srv.proto) == L4.HTTP else "any")
    onward = UPSTREAM.env(addr.upstream)
    moved = addr.target_port if addr.target_port and addr.target_port != addr.port else None
    if word == "any" and onward == "same" and moved is None:
        return None
    return Announcement(word=word, onward=onward, target_port=moved)


class Transport:
    """What a network layer has to be able to do."""

    def __init__(self, srv, on_block=None, on_output=None, on_exception=None, on_engine=None,
                 on_over_limit=None, on_died=None):
        self.srv = srv
        # Called with the id of whatever refused a connection — a regex rule id, or a
        # filter id for a pyfilter. Counters live in the database, which is the
        # manager's business, not ours.
        self.on_block = on_block
        #: Whatever the user's own code printed.
        self.on_output = on_output
        self.on_exception = on_exception
        #: What the datapath has seen and refused, in connections. Only the layers that
        #: work in connections report it; the rest leave it empty and the kernel's
        #: packet counters answer instead.
        self.counters: dict = {}
        #: Whatever the datapath says about itself. Forwarded rather than swallowed:
        #: these are the lines that say a filter lost its say or a fallback happened.
        self.on_engine = on_engine
        #: Called with how many *more* connections the limit has turned away since the
        #: last report. The engine's own counter resets when it restarts, so somebody
        #: above has to add them up if the trace is to outlive the process.
        self.on_over_limit = on_over_limit
        #: Called when a datapath process dies without being asked to. **The nftables
        #: rules outlive the process**, so nobody notices on their own: the traffic keeps
        #: being steered at a queue nobody is reading, the interface goes on reporting the
        #: service as active, and what it is doing is decided by the `bypass` flag alone.
        #: Whoever is above decides whether to bring it back.
        self.on_died = on_died
        #: Whether whatever this layer listens on can accept IPv6. Declared here rather
        #: than on the one layer that has a listener, so a caller asking a transport
        #: what it can accept gets an answer instead of an AttributeError.
        self.is_dual_stack: bool = False
        self.process: asyncio.subprocess.Process | None = None
        self._stderr_pump: asyncio.Task | None = None

    @classmethod
    def check(cls, srv, chain: list[ChainLink]) -> None:
        """Refuse an impossible combination before anything is started.

        Whatever the network layer is: a filter that cannot fire on this service's
        traffic is refused here, once, rather than by each transport separately.
        """
        if str(srv.proto) != L4.UDP:
            return
        # A file that asks for parsed HTTP needs a stream to parse. On datagrams the
        # library declines to build the model, so the filter is never called — and a
        # filter that silently never runs is worse than one that is refused. Saving such
        # code against a UDP service is refused too; this catches the case where the
        # service was switched to UDP afterwards.
        http = [
            link for link in chain
            if link.filter.active and link.kind == KIND.PYFILTER
            and link.filter.proto == PROTO.HTTP
        ]
        if http:
            raise UnsupportedChain(
                f"{', '.join(link.filter.name for link in http)} "
                f"{'ask' if len(http) > 1 else 'asks'} for parsed HTTP, which needs a "
                f"TCP stream underneath, and this service speaks UDP. On datagrams "
                f"those filters would never be called. Rewrite them against RawPacket, "
                f"or move the service back to TCP."
            )

    async def start(self, chain: list[ChainLink]) -> dict:
        """Bring the datapath up. Returns what `nftables.add` needs to steer traffic."""
        raise NotImplementedError

    async def reload(self, chain: list[ChainLink]) -> None:
        raise NotImplementedError

    async def add_udp_target(self, ip: str, port: int,
                             onward: str = "same") -> int:
        raise NotImplementedError

    async def stop(self) -> None:
        raise NotImplementedError

    async def _kill(self):
        if self.process and self.process.returncode is None:
            self.process.kill()
            await self.process.wait()
        self.process = None

    def _emit_block(self, rule_id: str):
        if self.on_block:
            self.on_block(rule_id)

    def _pump_stderr(self, stream) -> asyncio.Task | None:
        """Forward the datapath's own diagnostics line by line.

        The last `[fatal]` is kept as well as forwarded, because a datapath that dies
        during startup is reported by whatever was waiting for its handshake — and
        "did not report a listening port" is the symptom, while the line it printed on
        the way down is the reason. Kept on the *owner* rather than per process, which is
        what lets the NFQUEUE stages use it too: they pump their stderr through here and
        had the identical problem, a timeout reported as a missing queue number while the
        binary had already said why it was going.
        """
        if stream is None or not self.on_engine:
            return None

        async def run():
            try:
                while True:
                    line = await stream.readline()
                    if not line:
                        return
                    text = line.decode(errors="replace")
                    if "[fatal]" in text:
                        self._last_fatal = text.split("[fatal]", 1)[1].strip()
                    # The worker marks a filter that raised, because the verdict it sends
                    # back is an ordinary ACCEPT and the engine cannot tell that apart
                    # from a filter that agreed. The traceback beside this line says which
                    # filter and where; this is what says the traffic went through
                    # unfiltered, and it is the same sentence the queued layer's
                    # `EXCEPTION` produces.
                    if PYWORKER_EXCEPTION_MARK in text:
                        # A protocol token, like `BLOCKED <id>` on the other channel:
                        # it is turned into the sentence an operator reads and is not
                        # forwarded raw, or the log would carry both.
                        if self.on_exception:
                            self.on_exception(self.srv.id)
                        continue
                    self.on_engine(text)
            except (asyncio.CancelledError, asyncio.IncompleteReadError):
                pass
            except Exception:
                traceback.print_exc()

        return asyncio.create_task(run())

    async def _died_because(self, fallback: str) -> str:
        """What to tell the operator when the datapath would not come up.

        A moment first: stdout closing is what wakes the caller, and the reason was
        written to stderr, so the two arrive in that order often enough to matter.
        """
        for _ in range(10):
            if getattr(self, "_last_fatal", None):
                break
            await asyncio.sleep(0.05)
        reason = getattr(self, "_last_fatal", None)
        return f"{fallback}: {reason}" if reason else fallback


class _QueueStage:
    """One filter, in one NFQUEUE binary, at one position in the chain.

    The two binaries fuse transport and filter — `cppregex` is NFQUEUE plus hyperscan,
    `cpproxy` is NFQUEUE plus an embedded interpreter — so a chain of them is a chain of
    processes rather than a chain inside one. They also speak different control
    protocols, which is the only reason this class knows about both.
    """

    def __init__(self, srv, link: ChainLink, owner: "NfqueueTransport"):
        self.srv = srv
        self.link = link
        self.owner = owner
        self.process: asyncio.subprocess.Process | None = None
        self.queue_num: int | None = None
        self._reader_task: asyncio.Task | None = None
        self._output_task: asyncio.Task | None = None
        self._ack: asyncio.Future | None = None
        self._sock_path: str | None = None
        self._sock_server: asyncio.Server | None = None
        self._sock_reader: asyncio.StreamReader | None = None
        self._sock_writer: asyncio.StreamWriter | None = None
        self._sock_ready = asyncio.Event()
        #: Which rule id each pattern code stands for, for block attribution. A Python
        #: stage reports the function's own name instead, which needs no table.
        self._codes: dict[str, str] = {}
        #: Set by `stop()`, so the watchdog can tell a shutdown we asked for from one we
        #: did not. Without the distinction every ordinary stop looks like a crash.
        self._stopped = False
        self._watchdog: asyncio.Task | None = None

    async def start(self) -> int:
        if self.link.kind == KIND.PYFILTER:
            self.queue_num = await self._start_cpproxy()
        else:
            self.queue_num = await self._start_cppregex()
        self._watchdog = asyncio.create_task(self._watch())
        await self.reload(self.link)
        return self.queue_num

    async def _watch(self):
        """Notice the binary dying, which nothing else here does.

        The reader task sees EOF on stdout and returns, which is indistinguishable from a
        clean shutdown, so a crashed interceptor used to leave a service that reports
        itself as active and filters nothing — its rules still pointing traffic at a queue
        with no reader behind it.
        """
        try:
            returncode = await self.process.wait()
        except asyncio.CancelledError:
            return
        if self._stopped:
            return  # we killed it ourselves
        self.owner._stage_died(self.link.filter.name, returncode)

    # --- cppregex: config on stdin, events on stdout --------------------------

    async def _start_cppregex(self) -> int:
        self.process = await asyncio.create_subprocess_exec(
            CPPREGEX,
            stdout=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(
                os.environ,
                **{
                    "MATCH_MODE": "stream" if self.srv.proto == "tcp" else "block",
                    "NTHREADS": os.getenv("NTHREADS", "1"),
                    "FIREGEX_NFQUEUE_FAIL_OPEN": "1" if self.srv.fail_open else "0",
                },
            ),
        )
        nicenessify(-10, self.process.pid)
        self._output_task = self.owner._pump_stderr(self.process.stderr)
        queue = await self._read_queue_number(self.process.stdout)
        self._reader_task = asyncio.create_task(self._read_events(self.process.stdout))
        return queue

    # --- cpproxy: config and events over a unix socket ------------------------

    async def _start_cpproxy(self) -> int:
        self._sock_path = f"/tmp/firegex_service_{self.srv.id}_{self.link.id}.sock"
        if os.path.exists(self._sock_path):
            os.remove(self._sock_path)
        self._sock_ready.clear()
        self._sock_server = await asyncio.start_unix_server(
            self._accept_worker, path=self._sock_path
        )
        self.process = await asyncio.create_subprocess_exec(
            CPPROXY,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=dict(
                os.environ,
                **{
                    "NTHREADS": os.getenv("NTHREADS", "1"),
                    "FIREGEX_NFQUEUE_FAIL_OPEN": "1" if self.srv.fail_open else "0",
                    "FIREGEX_NFPROXY_SOCK": self._sock_path,
                    # How many UDP flows keep a filter's state at once: the service's own
                    # limit, 0 for none. Only datagrams need it — a TCP stream's state
                    # goes when the stream closes.
                    "FIREGEX_MAX_FLOWS": str(self.srv.max_connections),
                },
            ),
        )
        nicenessify(-10, self.process.pid)
        # Whatever the user's Python prints is theirs to see, so it is forwarded rather
        # than swallowed — a filter that is silently doing nothing is the hardest kind
        # to debug during a competition.
        self._output_task = asyncio.create_task(self._pump_output())
        try:
            async with asyncio.timeout(ACK_TIMEOUT):
                await self._sock_ready.wait()
                queue = await self._read_queue_number(self._sock_reader)
        except (asyncio.TimeoutError, TimeoutError) as e:
            reason = await self.owner._died_because("the nfqueue binary would not start")
            await self.stop()
            raise Exception(reason) from e
        self._reader_task = asyncio.create_task(self._read_events(self._sock_reader))
        return queue

    async def _accept_worker(self, reader, writer):
        if self._sock_reader or self._sock_writer:
            writer.close()  # only ever one connection; a second is not ours
            return
        self._sock_reader, self._sock_writer = reader, writer
        self._sock_ready.set()

    async def _pump_output(self):
        try:
            while True:
                data = await self.process.stdout.read(10 * 1024)
                if not data:
                    return
                text = data.decode(errors="replace")
                # The binary's own diagnostics share this pipe with the user's output, so
                # the reason it gives for dying is read here or not at all — and without
                # it a stage that would not start was reported as merely "would not
                # start", with the sentence that said why sitting in the log.
                for line in text.splitlines():
                    if "[fatal]" in line:
                        self.owner._last_fatal = line.split("[fatal]", 1)[1].strip()
                if self.owner.on_output:
                    self.owner.on_output(self.srv.id, text)
        except (asyncio.CancelledError, asyncio.IncompleteReadError):
            pass
        except Exception:
            traceback.print_exc()

    # --- shared ---------------------------------------------------------------

    async def _read_queue_number(self, reader: asyncio.StreamReader) -> int:
        try:
            line = (await asyncio.wait_for(reader.readuntil(), timeout=ACK_TIMEOUT)).decode()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            reason = await self.owner._died_because("the nfqueue binary would not start")
            await self.stop()
            raise Exception(reason) from e
        if not line.startswith("QUEUE "):
            await self.stop()
            raise Exception(f"unexpected output from the nfqueue binary: {line.strip()!r}")
        return int(line.split()[1])

    async def _read_events(self, reader: asyncio.StreamReader):
        try:
            while True:
                line = (await reader.readuntil()).decode().strip()
                if DEBUG:
                    print(f"[{self.srv.name}/{self.link.filter.name}] {line}")
                if line.startswith("BLOCKED "):
                    code = line.split()[1]
                    if self.link.kind == KIND.PYFILTER:
                        # The function that decided, as `<filter>/<function>`: the one
                        # token both network layers report.
                        self.owner._emit_block(f"{self.link.id}/{code}")
                    else:
                        self.owner._emit_block(self._codes.get(code, self.link.id))
                elif line.startswith("EXCEPTION") and self.owner.on_exception:
                    self.owner.on_exception(self.srv.id)
                elif line.startswith("ACK "):
                    rest = line[4:].strip()
                    if self._ack and not self._ack.done():
                        self._ack.set_result((rest.upper().startswith("OK"), rest))
        except (asyncio.CancelledError, asyncio.IncompleteReadError):
            pass
        except Exception:
            traceback.print_exc()

    async def reload(self, link: ChainLink) -> None:
        self.link = link
        if link.kind == KIND.REGEX:
            payload = self._regex_payload(link.regexes)
        else:
            payload = self._python_payload(link)
        await self._push(payload)

    def _regex_payload(self, regexes: list[Regex]) -> bytes:
        """cppregex takes its patterns as hex codes, one per direction.

        `<case><direction><hex>`: a pattern is bytes, and the only encoding both ends
        agree on without quoting rules is hex.
        """
        self._codes = {}
        codes = []
        for rx in regexes:
            if not rx.active:
                continue
            case = "1" if rx.case_sensitive else "0"
            for direction, wanted in (("C", rx.is_input), ("S", rx.is_output)):
                if wanted:
                    code = case + direction + rx.regex.hex()
                    self._codes[code] = rx.id
                    codes.append(code)
        return (" ".join(codes) + "\n").encode()

    def _python_payload(self, link: ChainLink) -> bytes:
        """cpproxy takes the user's module and compiles it in its own interpreter.

        **Nothing of the user's code runs here.** Which functions the file defines used to
        be asked of the library in this process, which meant `exec`ing the module body
        inside the backend's own event loop on every start and every reload — the thing
        `pyworker.py --check` exists to keep out of it. The binary is told which functions
        the operator left switched on, by name, and the library in there works out the rest
        against the module it has just compiled: `None` means every one the file defines,
        and a name the file no longer defines is passed over rather than refusing the file.
        """
        code = ""
        if link.code_path and os.path.exists(link.code_path):
            with open(link.code_path) as f:
                code = f.read()
        self._codes = {}
        enabled = link.enabled_functions
        body = (
            code
            + "\n\n__firegex_pyfilter_enabled = "
            + ("None" if enabled is None else repr(list(enabled)))
            + "\n"
            # No protocol is written in. The file shows which one it speaks by what its
            # filters ask for, so a file cannot disagree with its own declaration — it
            # used to be passed in from here, and a filter asking for an HttpRequest
            # under a service that said `tcp` was refused with an error naming its own
            # annotation.
            + "import firegex.pyfilters.internals\n"
            + "firegex.pyfilters.internals.compile(globals())\n"
        ).encode()
        # The length of what is sent, in bytes: counted in characters, a file with one
        # accented letter in a comment announced fewer bytes than followed, and the rest of
        # it was read as the next length prefix — the binary refused the code, then took the
        # leftover as an absurd size and exited.
        return len(body).to_bytes(4, byteorder="big") + body

    async def _push(self, payload: bytes):
        self._ack = asyncio.get_running_loop().create_future()
        if self._sock_writer:
            self._sock_writer.write(payload)
            await self._sock_writer.drain()
        elif self.process and self.process.stdin:
            self.process.stdin.write(payload)
            await self.process.stdin.drain()
        else:
            raise Exception("the nfqueue binary is not running")
        try:
            ok, detail = await asyncio.wait_for(self._ack, timeout=ACK_TIMEOUT)
        except asyncio.TimeoutError:
            await self.stop()
            raise Exception("the nfqueue binary did not acknowledge the filters")
        finally:
            self._ack = None
        if not ok:
            await self.stop()
            raise Exception(f"the nfqueue binary rejected the filters: {detail}")

    async def stop(self) -> None:
        # Said before anything is torn down, or the watchdog wakes on the kill below and
        # reports a crash we asked for.
        self._stopped = True
        if self._watchdog and self._watchdog is not asyncio.current_task():
            self._watchdog.cancel()
        self._watchdog = None
        for task in (self._reader_task, self._output_task):
            if task:
                task.cancel()
        self._reader_task = self._output_task = None
        if self._sock_server:
            self._sock_server.close()
            self._sock_server = None
        self._sock_reader = self._sock_writer = None
        if self._sock_path and os.path.exists(self._sock_path):
            os.remove(self._sock_path)
        self._sock_path = None
        if self.process and self.process.returncode is None:
            self.process.kill()
            await self.process.wait()
        self.process = None
        self.queue_num = None


class NfqueueTransport(Transport):
    """Packets are queued to userspace; the kernel keeps a verdict-shaped hole open.

    Nothing is terminated, so the protected service sees the original connection with no
    help from us, and `NFQA_CFG_F_FAIL_OPEN` plus the `bypass` flag on the nft rule mean
    traffic keeps flowing if a filter dies. The price is that a payload cannot be
    rewritten without desynchronising the stream.

    A chain here is a chain of *processes*, one per filter, each with its own queue and
    its own pair of base chains. A packet a filter accepts carries on to the next base
    chain in the same hook, so filter order is chain priority order and the first filter
    to refuse a packet is the last one that sees it. It costs a process and a reassembly
    pass per filter, which is the price of the two binaries fusing transport and filter;
    what it buys is that the model means the same thing on every network layer.
    """

    name = TRANSPORT.NFQUEUE

    @classmethod
    def check(cls, srv, chain: list[ChainLink]) -> None:
        super().check(srv, chain)
        if str(srv.proto) == L4.HTTP:
            # Not the TLS sentence and not the QUIC one, because the reason is neither:
            # an `http` service is reached over TLS and over QUIC *and* in the clear, and
            # this layer can decrypt none of it. Even the cleartext edge would be half an
            # answer — HTTP/2 in the clear is HPACK, and rendering it means terminating
            # the connection, which is the proxy layer's job by definition.
            raise UnsupportedChain(
                "An `http` service is reached over every version of HTTP at once, which "
                "means TLS on one port and QUIC on another — and this layer inspects "
                "packets on their way past rather than terminating them, so it can read "
                "none of it. Move the service to the proxy layer, or set its protocol to "
                "TCP and filter the HTTP/1.1 going by."
            )
        if srv.decrypts:
            # Decrypting means terminating the connection, which is what the proxy layer
            # does; this one inspects packets on their way past and hands the kernel a
            # verdict, which is the whole reason it can fail open. It was once offered
            # here by putting nginx in front to terminate and re-encrypt, with the
            # filters attached to the plaintext leg in between — so the connection *was*
            # terminated, the layer's one distinguishing property was already gone, and
            # it cost two loopback ports chosen by hashing the address.
            if str(srv.proto) == L4.QUIC:
                # And for QUIC there is not even that: nginx could terminate TLS and hand
                # over a TCP stream, but a QUIC connection past its first packet has its
                # frames and its stream boundaries encrypted as well as its payload.
                # Queued to userspace it is a UDP datagram of noise.
                raise UnsupportedChain(
                    "QUIC encrypts its frames and its stream boundaries, not just the "
                    "payload, so a packet queued to this layer carries nothing a filter "
                    "could read. It has to be terminated to be inspected at all: move "
                    "the service to the proxy layer, or set its protocol to UDP and "
                    "accept that the rules are matching the encrypted datagrams."
                )
            raise UnsupportedChain(
                "A service that speaks TLS has to be decrypted, and decrypting means "
                "terminating the connection — which is what the proxy layer does and "
                "this one deliberately does not. Move the service to the proxy layer, or "
                "set its protocol to TCP and filter the ciphertext as it goes by."
            )
        active = [link for link in chain if link.filter.active]
        if len(active) > MAX_CHAIN_POSITIONS:
            raise UnsupportedChain(
                f"the nfqueue transport chains at most {MAX_CHAIN_POSITIONS} filters, "
                f"and this service has {len(active)} active. Deactivate some, or move it "
                f"to the proxy transport, which walks the chain inside one process."
            )
        # There used to be a third refusal here, for patterns that rewrote the traffic
        # rather than blocking it. Nothing rewrites any more — on either layer — so
        # there is nothing left to refuse: see the note on ACTION in `models.py`.

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stages: list[_QueueStage] = []
        #: One report per datapath, not one per process: a chain is several binaries and
        #: they usually die together, which would otherwise ask for four restarts of one
        #: service.
        self._reported_death = False

    async def start(self, chain: list[ChainLink]) -> dict:
        self.check(self.srv, chain)
        active = [link for link in chain if link.filter.active]
        # No active filter still gets a datapath: the operator turned the rules off, not
        # the service, and turning one back on must not need a restart. An empty regex
        # stage matches nothing and costs one process.
        if not active:
            active = [ChainLink(_EmptyFilter(self.srv.id), regexes=[])]
        try:
            for link in active:
                stage = _QueueStage(self.srv, link, self)
                self.stages.append(stage)
                await stage.start()
        except Exception:
            await self.stop()
            raise
        return {"queue_nums": [stage.queue_num for stage in self.stages]}

    async def reload(self, chain: list[ChainLink]) -> None:
        self.check(self.srv, chain)
        active = [link for link in chain if link.filter.active]
        running = [stage.link.id for stage in self.stages]
        # Nothing active, and nothing but the stand-in running: the shape has not changed.
        # Compared as it was, the stand-in's id never matched an empty list, so every edit
        # to a service whose filters were all switched off — renaming one, adding a
        # pattern to one — tore the whole datapath down and built it again.
        if not active and running == [_EmptyFilter(self.srv.id).id]:
            return
        # A filter appearing, disappearing or changing places changes which process sits
        # at which priority, and that is the chain itself. Pushing new rules into the
        # processes that happen to be running would enforce the old order.
        if [link.id for link in active] != running:
            raise ChainShapeChanged()
        for stage, link in zip(self.stages, active):
            await stage.reload(link)

    async def stop(self) -> None:
        for stage in self.stages:
            await stage.stop()
        self.stages = []

    def _stage_died(self, filter_name: str, returncode: int):
        """One of the chain's processes is gone and nobody asked it to go.

        Reported once per shutdown: the stages share a service, so a chain of four that
        dies together would otherwise ask for four restarts of the same thing.
        """
        if self._reported_death:
            return
        self._reported_death = True
        if self.on_died:
            self.on_died(f"the {filter_name} interceptor", returncode)


class _EmptyFilter:
    """Stands in for a service with nothing active, so it still has a datapath."""

    def __init__(self, service_id: str):
        self.id = f"empty-{service_id}"
        self.name = "no active filter"
        self.kind = KIND.REGEX
        self.proto = PROTO.TCP
        self.active = True


def supports_ipv6() -> bool:
    try:
        import socket
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::", 0))
            return True
    except Exception:
        return False


class ProxyTransport(Transport):
    """The connection is terminated and reopened towards the service.

    That buys the whole chain: filters run in the order the operator set, a rewrite is
    exact because we own both halves, reassembly is the kernel's problem, and a slow
    filter slows the sender instead of dropping packets. What it costs is the kernel's
    fail-open backstop, which the engine rebuilds by hand — a filter that panics, hangs
    or crashes loses its say and the traffic keeps moving.

    The proxy is meant to be invisible: it always dials the service from the client's
    own address, and there is no setting for that. A service that suddenly saw one
    address for the whole internet would be a regression nobody would attribute to us.
    """

    name = TRANSPORT.PROXY

    @classmethod
    def check(cls, srv, chain: list[ChainLink]) -> None:
        super().check(srv, chain)
        # Asked here as well as where each was set, because an address added afterwards
        # can be one this instance cannot honour.
        for addr in srv.addresses:
            refusal = upstream_refusal(
                srv.proto, addr.upstream, L4.l4_of(addr.edge) == L4.UDP
            )
            if refusal:
                raise UnsupportedChain(refusal)
        if srv.carries(L4.UDP):
            from utils import get_interface_ips, is_ip_parse
            # Only the addresses that need a relay of their own. On an `http` service
            # those are its QUIC ones, sitting beside TCP addresses that need nothing of
            # the sort — which is why this asks the address rather than the service.
            for addr in srv.udp_addresses:
                if not is_ip_parse(addr.ip_int):
                    ips = get_interface_ips(addr.ip_int)
                    if not ips:
                        raise UnsupportedChain(
                            f"interface '{addr.ip_int}' has no IP assigned for UDP proxy relay. "
                            f"Use an IP address or NFQUEUE transport."
                        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._reader_task: asyncio.Task | None = None
        self._ack: asyncio.Future | None = None
        self._cmd_lock = asyncio.Lock()
        self.port: int | None = None
        #: One relay port per protected address, for UDP, keyed by `udp_relay_slot`: where
        #: the relay sends and what it speaks there. TCP needs none of this: a single
        #: listener fronts every address and recovers where each connection was headed
        #: from conntrack, which UDP cannot do — see `udp.rs`.
        self.udp_ports: dict[str, int] = {}
        #: Set by `stop()`, so the watchdog can tell a shutdown we asked for from one we
        #: did not — the same distinction the NFQUEUE stages make.
        self._stopped = False
        self._watchdog: asyncio.Task | None = None

    def _published(self) -> list[str]:
        """What this engine is told about its TCP addresses, one entry each.

        `10.0.0.1:443|tls|plain=10.0.0.1:80` reads as: what arrives at the first is
        spoken under TLS, the service behind it answers in the clear, and it is at the
        second. Every part after the address is optional and an address that needs none
        of them is not listed at all — which is every address of every service until an
        operator says otherwise, and is what keeps the transparent case exactly as it
        was.

        Only TCP: a UDP or QUIC address has a relay of its own, bound to the service it
        fronts and terminating what it was built to terminate, so both questions are
        already answered by `FGEX_PROXY_UDP`.

        **An interface is resolved to the addresses it carries, one entry each**, rather
        than skipped. The engine keys this map on what `SO_ORIGINAL_DST` hands back,
        which is an address and never an interface — so there was nothing to key on and
        the row was dropped. What that cost: an HTTPS edge declared on `lo:443` was never
        announced, so the engine met the connection with no idea it was a TLS edge or
        that the service was on `:80`, terminated it as an ordinary one and dialled
        `:443`, where nothing listens. HTTPS on that address simply did not answer, and
        the same address written `127.0.0.1:443` worked — which is how it was found.
        """
        out = []
        for addr in self.srv.addresses:
            # An address with nothing to say is not listed: the engine's answer for one
            # it has never heard of is the transparent case, which is exactly what it
            # would be told. `announcement` is where that is decided, and it is shared
            # with `ServiceManager.address_added` so that an address present at startup
            # and one added afterwards cannot come to mean different things.
            said = announcement(self.srv, addr)
            if said is None:
                continue
            for host in interface_addresses(addr.ip_int):
                entry = f"{udp_relay_key(host, addr.port)}|{said.word}|{said.onward}"
                if said.target_port:
                    entry += f"={udp_relay_key(host, said.target_port)}"
                out.append(entry)
        return out

    def _udp_targets(self) -> list[tuple[str, int, str]]:
        """The addresses that each need a relay of their own, resolved. Empty for TCP.

        Resolved here and nowhere else, so the relay the engine is asked to open, the
        rule that points at it and the key both are filed under are derived from one
        answer rather than from three lookups that could each land somewhere different.

        The third item is what the service behind *that relay* speaks, because a relay is
        one protected address and the question belongs to the address.
        """
        out = []
        for addr in self.srv.udp_addresses:
            target = service_at(self.srv, addr)
            if not target:
                continue
            target_ip, target_port = target
            try:
                out.append((udp_relay_host(target_ip), target_port,
                            UPSTREAM.env(addr.upstream)))
            except NoRelayAddress as e:
                raise UnsupportedChain(
                    f"{e}. Give the service an IP address, or put it on the NFQUEUE "
                    f"layer, which needs none."
                ) from e
        return out

    def _crypto_env(self) -> dict:
        """Hand the engine its certificate, or nothing at all.

        The engine reads **paths**, not the material: a certificate on a command line or
        in an environment dump is a certificate in a log somewhere. They are written
        `0600` under a directory of the service's own, and removed when it stops.

        What the service *behind* speaks does not travel here: it is the address's
        answer, not the service's, so it rides with the address — on `FGEX_PROXY_TARGETS`
        and `PUBLISH` for a TCP one, and on `FGEX_PROXY_UDP` and `ADD_UDP` for a relay.
        `same` re-encrypts on the way out the way nginx's `proxy_ssl on` did; the other
        two say the service speaks HTTP/1.1, in the clear or under its own TLS.

        QUIC takes the same pair and one more word. It needs no `_UPSTREAM` flag because
        there is no unencrypted QUIC to choose between — the handshake is part of the
        transport — and it needs `FGEX_PROXY_QUIC` because what binds a protected
        address is then an endpoint that terminates rather than a socket that forwards.
        """
        if not self.srv.decrypts:
            return {}
        os.makedirs(TLS_DIR, exist_ok=True)
        cert_path = os.path.join(TLS_DIR, f"{self.srv.id}.crt")
        key_path = os.path.join(TLS_DIR, f"{self.srv.id}.key")
        for path, material in ((cert_path, self.srv.tls_cert), (key_path, self.srv.tls_key)):
            # Opened restricted rather than written and then chmod'ed: between the two
            # there is a moment when the key is readable, and it only takes one.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(material or "")
        material = {
            "FGEX_PROXY_TLS_CERT": cert_path,
            "FGEX_PROXY_TLS_KEY": key_path,
        }
        if str(self.srv.proto) == L4.HTTP:
            # Every edge at once, in one process, with one certificate and one chain.
            # `TLS_OPTIONAL` is the whole of what makes that possible: the TCP listener
            # terminates TLS only for the connections that start a handshake, so the
            # cleartext port and the encrypted one are the same listener and the same
            # filters. `QUIC` is set whether or not the service has a UDP address yet,
            # so that adding one later opens a relay on the engine already running rather
            # than needing it restarted.
            return {
                **material,
                "FGEX_PROXY_TLS": "1",
                "FGEX_PROXY_TLS_OPTIONAL": "1",
                "FGEX_PROXY_QUIC": "1",
                "FGEX_PROXY_QUIC_ALPN": ",".join(quic_alpn()),
            }
        if str(self.srv.proto) == L4.QUIC:
            return {
                **material,
                "FGEX_PROXY_QUIC": "1",
                # What the engine offers the service, in this order. It cannot be asked
                # of the client the way the TLS path asks: a QUIC ClientHello arrives
                # inside an encrypted Initial whose processing *is* the handshake, so
                # there is nothing to hold it at and nothing to read before answering.
                # `h3` is what a QUIC service speaks nine times in ten; an instance in
                # front of something else sets this in its own environment, the same way
                # the filter deadline beside it is set. Per service it would be a column,
                # and nothing yet has wanted one.
                "FGEX_PROXY_QUIC_ALPN": ",".join(quic_alpn()),
            }
        return material

    def _clear_crypto_material(self) -> None:
        for suffix in (".crt", ".key"):
            try:
                os.remove(os.path.join(TLS_DIR, f"{self.srv.id}{suffix}"))
            except OSError:
                pass

    async def start(self, chain: list[ChainLink]) -> dict:
        self.check(self.srv, chain)
        # The listener has to be able to accept every family the service answers in. A
        # dual-stack listener ([::]:0) is used whenever IPv6 is supported on the host,
        # so it accepts both IPv4 (as mapped addresses) and IPv6 connections from the start.
        # This allows adding new IPv6 addresses to a running service without any restart.
        self.is_dual_stack = self.srv.has_ipv6 or supports_ipv6()
        listen = "[::]:0" if self.is_dual_stack else "0.0.0.0:0"
        # Resolved once: the list the engine is launched with and the number of `UDP`
        # lines read back afterwards have to be the same answer.
        relays = self._udp_targets()
        self.process = await asyncio.create_subprocess_exec(
            PROXY_ENGINE,
            stdout=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
            # Captured rather than inherited: the engine writes its warnings here, and
            # on the backend's own stderr nobody reads them during a competition.
            stderr=asyncio.subprocess.PIPE,
            env=dict(
                os.environ,
                **{
                    # Port 0: the kernel picks and the engine reports back, so nothing
                    # has to keep a registry of which ports are already taken.
                    "FGEX_PROXY_LISTEN": listen,
                    "FGEX_PROXY_UPSTREAM": "original",
                    "FGEX_PROXY_SPOOF_SOURCE": "1",
                    # The same knob the NFQUEUE binaries get. `run.py --threads` used to
                    # reach them and not this engine, so one flag meant two things.
                    "NTHREADS": os.getenv("NTHREADS", "1"),
                    # One relay per address, each with its upstream already known:
                    # `SO_ORIGINAL_DST` is TCP-only, so there is nothing to recover per
                    # datagram and nothing to recover it from. The same list serves QUIC,
                    # which is UDP as far as the rules are concerned — what changes is
                    # what binds the port, and `_crypto_env` is where that is said.
                    "FGEX_PROXY_UDP": ",".join(
                        udp_relay_slot(ip, port, onward) for ip, port, onward in relays
                    ),
                    # The addresses this service is *published* on rather than
                    # intercepted at: `dialled=service`, one pair per address that says
                    # where the service really is. Only TCP needs telling — a UDP or
                    # QUIC address has a relay of its own whose upstream is already the
                    # answer, which is the same list above. Empty is the transparent
                    # case, which is every address that did not say otherwise.
                    "FGEX_PROXY_TARGETS": ",".join(self._published()),
                    # One number for both halves: TCP connections and UDP flows spend
                    # the same descriptors, and two limits meaning "how much of that may
                    # go" would be two things to keep in step.
                    "FGEX_PROXY_MAX_CONNECTIONS": str(self.srv.max_connections),
                    **({"FGEX_PROXY_OVER_LIMIT_FORWARD": "1"}
                       if self.srv.over_limit_forwards else {}),
                    "FGEX_PROXY_FIRST_BYTE_TIMEOUT": str(self.srv.first_byte_timeout),
                    "FGEX_PROXY_FILTER_TIMEOUT_MS": os.getenv("FGEX_PROXY_FILTER_TIMEOUT_MS", "2000"),
                    **self._crypto_env(),
                },
            ),
        )
        nicenessify(-10, self.process.pid)
        self._stderr_pump = self._pump_stderr(self.process.stderr)
        try:
            line = (
                await asyncio.wait_for(self.process.stdout.readuntil(), timeout=ACK_TIMEOUT)
            ).decode()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            # Read before `stop()` clears it: the pump is cancelled there.
            reason = await self._died_because("the proxy engine would not start")
            await self.stop()
            raise Exception(reason) from e
        if not line.startswith("PORT "):
            await self.stop()
            raise Exception(f"unexpected output from the proxy engine: {line.strip()!r}")
        self.port = int(line.split()[1])
        # One `UDP <upstream> <port>` line per relay, before anything else. Read here
        # rather than in the event loop because the rules cannot be installed until
        # every one of them is known.
        for _ in relays:
            try:
                line = (
                    await asyncio.wait_for(self.process.stdout.readuntil(), timeout=ACK_TIMEOUT)
                ).decode()
            except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
                reason = await self._died_because(
                    "the proxy engine would not open a UDP relay")
                await self.stop()
                raise Exception(reason) from e
            if not line.startswith("UDP "):
                await self.stop()
                raise Exception(f"unexpected output from the proxy engine: {line.strip()!r}")
            _, slot, port = line.split()
            self.udp_ports[slot] = int(port)
        # Only now: the handshake line was read directly above, and everything after
        # it belongs to the event reader.
        self._reader_task = asyncio.create_task(self._read_events())
        # And someone to notice if it goes. The nft rules outlive the process: without
        # this an engine that died — killed by the OOM killer under a flood, say — left
        # every connection redirected at a port nobody listened on, so each client got a
        # reset while the interface went on reporting the service as active, and nothing
        # ever brought it back. The NFQUEUE stages always had one.
        self._watchdog = asyncio.create_task(self._watch())
        # Rules before traffic. The engine must already be enforcing when the nft rule
        # starts sending it connections, or the first ones through a freshly started
        # service would go unfiltered.
        await self.reload(chain)
        return {"proxy_port": self.port, "udp_ports": self.udp_ports}

    def _payload(self, chain: list[ChainLink]) -> str:
        """The chain as the engine's one-line JSON, in the operator's order."""
        out = []
        for link in chain:
            if not link.filter.active:
                continue
            if link.kind == KIND.REGEX:
                for rx in link.regexes:
                    if not rx.active:
                        continue
                    out.append(
                        {
                            "kind": "regex",
                            "id": rx.id,
                            # Which filter it belongs to, so the engine knows where one
                            # thing the operator placed ends and the next begins.
                            "filter": link.id,
                            "pattern": rx.regex.decode(errors="replace"),
                            "direction": {"C": "c2s", "S": "s2c"}.get(rx.mode, "both"),
                            "case_sensitive": rx.case_sensitive,
                        }
                    )
            elif link.kind == KIND.PYFILTER and link.code_path:
                out.append(
                    {
                        "kind": "python",
                        "id": link.id,
                        "code_path": os.path.abspath(link.code_path),
                        # Which of the file's functions are switched on. `None` — the
                        # case of a filter whose list was never derived — means all of
                        # them, and is not the same as an empty list, which means the
                        # operator switched every one of them off.
                        "enabled": link.enabled_functions,
                        # No protocol: the worker reads it off the file, the same way
                        # the NFQUEUE binary does. This used to send the *service's*
                        # protocol, which is a different thing entirely — so an HTTP
                        # filter on a TCP service was refused for asking for an
                        # HttpRequest, which is the only thing an HTTP filter does.
                        "command": [sys.executable or "python3", PYWORKER],
                        "timeout_ms": 1000,
                    }
                )
        return json.dumps(out)

    async def _watch(self):
        """Notice the engine dying, which nothing else here does. See `start`."""
        process = self.process
        try:
            returncode = await process.wait()
        except asyncio.CancelledError:
            return
        if self._stopped or process is not self.process:
            return  # we stopped it ourselves
        if self.on_died:
            self.on_died("the proxy engine", returncode)

    async def reload(self, chain: list[ChainLink]) -> None:
        if not self.process or self.process.returncode is not None:
            # Said, rather than passed over: returning quietly made an edit look applied
            # to an engine that was not there to apply it. The watchdog restarts a dead
            # engine from what the database holds.
            raise Exception("the proxy engine is not running")
        async with self._cmd_lock:
            self._ack = asyncio.get_running_loop().create_future()
            self.process.stdin.write((self._payload(chain) + "\n").encode())
            await self.process.stdin.drain()
            try:
                ok, detail = await asyncio.wait_for(self._ack, timeout=ACK_TIMEOUT)
            except asyncio.TimeoutError:
                raise Exception("the proxy engine did not acknowledge the chain")
            finally:
                self._ack = None
            if not ok:
                # Deliberately not fatal to the datapath: the engine keeps enforcing the
                # chain it already had, so a rejected edit costs the operator an error
                # message rather than their protection.
                raise Exception(f"the proxy engine rejected the chain: {detail}")

    async def add_udp_target(self, ip: str, port: int, onward: str = "same") -> int:
        """Bind a dedicated UDP relay for a new address without restarting the engine.

        `onward` is what the service behind *this* relay speaks, because a relay is one
        protected address and that question belongs to the address.

        Idempotent, and deliberately the only way in: the map of relays is this
        object's, so a caller that has just added an address asks for the relay and is
        handed the port, rather than keeping a second map of its own beside this one.
        """
        host = udp_relay_host(ip)
        target = udp_relay_key(host, port)
        # What names a relay is where it sends *and* what it speaks there: keyed on the
        # first alone, an address whose answer was edited on a running service was handed
        # the relay it already had, and the new choice reached nothing until a restart.
        slot = udp_relay_slot(host, port, onward)
        if slot in self.udp_ports:
            return self.udp_ports[slot]
        if not self.process or self.process.returncode is not None:
            raise Exception("the proxy engine is not running")

        async with self._cmd_lock:
            if slot in self.udp_ports:
                return self.udp_ports[slot]
            self._ack = asyncio.get_running_loop().create_future()
            self.process.stdin.write(f"ADD_UDP {target} {onward}\n".encode())
            await self.process.stdin.drain()
            try:
                ok, detail = await asyncio.wait_for(self._ack, timeout=ACK_TIMEOUT)
            except asyncio.TimeoutError:
                raise Exception(f"the proxy engine did not acknowledge ADD_UDP for {target}")
            finally:
                self._ack = None
            if not ok:
                raise Exception(f"the proxy engine rejected ADD_UDP {target}: {detail}")
            relay_port = self.udp_ports.get(slot)
            if relay_port is None:
                raise Exception(
                    f"the proxy engine acknowledged ADD_UDP but did not report port for {slot}"
                )
            return relay_port

    async def publish(self, public: tuple[str, int], edge: str, onward: str,
                      target: tuple[str, int] | None) -> None:
        """Tell the running engine about one TCP address.

        The same thing `FGEX_PROXY_TARGETS` says at startup, said to an engine that is
        already carrying traffic — because an address can be added to a running service
        and the point of that is that nothing is dropped.

        UDP and QUIC addresses are not here: theirs is a relay with its upstream fixed
        when it is bound, so `add_udp_target` has already answered both questions.
        """
        where = f" {udp_relay_key(*target)}" if target else ""
        await self._command(f"PUBLISH {udp_relay_key(*public)} {edge} {onward}{where}")

    async def withdraw(self, public: tuple[str, int]) -> None:
        await self._command(f"WITHDRAW {udp_relay_key(*public)}")

    async def _command(self, line: str) -> None:
        """One control line, and the acknowledgement it is owed."""
        if not self.process or self.process.returncode is not None:
            raise Exception("the proxy engine is not running")
        async with self._cmd_lock:
            self._ack = asyncio.get_running_loop().create_future()
            self.process.stdin.write(f"{line}\n".encode())
            await self.process.stdin.drain()
            try:
                ok, detail = await asyncio.wait_for(self._ack, timeout=ACK_TIMEOUT)
            except asyncio.TimeoutError:
                raise Exception(f"the proxy engine did not acknowledge {line.split()[0]}")
            finally:
                self._ack = None
            if not ok:
                raise Exception(f"the proxy engine rejected {line}: {detail}")

    async def _read_events(self):
        try:
            while True:
                line = (await self.process.stdout.readuntil()).decode().strip()
                if DEBUG:
                    print(f"[{self.srv.name}] {line}")
                if line.startswith("ACK "):
                    rest = line[4:].strip()
                    if self._ack and not self._ack.done():
                        self._ack.set_result((rest.upper().startswith("OK"), rest))
                elif line.startswith("UDP "):
                    parts = line.split()
                    if len(parts) == 3:
                        _, slot, port_str = parts
                        self.udp_ports[slot] = int(port_str)
                elif line.startswith("BLOCKED "):
                    self._emit_block(line.split()[1])
                elif line.startswith("STATS "):
                    # `seen` and `refused`, both connections, both cumulative since the
                    # engine started. Reported on a timer rather than one line per
                    # connection: this is a denominator, not a live feed.
                    was = self.counters.get("over_limit", 0)
                    for token in line[6:].split():
                        key, _, value = token.partition("=")
                        if value.isdigit():
                            self.counters[key] = int(value)
                    # Only the increase, and only when there is one: the engine counts
                    # from zero every time it starts, so handing the absolute number up
                    # would reset the durable trace on every restart of the service.
                    grew = self.counters.get("over_limit", 0) - was
                    if grew > 0 and self.on_over_limit:
                        self.on_over_limit(grew)
        except (asyncio.CancelledError, asyncio.IncompleteReadError):
            pass
        except Exception:
            traceback.print_exc()

    async def stop(self) -> None:
        # Said before anything is torn down, or the watchdog wakes on the kill below and
        # reports a crash we asked for.
        self._stopped = True
        if self._watchdog and self._watchdog is not asyncio.current_task():
            self._watchdog.cancel()
        self._watchdog = None
        for task in (self._reader_task, self._stderr_pump):
            if task:
                task.cancel()
        self._reader_task = self._stderr_pump = None
        self.port = None
        await self._kill()
        # After the engine is gone, never before: a key removed while the process that
        # reads it is still running would be a key removed from under a restart.
        self._clear_crypto_material()


class ExternalTransport(Transport):
    """Hand the traffic to a proxy the operator runs themselves.

    Nothing of firegex is in the path: the rules rewrite the destination on the way in
    and change it back on the way out, so their proxy sees the connection arrive and the
    client sees answers from the address it dialled. It is the escape hatch for a
    protocol none of the built-in filters understand — write the proxy, point a service
    at it, and firegex arranges the rest.

    Because nothing here inspects anything, a filter attached to such a service would be
    a filter that never runs. Saying so beats letting an operator believe their patterns
    are in force.
    """

    name = TRANSPORT.EXTERNAL

    @classmethod
    def check(cls, srv, chain: list[ChainLink]) -> None:
        super().check(srv, chain)
        if any(addr.is_interface for addr in srv.addresses):
            raise UnsupportedChain(
                "the external transport hands traffic to an external proxy and rewrites the "
                "source IP on return, which requires a concrete IP address rather than an interface."
            )
        missing = [addr for addr in srv.addresses if not addr.proxy_port]
        if missing:
            raise UnsupportedChain(
                f"this service hands its traffic to a proxy you run, so every address "
                f"needs the port that proxy listens on for it — "
                f"{', '.join(f'{a.ip_int}:{a.port}' for a in missing)} has none. They "
                f"cannot share one: the return rule puts the original port back by "
                f"recognising your proxy's, so two addresses behind the same endpoint "
                f"could not be told apart on the way out."
            )
        active = [link for link in chain if link.filter.active]
        if active:
            raise UnsupportedChain(
                f"this service hands its traffic to your own proxy, so firegex inspects "
                f"nothing and the {len(active)} filter(s) attached to it would never run. "
                f"Deactivate them, or move the service to the proxy transport, which "
                f"filters and can still forward."
            )
        if srv.decrypts:
            raise UnsupportedChain(
                f"Decrypting exists so that filters can see the plaintext, and this "
                f"service has no filters — nothing of firegex is in its path. Let your own "
                f"proxy speak "
                f"{'QUIC' if str(srv.proto) == L4.QUIC else 'HTTP itself' if str(srv.proto) == L4.HTTP else 'TLS'}"
                f", or move "
                f"the service to the proxy layer."
            )

    async def start(self, chain: list[ChainLink]) -> dict:
        self.check(self.srv, chain)
        # Deliberately nothing to start. The rules are the whole mechanism, and the
        # manager installs them right after this returns.
        return {}

    async def reload(self, chain: list[ChainLink]) -> None:
        self.check(self.srv, chain)

    async def stop(self) -> None:
        pass


TRANSPORTS = {
    TRANSPORT.NFQUEUE: NfqueueTransport,
    TRANSPORT.PROXY: ProxyTransport,
    TRANSPORT.EXTERNAL: ExternalTransport,
}


def build(srv, **kwargs) -> Transport:
    try:
        return TRANSPORTS[srv.transport](srv, **kwargs)
    except KeyError:
        raise Exception(f"unknown transport {srv.transport!r}")


def build_class(transport: str) -> type[Transport]:
    """The transport a name stands for, for asking `check()` before anything exists."""
    try:
        return TRANSPORTS[transport]
    except KeyError:
        raise Exception(f"unknown transport {transport!r}")
