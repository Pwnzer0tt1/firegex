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

from modules.services.models import KIND, L4, PROTO, TRANSPORT, Filter, Regex
from modules.services.nftables import (MAX_CHAIN_POSITIONS, NoRelayAddress,
                                       resolve_target, udp_relay_host, udp_relay_key)
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


class Transport:
    """What a network layer has to be able to do."""

    def __init__(self, srv, on_block=None, on_output=None, on_exception=None, on_engine=None,
                 on_over_limit=None):
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

    async def add_udp_target(self, ip: str, port: int) -> int:
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
        #: Which rule id each filter code stands for, for block attribution.
        self._codes: dict[str, str] = {}

    async def start(self) -> int:
        if self.link.kind == KIND.PYFILTER:
            self.queue_num = await self._start_cpproxy()
        else:
            self.queue_num = await self._start_cppregex()
        await self.reload(self.link)
        return self.queue_num

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
                if self.owner.on_output:
                    self.owner.on_output(self.srv.id, data.decode(errors="replace"))
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
                if line.startswith("BLOCKED ") or line.startswith("MANGLED "):
                    code = line.split()[1]
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
        """cpproxy takes the user's module and compiles it in its own interpreter."""
        from firegex.pyfilters.internals import get_filter_names

        code = ""
        if link.code_path and os.path.exists(link.code_path):
            with open(link.code_path) as f:
                code = f.read()
        # Which filters the file defines, asked of the library rather than assumed: it
        # decides what counts as one, and it refuses to compile a module that does not
        # tell it. Every block the binary reports names one of these, so they are also
        # what attributes a refusal to a rule.
        try:
            names = get_filter_names(code) if code.strip() else []
        except Exception:
            # A file that will not even parse is the binary's refusal to make, with the
            # error the operator needs; guessing an empty list here would hide it.
            names = []
        # Only what the operator left switched on, intersected with what the file
        # actually defines: a stale selection naming a function that has since been
        # deleted must not stop the module from loading.
        enabled = link.enabled_functions
        if enabled is not None:
            names = [name for name in names if name in set(enabled)]
        # The binary reports a block by the function name; `<filter>/<function>` is the
        # one token both network layers send, so the backend attributes a block the same
        # way whichever one produced it.
        self._codes = {name: f"{link.id}/{name}" for name in names}
        body = (
            code
            + "\n\n__firegex_pyfilter_enabled = ["
            + ", ".join(repr(name) for name in names)
            + "]\n"
            # No protocol is written in. The file shows which one it speaks by what its
            # filters ask for, so a file cannot disagree with its own declaration — it
            # used to be passed in from here, and a filter asking for an HttpRequest
            # under a service that said `tcp` was refused with an error naming its own
            # annotation.
            + "import firegex.pyfilters.internals\n"
            + "firegex.pyfilters.internals.compile(globals())\n"
        )
        return len(body).to_bytes(4, byteorder="big") + body.encode()

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
        if srv.terminates_tls:
            # Decrypting means terminating the connection, which is what the proxy layer
            # does; this one inspects packets on their way past and hands the kernel a
            # verdict, which is the whole reason it can fail open. It was once offered
            # here by putting nginx in front to terminate and re-encrypt, with the
            # filters attached to the plaintext leg in between — so the connection *was*
            # terminated, the layer's one distinguishing property was already gone, and
            # it cost two loopback ports chosen by hashing the address.
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
        # A filter appearing, disappearing or changing places changes which process sits
        # at which priority, and that is the chain itself. Pushing new rules into the
        # processes that happen to be running would enforce the old order.
        if [link.id for link in active] != [stage.link.id for stage in self.stages]:
            raise ChainShapeChanged()
        for stage, link in zip(self.stages, active):
            await stage.reload(link)

    async def stop(self) -> None:
        for stage in self.stages:
            await stage.stop()
        self.stages = []


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
        if str(srv.proto) == L4.UDP:
            from utils import get_interface_ips, is_ip_parse
            for addr in srv.addresses:
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
        #: One relay port per protected address, for UDP. TCP needs none of this: a
        #: single listener fronts every address and recovers where each connection was
        #: headed from conntrack, which UDP cannot do — see `udp.rs`.
        self.udp_ports: dict[str, int] = {}

    def _udp_targets(self) -> list[tuple[str, int]]:
        """The addresses that each need a relay of their own, resolved. Empty for TCP.

        Resolved here and nowhere else, so the relay the engine is asked to open, the
        rule that points at it and the key both are filed under are derived from one
        answer rather than from three lookups that could each land somewhere different.
        """
        if str(self.srv.proto) != L4.UDP:
            return []
        out = []
        for addr in self.srv.addresses:
            target = resolve_target(self.srv, addr)
            if not target:
                continue
            target_ip, target_port = target
            try:
                out.append((udp_relay_host(target_ip), target_port))
            except NoRelayAddress as e:
                raise UnsupportedChain(
                    f"{e}. Give the service an IP address, or put it on the NFQUEUE "
                    f"layer, which needs none."
                ) from e
        return out

    def _tls_env(self) -> dict:
        """Hand the engine its certificate, or nothing at all.

        The engine reads **paths**, not the material: a certificate on a command line or
        in an environment dump is a certificate in a log somewhere. They are written
        `0600` under a directory of the service's own, and removed when it stops.

        `FGEX_PROXY_TLS_UPSTREAM` is set with them, because a service behind TLS speaks
        TLS: nginx used to re-encrypt on the way out with `proxy_ssl on`, and the engine
        does the same thing in the same place.
        """
        if not self.srv.terminates_tls:
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
        return {
            "FGEX_PROXY_TLS_CERT": cert_path,
            "FGEX_PROXY_TLS_KEY": key_path,
            "FGEX_PROXY_TLS_UPSTREAM": "1",
        }

    def _clear_tls_material(self) -> None:
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
                    # UDP gets one relay per address, each with its upstream already
                    # known: `SO_ORIGINAL_DST` is TCP-only, so there is nothing to
                    # recover per datagram and nothing to recover it from. The client's
                    # address is not preserved on that path, which the operator is told
                    # before choosing it.
                    "FGEX_PROXY_UDP": ",".join(
                        udp_relay_key(ip, port) for ip, port in self._udp_targets()
                    ),
                    # One number for both halves: TCP connections and UDP flows spend
                    # the same descriptors, and two limits meaning "how much of that may
                    # go" would be two things to keep in step.
                    "FGEX_PROXY_MAX_CONNECTIONS": str(self.srv.max_connections),
                    **({"FGEX_PROXY_OVER_LIMIT_FORWARD": "1"}
                       if self.srv.over_limit_forwards else {}),
                    "FGEX_PROXY_FIRST_BYTE_TIMEOUT": str(self.srv.first_byte_timeout),
                    "FGEX_PROXY_FILTER_TIMEOUT_MS": os.getenv("FGEX_PROXY_FILTER_TIMEOUT_MS", "2000"),
                    **self._tls_env(),
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
        for _ in self._udp_targets():
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
            _, upstream, port = line.split()
            self.udp_ports[upstream] = int(port)
        # Only now: the handshake line was read directly above, and everything after
        # it belongs to the event reader.
        self._reader_task = asyncio.create_task(self._read_events())
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

    async def reload(self, chain: list[ChainLink]) -> None:
        if not self.process or self.process.returncode is not None:
            return
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

    async def add_udp_target(self, ip: str, port: int) -> int:
        """Bind a dedicated UDP relay for a new address without restarting the engine.

        Idempotent, and deliberately the only way in: the map of relays is this
        object's, so a caller that has just added an address asks for the relay and is
        handed the port, rather than keeping a second map of its own beside this one.
        """
        target = udp_relay_key(udp_relay_host(ip), port)
        if target in self.udp_ports:
            return self.udp_ports[target]
        if not self.process or self.process.returncode is not None:
            raise Exception("the proxy engine is not running")

        async with self._cmd_lock:
            if target in self.udp_ports:
                return self.udp_ports[target]
            self._ack = asyncio.get_running_loop().create_future()
            self.process.stdin.write(f"ADD_UDP {target}\n".encode())
            await self.process.stdin.drain()
            try:
                ok, detail = await asyncio.wait_for(self._ack, timeout=ACK_TIMEOUT)
            except asyncio.TimeoutError:
                raise Exception(f"the proxy engine did not acknowledge ADD_UDP for {target}")
            finally:
                self._ack = None
            if not ok:
                raise Exception(f"the proxy engine rejected ADD_UDP {target}: {detail}")
            relay_port = self.udp_ports.get(target)
            if relay_port is None:
                raise Exception(
                    f"the proxy engine acknowledged ADD_UDP but did not report port for {target}"
                )
            return relay_port

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
                        _, upstream, port_str = parts
                        self.udp_ports[upstream] = int(port_str)
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
        for task in (self._reader_task, self._stderr_pump):
            if task:
                task.cancel()
        self._reader_task = self._stderr_pump = None
        self.port = None
        await self._kill()
        # After the engine is gone, never before: a key removed while the process that
        # reads it is still running would be a key removed from under a restart.
        self._clear_tls_material()


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
        if srv.terminates_tls:
            raise UnsupportedChain(
                "Decrypting exists so that filters can see the plaintext, and this "
                "service has no filters — nothing of firegex is in its path. Let your own "
                "proxy speak TLS, or move the service to the proxy layer."
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
