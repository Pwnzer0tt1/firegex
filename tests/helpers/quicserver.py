"""A QUIC service for firegex to protect, and a client that talks to it through firegex.

Deliberately HTTP/3 rather than some invented protocol over QUIC. That is what a QUIC
service is in practice, it is the one the engine terminates rather than relays, and it is
the only shape in which "the filters saw the request" means anything: on the wire a path
is a QPACK-compressed header block, and what the chain is shown is the HTTP/1.1 that
exchange would have been.

`aioquic` is the only way to speak QUIC from Python, and it is not a dependency anybody
should need to have installed to run the rest of the suite — so it is imported here and
the tests that need it skip with a reason when it is missing, like every other thing this
machine may decline to do.
"""

import asyncio
import ssl
import threading

import pytest

try:
    from aioquic.asyncio import serve
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ConnectionTerminated, StreamDataReceived
    HAVE_AIOQUIC = True
except ImportError:  # pragma: no cover - depends on what is installed
    HAVE_AIOQUIC = False


needs_quic = pytest.mark.skipif(
    not HAVE_AIOQUIC,
    reason="aioquic is not installed, so nothing here can speak QUIC",
)

#: What the service answers on this path, and nowhere else. The point of having it is
#: that a test of the *answer* has to use bytes that appear nowhere in the request.
SECRET_PATH = "/secret"
SECRET_ANSWER = "here is FLAG{only-in-the-answer}"


class QuicEcho:
    """An HTTP/3 service that answers with what it was asked.

    A thread running an event loop of its own, because aioquic is asyncio and the rest of
    the suite is not. Stopping it closes the loop, which is what ends the server.
    """

    def __init__(self, port: int, cert: str, key: str, ipv6: bool = False,
                 alpn: list[str] | None = None):
        self.port = port
        self.cert = cert
        self.key = key
        self.ipv6 = ipv6
        #: What it negotiates. HTTP/3 unless told otherwise; anything else is a service
        #: that echoes each stream back as it is — QUIC carrying a protocol of its own,
        #: which is what a CTF's QUIC service usually is when it is not a web one.
        self.alpn = alpn
        #: Every address a connection arrived from. What the *service* saw, which is the
        #: only way to check that the client's own address survived the relay.
        self.seen_peers: list[tuple] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    @property
    def host(self) -> str:
        return "::1" if self.ipv6 else "127.0.0.1"

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=10):
            raise RuntimeError("the QUIC stand-in did not come up")

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())
        self._loop.run_forever()

    async def _serve(self):
        import tempfile
        import os
        # aioquic reads them from disk, and a key written world-readable is a key
        # somebody else on the machine can have.
        paths = []
        for material in (self.cert, self.key):
            fd, path = tempfile.mkstemp()
            with os.fdopen(fd, "w") as handle:
                handle.write(material)
            os.chmod(path, 0o600)
            paths.append(path)
        config = QuicConfiguration(is_client=False, alpn_protocols=self.alpn or H3_ALPN)
        config.load_cert_chain(paths[0], paths[1])
        seen = self.seen_peers
        protocol = _EchoProtocol if not self.alpn else _RawEchoProtocol
        await serve(self.host, self.port, configuration=config,
                    create_protocol=lambda *a, **kw: protocol(seen, *a, **kw))
        for path in paths:
            os.unlink(path)
        self._ready.set()

    def stop(self):
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)


if HAVE_AIOQUIC:

    class _EchoProtocol(QuicConnectionProtocol):
        def __init__(self, seen_peers, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._seen = seen_peers
            self._http = H3Connection(self._quic)
            self._bodies: dict[int, bytes] = {}
            self._paths: dict[int, str] = {}

        def quic_event_received(self, event):
            for http_event in self._http.handle_event(event):
                if isinstance(http_event, HeadersReceived):
                    headers = dict(http_event.headers)
                    self._paths[http_event.stream_id] = \
                        headers.get(b":path", b"/").decode()
                    self._bodies[http_event.stream_id] = b""
                    if http_event.stream_ended:
                        self._answer(http_event.stream_id)
                elif isinstance(http_event, DataReceived):
                    self._bodies[http_event.stream_id] = \
                        self._bodies.get(http_event.stream_id, b"") + http_event.data
                    if http_event.stream_ended:
                        self._answer(http_event.stream_id)

        def _answer(self, stream_id: int):
            path = self._paths.get(stream_id, "/")
            body = self._bodies.get(stream_id, b"")
            peer = getattr(self._quic, "_network_paths", None)
            if peer:
                self._seen.append(peer[0].addr)
            answer = (SECRET_ANSWER if path == SECRET_PATH else
                      f"you asked for {path} and sent {len(body)} bytes: "
                      f"{body.decode(errors='replace')}").encode()
            self._http.send_headers(stream_id, [
                (b":status", b"200"),
                (b"content-length", str(len(answer)).encode()),
            ])
            self._http.send_data(stream_id, answer, end_stream=True)
            self.transmit()

    class _RawEchoProtocol(QuicConnectionProtocol):
        """Each stream back as it came, once the client has finished sending it."""

        def __init__(self, seen_peers, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._streams: dict[int, bytes] = {}

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                self._streams[event.stream_id] = \
                    self._streams.get(event.stream_id, b"") + event.data
                if event.end_stream:
                    self._quic.send_stream_data(
                        event.stream_id, self._streams.pop(event.stream_id), end_stream=True)
                    self.transmit()

    class _RequestingProtocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._http = H3Connection(self._quic)
            self._waiters: dict[int, asyncio.Future] = {}
            self._bodies: dict[int, bytes] = {}

        async def ask(self, method: str, authority: str, path: str,
                      body: bytes | None = None, declare_length: bool = False) -> str:
            stream_id = self._quic.get_next_available_stream_id()
            headers = [
                (b":method", method.encode()),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
            ]
            if declare_length:
                headers.append((b"content-length", str(len(body or b"")).encode()))
            self._http.send_headers(stream_id, headers, end_stream=body is None)
            if body is not None:
                self._http.send_data(stream_id, body, end_stream=True)
            waiter = asyncio.get_event_loop().create_future()
            self._waiters[stream_id] = waiter
            self._bodies[stream_id] = b""
            self.transmit()
            return await asyncio.shield(waiter)

        def quic_event_received(self, event):
            if isinstance(event, ConnectionTerminated):
                # What a blocked exchange looks like from here: the connection carrying
                # it is closed, with firegex's reason on it.
                for waiter in self._waiters.values():
                    if not waiter.done():
                        waiter.set_exception(
                            ConnectionError(f"closed: {event.reason_phrase or event.error_code}")
                        )
                self._waiters.clear()
                return
            for http_event in self._http.handle_event(event):
                stream_id = getattr(http_event, "stream_id", None)
                if stream_id is None or stream_id not in self._waiters:
                    continue
                if isinstance(http_event, DataReceived):
                    self._bodies[stream_id] += http_event.data
                ended = getattr(http_event, "stream_ended", False)
                if ended and not self._waiters[stream_id].done():
                    self._waiters.pop(stream_id).set_result(
                        self._bodies.pop(stream_id).decode(errors="replace")
                    )


async def _ask(host: str, port: int, method: str, path: str,
               body: bytes | None, declare_length: bool, timeout: float) -> str:
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    # The certificate is firegex's own, minted for the test: there is nothing to verify
    # it against and nothing this proves by trying.
    config.verify_mode = ssl.CERT_NONE
    async with connect(host, port, configuration=config,
                       create_protocol=_RequestingProtocol) as client:
        return await asyncio.wait_for(
            client.ask(method, authority(host, port), path, body, declare_length), timeout
        )


async def _raw(host: str, port: int, alpn: str, payload: bytes, timeout: float) -> bytes:
    config = QuicConfiguration(is_client=True, alpn_protocols=[alpn])
    config.verify_mode = ssl.CERT_NONE
    async with connect(host, port, configuration=config) as client:
        reader, writer = await client.create_stream()
        writer.write(payload)
        writer.write_eof()
        return await asyncio.wait_for(reader.read(), timeout)


def quic_exchange(host: str, port: int, alpn: str, payload: bytes,
                  timeout: float = 8.0) -> bytes | None:
    """One stream over a QUIC connection negotiating `alpn`: what came back, or `None`
    when no connection could be made or nothing came back in time."""
    try:
        return asyncio.run(asyncio.wait_for(_raw(host, port, alpn, payload, timeout),
                                            timeout + 2))
    except (ConnectionError, OSError, asyncio.TimeoutError, TimeoutError):
        return None


def authority(host: str, port: int) -> str:
    """What goes in `:authority`, bracketed where the host needs it.

    An IPv6 literal without brackets is not an authority, and the far end is right to
    refuse it: h3 answers `H3_MESSAGE_ERROR`, which arrives here as a connection that
    closed — indistinguishable from a filter having refused the request unless somebody
    looks at the log. So this is the client's business to get right, not something to
    make the engine tolerant of.
    """
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def h3_request(host: str, port: int, path: str = "/", method: str = "GET",
               body: bytes | None = None, declare_length: bool = False,
               timeout: float = 8.0) -> str:
    """One HTTP/3 exchange. Raises if the connection was closed before an answer."""
    return asyncio.run(_ask(host, port, method, path, body, declare_length, timeout))


def h3_is_blocked(host: str, port: int, path: str = "/", **kwargs) -> bool:
    """Whether the exchange was refused rather than answered.

    Only a closed connection counts. A refusal on this layer closes the connection
    carrying the stream, and that is what reaches here as `ConnectionError` — while a
    malformed request, an unreachable port and a timeout are all failures with nothing to
    do with a filter. Catching those too would let "the filter blocked it" pass for
    reasons that are not a block, which is the one assertion in this file that has to be
    exact; so everything else is raised and the test says what actually happened.
    """
    try:
        h3_request(host, port, path, **kwargs)
        return False
    except ConnectionError:
        return True
