"""`fgex pyfilters`: the way an operator tries a filter before it goes near a service.

Run as they would run it — the `fgex` script, as a process of its own, in front of a
real service — because every part of that path has broken on its own at some point: the
file watcher that starts the proxy, the child process it runs in (Python 3.14 starts
those with `forkserver`, which imports the script again), and the filtering itself.
Nothing else in the suite runs it, so a release could ship a simulator that no longer
simulates and nobody would find out until they needed it.

What it has to agree with is production. A filter that refuses here refuses there, clean
traffic comes back, and traffic the HTTP parser cannot read is carried — the library's
default — rather than refused as it used to be.
"""

import os
import signal
import socket
import subprocess
import sys
import threading
import time

import pytest

from helpers.net import free_port

FGEX = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "fgex-lib", "fgex"))

RAW = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

@pyfilter
def refuse(packet: RawPacket):
    return REJECT if b"BLOCKME" in packet.data else ACCEPT
"""

HTTP = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import HttpRequest

@pyfilter
def refuse(req: HttpRequest):
    return REJECT if "BLOCKME" in (req.url or "") else ACCEPT
"""


@pytest.fixture
def echo():
    """A service that answers with whatever it was sent. Returns its port."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", free_port()))
    server.listen(16)

    def answer(conn):
        try:
            while data := conn.recv(4096):
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            threading.Thread(target=answer, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    yield server.getsockname()[1]
    server.close()


@pytest.fixture
def simulator(echo, tmp_path):
    """Start `fgex pyfilters` on a filter file in front of `echo`. Returns an asker."""
    started = []

    def _start(code: str):
        path = tmp_path / "filter.py"
        path.write_text(code)
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, FGEX, "pyfilters", str(path), "127.0.0.1", str(echo),
             "--from-port", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        started.append(proc)
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"fgex pyfilters exited: {proc.stdout.read()}")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("fgex pyfilters never started listening")

        def ask(payload: bytes) -> bytes:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
                    conn.sendall(payload)
                    return conn.recv(4096)
            except OSError:
                return b""

        return ask

    yield _start
    for proc in started:
        # Interrupted rather than killed: that is how an operator stops it, and it is the
        # path that takes the proxy's own process down with it.
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def test_a_raw_filter_refuses_what_it_should_and_carries_the_rest(simulator):
    ask = simulator(RAW)
    assert ask(b"hello") == b"hello"
    assert ask(b"carrying BLOCKME") == b""


def test_an_http_filter_reads_requests_and_carries_what_is_not_http(simulator):
    ask = simulator(HTTP)
    clean = b"GET /fine HTTP/1.1\r\nHost: x\r\n\r\n"
    assert ask(clean) == clean
    assert ask(b"GET /BLOCKME HTTP/1.1\r\nHost: x\r\n\r\n") == b""
    # Not a refusal: `invalid_encoding_action` is ACCEPT unless the file says otherwise.
    garbage = b"\x16\x03\x01 not a request\r\n\r\n"
    assert ask(garbage) == garbage
