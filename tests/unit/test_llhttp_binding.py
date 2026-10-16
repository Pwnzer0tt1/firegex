"""The HTTP parser binding stands on its own.

`firegex._llhttp` is a fork of `pyllhttp`, and for a while it was still *calling* it: the
error path imported the module `pyllhttp` to fetch the exception class to raise. That
package is archived, is not a dependency, and is installed on no machine the wheel is
installed on — so the import failed, its traceback went to stderr (which on a filter is
the service log), and the function returned without setting an exception. CPython reports
that to the caller as `SystemError: ... returned NULL without setting an exception`, and
a malformed request — the traffic this parser exists to look at — said exactly that
instead of naming the problem.

It went unnoticed because a machine that once installed `pyllhttp` has it, and both the
laptop and the VM these tests were written on did. So the cases below take it away first.
"""

import sys

import pytest


class _Blocked:
    """A meta-path finder that makes one module unimportable, as if it were not there."""

    def __init__(self, name: str):
        self.name = name

    def find_spec(self, name, path=None, target=None):
        if name == self.name:
            raise ImportError(f"No module named {self.name}")
        return None


@pytest.fixture
def without_pyllhttp():
    """The state every machine that installs the wheel is in."""
    blocker = _Blocked("pyllhttp")
    sys.meta_path.insert(0, blocker)
    saved = sys.modules.pop("pyllhttp", None)
    try:
        yield
    finally:
        sys.meta_path.remove(blocker)
        if saved is not None:
            sys.modules["pyllhttp"] = saved


def test_the_parser_names_itself():
    """The types and the exceptions belong to this module, under this module's name."""
    from firegex import _llhttp

    assert _llhttp.Request.__module__ == "firegex._llhttp"
    assert _llhttp.Response.__module__ == "firegex._llhttp"
    assert _llhttp.Error.__module__ == "firegex._llhttp"


def test_a_parse_error_raises_this_modules_exception(without_pyllhttp):
    """…and raises it with nothing else installed to borrow it from."""
    from firegex import _llhttp

    parser = _llhttp.Request()
    with pytest.raises(_llhttp.InvalidMethodError) as raised:
        parser.execute(b"NOTAMETHOD / HTTP/1.1\r\n\r\n")

    assert isinstance(raised.value, _llhttp.Error)
    assert type(raised.value).__module__ == "firegex._llhttp"
    # The message is llhttp's own reason, not the shape of the failure to find a class.
    assert "method" in str(raised.value).lower()


def test_every_error_code_has_a_class_to_raise(without_pyllhttp):
    """A code with no class would be the silent half of the old bug coming back.

    `RuntimeError` is the floor here, deliberately: whatever goes wrong looking the class
    up, something is raised, because returning without an exception set is what produced
    a `SystemError` naming a package the operator has never heard of.
    """
    from firegex import _llhttp

    # One representative per kind of thing that can go wrong mid-message.
    cases = [
        (b"NOTAMETHOD / HTTP/1.1\r\n\r\n", "request"),
        (b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \r\n\r\n", "request"),
        (b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n", "response"),
    ]
    for payload, kind in cases:
        parser = _llhttp.Request() if kind == "request" else _llhttp.Response()
        with pytest.raises(_llhttp.Error):
            parser.execute(payload)


def test_a_valid_exchange_is_unaffected(without_pyllhttp):
    from firegex import _llhttp

    response = _llhttp.Response()
    response.execute(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    assert response.status_code == 404


# --- naming the method --------------------------------------------------------
# The name used to be read out of an array built from `HTTP_METHOD_MAP` and indexed with
# the method's number. That map is not the numbers in order — it runs 0 to 33 and jumps to
# QUERY at 46, with PRI and the RTSP methods not in it at all — so a request parser handed
# any of those read past the end of the array: QUERY and PLAY came back named after
# whatever lay beyond it, and FLUSH crashed the process. A client decides which method it
# sends, so each case runs in a process of its own: a crash has to fail one test, not end
# the run.

_METHOD_OF = """
import sys
from firegex import _llhttp

class Parser(_llhttp.Request):
    def on_headers_complete(self):
        print(self.method, flush=True)

Parser().execute(sys.argv[1].encode())
"""


@pytest.mark.parametrize("method, line", [
    ("GET", "GET / HTTP/1.1"),
    ("QUERY", "QUERY / HTTP/1.1"),
    ("PLAY", "PLAY rtsp://example/ RTSP/1.0"),
    ("FLUSH", "FLUSH rtsp://example/ RTSP/1.0"),
    ("DESCRIBE", "DESCRIBE rtsp://example/ RTSP/1.0"),
])
def test_every_method_the_parser_accepts_is_named(method, line):
    import subprocess

    ran = subprocess.run(
        [sys.executable, "-c", _METHOD_OF, f"{line}\r\nHost: a\r\nCSeq: 1\r\n\r\n"],
        capture_output=True, text=True, timeout=30,
    )
    assert ran.returncode == 0, f"parsing {line!r} ended the process: {ran.stderr[-300:]}"
    assert ran.stdout.strip() == method
