"""The two zstd backends have to answer the same thing, on the same bytes.

`compression.zstd` is Python 3.14 and later; `zstandard` fills the gap below it. They are
not interchangeable by import alone — `zstandard.decompress()` refuses a frame whose
header carries no content size, which is exactly what a server produces when it
compresses a response body on the fly — so the shim normalises them. A filter that reads
a body on one Python and gets nothing on another is the same class of lie as a tester
that disagrees with the engine, which is why this is pinned rather than assumed.

Both backends are exercised in one run wherever `zstandard` is installed: the fallback is
loaded a second time with `compression` hidden, so the agreement is checked rather than
inferred from whichever Python happens to be running the suite.
"""

import builtins
import importlib.util
import io
import os

import pytest

zstandard = pytest.importorskip("zstandard")

SHIM = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "fgex-lib",
    "firegex", "pyfilters", "internals", "zstd_compat.py"))


def _load(hide_stdlib: bool):
    """Load the shim, optionally with `compression` unavailable."""
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if hide_stdlib and name.startswith("compression"):
            raise ImportError("hidden for this test")
        return real_import(name, *args, **kwargs)

    spec = importlib.util.spec_from_file_location("zstd_compat_probe", SHIM)
    module = importlib.util.module_from_spec(spec)
    builtins.__import__ = blocked
    try:
        spec.loader.exec_module(module)
    finally:
        builtins.__import__ = real_import
    return module


def _corpus():
    """The shapes an HTTP body actually arrives in."""
    compressor = zstandard.ZstdCompressor()
    for name, data in (("small", b"hello"),
                       ("empty", b""),
                       ("large", bytes(range(256)) * 400)):
        # A body whose length was known before compressing.
        yield f"{name}, content size in the header", compressor.compress(data), data
        # And one compressed on the fly, which carries no length at all. This is the
        # case a bare `zstandard.decompress()` refuses.
        buf = io.BytesIO()
        with compressor.stream_writer(buf, closefd=False) as writer:
            writer.write(data)
        yield f"{name}, streamed", buf.getvalue(), data
    # An encoder that flushed mid-response produces a concatenation of frames, and the
    # standard library reads it as one body.
    yield ("two frames concatenated",
           compressor.compress(b"first") + compressor.compress(b"second"),
           b"firstsecond")


BACKENDS = [
    pytest.param(False, id="whatever-this-python-has"),
    pytest.param(True, id="zstandard-fallback"),
]


@pytest.mark.parametrize("hide_stdlib", BACKENDS)
@pytest.mark.parametrize("label,blob,expected",
                         [pytest.param(n, b, e, id=n) for n, b, e in _corpus()])
def test_both_backends_decompress_the_same_bytes(hide_stdlib, label, blob, expected):
    assert _load(hide_stdlib).decompress(blob) == expected


def test_the_fallback_is_reachable_at_all():
    """Guards the test above from passing vacuously.

    If hiding `compression` did not actually select the other backend, every case would
    be checking one implementation twice and the disagreement this exists to catch would
    sail straight through.
    """
    fallback = _load(hide_stdlib=True)
    # The stdlib path is a module-level `from compression.zstd import decompress`, so its
    # function belongs to the standard library; the fallback's is a plain `def` in the
    # shim itself. That is what tells the two apart.
    assert fallback._decompress.__module__ == "zstd_compat_probe", \
        "hiding `compression` did not select the zstandard fallback"
