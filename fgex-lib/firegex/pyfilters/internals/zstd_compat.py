"""One `zstd.decompress`, whichever Python is underneath.

`compression.zstd` arrived in the standard library in Python 3.14. The library imported
it directly, while `setup.py` promised 3.10 — so on everything from 3.10 to 3.13 the
package installed cleanly and then raised `ModuleNotFoundError: No module named
'compression'` on the first import of an HTTP model. That was the whole of what stopped
it running on Python 3.12, which is what Ubuntu 24.04 LTS ships.

The `zstandard` package fills the gap, and the shim is not a one-line alias because the
two do **not** answer the same question. `zstandard.decompress()` refuses a frame whose
header carries no content size — which is exactly the shape a server produces when it
compresses a response body on the fly, the common case here — while the standard
library's handles it. A filter that reads a body on 3.14 and gets nothing on 3.12 is the
same class of lie as a tester that disagrees with the engine, so this normalises to the
more capable behaviour rather than to whichever backend is present.
"""

import io

try:  # Python 3.14 and later
    from compression.zstd import ZstdFile as _ZstdFile
    from compression.zstd import decompress as _decompress

    def _read(data: bytes, size: int) -> bytes:
        with _ZstdFile(io.BytesIO(data)) as f:
            return f.read(size)

except ImportError:  # Python 3.10 - 3.13
    import zstandard

    def _reader(data: bytes):
        """Every frame in `data`, streamed.

        `stream_reader` rather than `ZstdDecompressor.decompress`: the latter needs the
        content size in the frame header and raises without it. `read_across_frames`
        matches the standard library, which decompresses a concatenation of frames as
        one body — an encoder that flushed mid-response produces exactly that.
        """
        return zstandard.ZstdDecompressor().stream_reader(
            io.BytesIO(data), read_across_frames=True
        )

    def _decompress(data: bytes) -> bytes:
        return _reader(data).read()

    def _read(data: bytes, size: int) -> bytes:
        reader = _reader(data)
        out = bytearray()
        while len(out) < size:
            piece = reader.read(size - len(out))
            if not piece:
                break
            out += piece
        return bytes(out)


def decompress(data: bytes, max_length: int | None = None) -> bytes:
    """`data` decompressed, or its first `max_length` bytes when that is given.

    Bounded by reading rather than by decompressing and measuring: a frame a few hundred
    bytes long can declare gigabytes, and what arrives in an HTTP body is whatever the
    other end chose to send.
    """
    if max_length is None:
        return _decompress(data)
    return _read(data, max_length)
