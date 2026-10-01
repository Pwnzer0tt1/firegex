"""Reading the interface the engine writes its reconstructions to.

`firegex0` carries what the filters saw, framed as the TCP streams the traffic either was
(TLS over TCP) or would have been (a QUIC stream, an HTTP/3 exchange). The framing is
invented — that is said everywhere this is offered — so the one thing worth testing about
it is whether a tool pointed at the interface can take it apart again, which is precisely
what the invention is for.

`tcpdump` writes the pcap and this reads it. No scapy: the suite's dependencies are pure
python on purpose, the format is four headers deep, and a parser small enough to read is
a better neighbour than a dependency that has to be installed on a competition laptop.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

import pytest

DEVICE = "firegex0"

#: Long enough for the engine to have written what the client already received: the send
#: is best-effort and non-blocking, so it can trail the traffic slightly.
DRAIN = 1.0

needs_capture = pytest.mark.skipif(
    not (shutil.which("tcpdump") and os.path.isdir(f"/sys/class/net/{DEVICE}")),
    reason=f"no tcpdump, or no {DEVICE} on this host",
)


@dataclass
class Segment:
    """One reconstructed TCP segment, in the terms the assertions are written in."""
    src_port: int
    dst_port: int
    syn: bool
    fin: bool
    payload: bytes


@dataclass
class Capture:
    segments: list = field(default_factory=list)

    def carrying(self, needle: bytes) -> list:
        return [s for s in self.segments if needle in s.payload]

    def conversations(self, needle: bytes) -> set:
        """Which reconstructed streams carried these bytes.

        A stream is named by its client port, which on a multiplexed connection is the
        only thing that tells two of them apart — and is synthetic for exactly that
        reason.
        """
        return {s.src_port for s in self.carrying(needle)}

    def opened(self, port: int) -> bool:
        return any(s.syn and s.src_port == port for s in self.segments)


@contextmanager
def watching(device: str = DEVICE):
    """Run `tcpdump` over the body, and hand back what it recorded."""
    recorded = Capture()
    handle, path = tempfile.mkstemp(suffix=".pcap")
    os.close(handle)
    # `-U` so each packet is written as it arrives rather than at the end of a buffer,
    # which matters because this is stopped by a signal.
    dump = subprocess.Popen(
        ["tcpdump", "-i", device, "-s", "0", "-U", "-w", path, "-n"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    # tcpdump says when it is listening, and starting the traffic before it does is how
    # a test loses the first exchange and then passes or fails by the clock.
    deadline = time.time() + 10
    while time.time() < deadline:
        line = dump.stderr.readline()
        if b"listening on" in line:
            break
        if dump.poll() is not None:
            pytest.skip(f"tcpdump would not start: {line.decode(errors='replace').strip()}")
    try:
        yield recorded
    finally:
        time.sleep(DRAIN)
        dump.terminate()
        dump.wait(timeout=10)
        recorded.segments.extend(read_pcap(path))
        try:
            os.remove(path)
        except OSError:
            pass


def read_pcap(path: str) -> list:
    """Every TCP segment in the file, with the headers peeled off."""
    with open(path, "rb") as handle:
        raw = handle.read()
    if len(raw) < 24:
        return []
    magic = raw[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        return []

    segments = []
    offset = 24
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from(f"{endian}IIII", raw, offset)
        offset += 16
        frame = raw[offset:offset + captured]
        offset += captured
        segment = _tcp_of(frame)
        if segment is not None:
            segments.append(segment)
    return segments


def _tcp_of(frame: bytes):
    """Ethernet → IP → TCP, or `None` for anything else on the interface."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    if ethertype == 0x0800:
        if len(frame) < 34:
            return None
        ihl = (frame[14] & 0x0F) * 4
        if frame[23] != 6:  # not TCP
            return None
        start = 14 + ihl
    elif ethertype == 0x86DD:
        if len(frame) < 54 or frame[20] != 6:
            return None
        start = 54
    else:
        return None

    if len(frame) < start + 20:
        return None
    src_port, dst_port = struct.unpack_from(">HH", frame, start)
    data_offset = (frame[start + 12] >> 4) * 4
    flags = frame[start + 13]
    return Segment(
        src_port=src_port,
        dst_port=dst_port,
        syn=bool(flags & 0x02),
        fin=bool(flags & 0x01),
        payload=frame[start + data_offset:],
    )
