"""The interface the engine writes decrypted traffic to.

TLS is terminated inside the engine, which is what lets a protected service occupy no
port beyond the one it already answered on — and it means the plaintext is never a packet
on any interface, so there would be nothing for a capture tool to read. The engine writes
it out itself (`proxysrc/src/capture.rs`), framed as the TCP stream it was before
encryption, onto the device this module puts there.

All that is needed here is the device: a `dummy` interface, which is a sink that carries
whatever is sent to it and goes nowhere. One for the whole instance, so every TLS
service's plaintext arrives on the same interface and a single capture covers the lot.

It exists for as long as firegex does, put there by `FirewallManager.init` and taken
away by `close`. It used to come and go with the TLS services themselves, on the argument
that an interface present while nothing is decrypting is one somebody points a capture at
and watches stay empty. Watching it stay empty turned out to be the better failure: a
capture tool is attached once, at the start of a round, and an interface that disappears
underneath it takes the tool with it — Zeek and Suricata exit rather than wait, and the
restart of a single TLS service was enough to do it. So the device now outlives any one
service, and the thing an operator points at in the morning is still there in the
afternoon.
"""

import subprocess

#: What an operator types into a capture tool. Fixed, and the same name the engine uses.
DEVICE = "firegex0"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True)


def present() -> bool:
    return _run("ip", "link", "show", DEVICE).returncode == 0


def ensure() -> bool:
    """Put the device there, if it is not already. Returns whether it is now.

    A failure is not an error anybody hears about: a capture aid that could stop a
    service from starting would be worse than no capture aid. The engine finds no
    interface, writes nothing, and the traffic is filtered and forwarded exactly as it
    would have been.
    """
    if present():
        return True
    if _run("ip", "link", "add", DEVICE, "type", "dummy").returncode != 0:
        return False
    return _run("ip", "link", "set", DEVICE, "up").returncode == 0


def release() -> None:
    """Take it away again, at shutdown and nowhere else."""
    _run("ip", "link", "del", DEVICE)
