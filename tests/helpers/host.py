"""What the host firegex runs on says about it, read as root.

Reading a ruleset or naming the process behind a socket needs root, and the suite does
not: each command goes through `sudo -n` unless it already is root, so a developer with
passwordless sudo gets these checks and one without gets `None` — a skip — rather than a
failure about a permission the tests never asked anyone for.
"""

import os
import re
import subprocess


def as_root(*argv: str) -> str | None:
    """Run one command as root: its output, or `None` where that cannot be done here."""
    command = list(argv) if os.geteuid() == 0 else ["sudo", "-n", *argv]
    try:
        done = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError:
        return None
    return done.stdout if done.returncode == 0 else None


def ruleset() -> str | None:
    """The services module's table, or `None` where it cannot be read from here."""
    return as_root("nft", "list", "table", "inet", "fgex")


def engine_port(service_port: int, l4: str = "tcp") -> int | None:
    """Where the proxy layer's redirect sends a service's port: the engine's listener,
    or with `l4="udp"` the relay bound for that address.

    The engine picks ephemeral ports when it starts and tells only the backend, so the
    redirect is the one place outside those two that says which they are.
    """
    for line in (ruleset() or "").splitlines():
        # By protocol: a UDP address on the same port is redirected to its own relay.
        if re.search(rf"\b{l4} dport {service_port}\b", line):
            found = re.search(r"redirect to :(\d+)", line)
            if found:
                return int(found.group(1))
    return None


def listening_pid(port: int) -> int | None:
    """The process listening on a TCP port, as the host sees it."""
    found = re.search(r"pid=(\d+)", as_root("ss", "-Hltnp", f"sport = :{port}") or "")
    return int(found.group(1)) if found else None
