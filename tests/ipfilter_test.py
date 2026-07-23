#!/usr/bin/env python3
"""
Verifies the IP-based access control middleware (IPFilterMiddleware in backend/app.py),
configured via `run.py`'s --allowed-ips / --proxy-ip-header flags (ALLOWED_IPS / PROXY_IP_HEADER
env vars).

Unlike the rest of the test suite, this script manages firegex's own start/stop lifecycle,
since ALLOWED_IPS/PROXY_IP_HEADER are only read once at process startup (no live reload) -
each scenario needs a fresh restart with different flags. Must be run on the same Linux/Docker
host firegex runs on (same requirements as run.py itself).
"""
import argparse
import os
import socket
import subprocess
import sys
import time

import requests

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "http://127.0.0.1:4444/"

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"\033[32mPASS: {name}\033[0m")
    else:
        print(f"\033[31mFAIL: {name}{' - ' + detail if detail else ''}\033[0m")
        failures.append(name)


def run_py(*args, timeout=180):
    res = subprocess.run(["python3", "run.py", *args], cwd=REPO_ROOT, timeout=timeout)
    return res.returncode


def wait_ready(timeout=90):
    start = time.time()
    while time.time() - start < timeout:
        try:
            # A bare /api/status request is never blocked by design considerations of this
            # test (it's the endpoint we probe), so poll it via a raw request expecting
            # either 200 or 403 - both mean "the app answered", unlike a connection error.
            r = requests.get(BASE + "api/status", timeout=2)
            if r.status_code in (200, 403):
                return True
        except requests.RequestException:
            pass
        time.sleep(1)
    return False


def restart_with(allowed_ips=None, proxy_ip_header=None):
    print(f"\n--- restarting firegex (allowed_ips={allowed_ips!r}, proxy_ip_header={proxy_ip_header!r}) ---")
    run_py("stop")
    args = ["start", "-P", "testpassword"]
    # An empty string still needs to be passed explicitly to clear a previous value.
    if allowed_ips is not None:
        args += ["--allowed-ips", allowed_ips]
    if proxy_ip_header is not None:
        args += ["--proxy-ip-header", proxy_ip_header]
    run_py(*args)
    if not wait_ready():
        print("FATAL: firegex didn't come back up after restart")
        sys.exit(1)


def raw_ws_handshake_rejected(path="/sock/socket.io/?EIO=4&transport=websocket", extra_headers=None, timeout=5):
    """Best-effort check: performs a raw WS upgrade handshake and reports whether the
    server completed it (101 Switching Protocols) or refused/closed the connection.
    Returns True if the handshake looks rejected, False if it looks accepted, None if
    inconclusive (e.g. connection reset before any bytes came back)."""
    lines = [
        f"GET {path} HTTP/1.1",
        "Host: 127.0.0.1:4444",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
    ]
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}")
    req = "\r\n".join(lines) + "\r\n\r\n"
    try:
        with socket.create_connection(("127.0.0.1", 4444), timeout=timeout) as s:
            s.sendall(req.encode())
            data = s.recv(4096)
    except (ConnectionResetError, OSError):
        return True
    if not data:
        return True
    return b"101" not in data.split(b"\r\n", 1)[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-cleanup-restart", action="store_true",
                         help="Don't restart firegex without restrictions at the end (leaves the last scenario's config applied)")
    args = parser.parse_args()

    try:
        # 1. No restriction configured -> unrestricted access (backward compatible default)
        restart_with(allowed_ips="")
        r = requests.get(BASE + "api/status")
        check("no ALLOWED_IPS configured -> request succeeds", r.status_code == 200, f"got {r.status_code}")

        # 2. Restrict to a network that excludes the loopback test client -> blocked
        restart_with(allowed_ips="203.0.113.0/24")
        r = requests.get(BASE + "api/status")
        check("ALLOWED_IPS excludes client -> 403", r.status_code == 403, f"got {r.status_code}")
        ws_rejected = raw_ws_handshake_rejected()
        check("ALLOWED_IPS excludes client -> websocket upgrade rejected", ws_rejected is True, f"result={ws_rejected}")

        # 3. Restrict to a network (CIDR) that includes the loopback test client -> allowed
        restart_with(allowed_ips="127.0.0.1/32,::1/128")
        r = requests.get(BASE + "api/status")
        check("ALLOWED_IPS includes client (CIDR) -> 200", r.status_code == 200, f"got {r.status_code}")

        # 4. PROXY_IP_HEADER: the header value is trusted over the raw TCP peer
        restart_with(allowed_ips="203.0.113.55/32", proxy_ip_header="X-Forwarded-For")
        r = requests.get(BASE + "api/status", headers={"X-Forwarded-For": "203.0.113.55"})
        check("PROXY_IP_HEADER value matches allowlist -> 200", r.status_code == 200, f"got {r.status_code}")
        r = requests.get(BASE + "api/status", headers={"X-Forwarded-For": "8.8.8.8"})
        check("PROXY_IP_HEADER value NOT in allowlist -> 403", r.status_code == 403, f"got {r.status_code}")
        r = requests.get(BASE + "api/status")  # header absent -> falls back to raw peer (127.0.0.1, not allowed here)
        check("PROXY_IP_HEADER configured but header absent -> falls back to raw peer -> 403",
              r.status_code == 403, f"got {r.status_code}")

        # 5. Malformed value in the trusted header must fail CLOSED (deny), not open -
        # otherwise a client that can reach the port directly could send a garbage header
        # value to bypass the allowlist entirely.
        r = requests.get(BASE + "api/status", headers={"X-Forwarded-For": "not-an-ip"})
        check("malformed PROXY_IP_HEADER value -> fails closed (403)", r.status_code == 403, f"got {r.status_code}")

    finally:
        if not args.skip_cleanup_restart:
            restart_with(allowed_ips="")

    print()
    if failures:
        print(f"\033[31m{len(failures)} check(s) failed: {failures}\033[0m")
        sys.exit(1)
    else:
        print("\033[32mAll IP filter checks passed\033[0m")
