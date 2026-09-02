#!/usr/bin/env python3
"""
Verifies the access control sitting in front of the API: the IP-based middleware
(IPFilterMiddleware in backend/app.py), configured via `run.py`'s --allowed-ips /
--proxy-ip-header flags (ALLOWED_IPS / PROXY_IP_HEADER env vars), and the --unsafe-disable-auth
flag (UNSAFE_DISABLE_AUTH) that hands access control over to a reverse proxy.

Unlike the rest of the test suite, this script manages firegex's own start/stop lifecycle,
since ALLOWED_IPS/PROXY_IP_HEADER are only read once at process startup (no live reload) -
each scenario needs a fresh restart with different flags. Must be run on the same Linux/Docker
host firegex runs on (same requirements as run.py itself).
"""
import argparse
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import time

import requests
import socketio

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


def restart_with(allowed_ips=None, proxy_ip_header=None, unsafe_disable_auth=None):
    print(f"\n--- restarting firegex (allowed_ips={allowed_ips!r}, proxy_ip_header={proxy_ip_header!r}, unsafe_disable_auth={unsafe_disable_auth!r}) ---")
    run_py("stop")
    args = ["start", "-P", "testpassword"]
    # An empty string still needs to be passed explicitly to clear a previous value.
    if allowed_ips is not None:
        args += ["--allowed-ips", allowed_ips]
    if proxy_ip_header is not None:
        args += ["--proxy-ip-header", proxy_ip_header]
    if unsafe_disable_auth is not None:
        args += ["--unsafe-disable-auth" if unsafe_disable_auth else "--no-unsafe-disable-auth"]
    run_py(*args)
    if not wait_ready():
        print("FATAL: firegex didn't come back up after restart")
        sys.exit(1)


def sio_connect_accepted(token=None):
    """Whether a socket.io client gets past the `connect` auth handler. The raw handshake
    check below only covers the HTTP upgrade, which happens before that handler runs, so
    it cannot tell an accepted connection from a rejected one."""
    client = socketio.Client()
    try:
        client.connect(BASE.rstrip("/"), socketio_path="/sock/socket.io",
                       transports=["websocket"],
                       auth={"token": token} if token is not None else None,
                       wait_timeout=10)
    except socketio.exceptions.ConnectionError:
        return False
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
    return True


def check_startup_password_survives_disabled_auth():
    """--unsafe-disable-auth must not swallow an explicit -P, otherwise re-enabling authentication
    later leaves the instance in its initial-setup state, where anyone able to reach it
    chooses the password.

    get_password() is pure argument handling, so it is checked directly against a throwaway
    config file: reproducing it against the live instance would mean wiping its database."""
    spec = importlib.util.spec_from_file_location("firegex_run", os.path.join(REPO_ROOT, "run.py"))
    run_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run_module)
    globs = run_module.get_password.__globals__
    globs["volume_exists"] = lambda: False  # pretend this is a first start
    with tempfile.TemporaryDirectory() as tmp:
        run_module.g.configfile = os.path.join(tmp, "conf.json")
        for extra in ([], ["--unsafe-disable-auth"]):
            globs["args"] = run_module.gen_args(["start", "-P", "testpassword", *extra])
            got = run_module.get_password()
            check(f"first start with -P {' '.join(extra) or '(no extra flag)'} -> password is kept",
                  got == "testpassword", f"got {got!r}")


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

        # 6. Authentication on (the default): the API and socket.io both need a token.
        restart_with(allowed_ips="", unsafe_disable_auth=False)
        r = requests.get(BASE + "api/status")
        check("auth enabled -> not logged in without a token",
              r.status_code == 200 and r.json().get("loggined") is False and r.json().get("auth_disabled") is False,
              f"got {r.status_code}: {r.text}")
        r = requests.get(BASE + "api/interfaces")
        check("auth enabled -> protected API without a bearer token is refused", r.status_code == 401, f"got {r.status_code}")
        check("auth enabled -> socket.io without a token is refused", sio_connect_accepted("") is False)

        # 7. Built-in authentication can be disabled for a reverse proxy that owns
        # access control. Protected API routes, the status endpoint and socket.io then
        # work without a bearer token.
        # No IP allowlist here on purpose: whether the container sees the test client as
        # 127.0.0.1 depends on how docker publishes the port, and that is scenario 3's
        # business, not this one's.
        restart_with(allowed_ips="", unsafe_disable_auth=True)
        r = requests.get(BASE + "api/status")
        check("UNSAFE_DISABLE_AUTH reports a logged-in running app",
              r.status_code == 200 and r.json().get("status") == "run" and r.json().get("loggined") is True,
              f"got {r.status_code}: {r.text}")
        check("UNSAFE_DISABLE_AUTH is advertised to the frontend", r.json().get("auth_disabled") is True, f"got {r.text}")
        r = requests.get(BASE + "api/interfaces")
        check("UNSAFE_DISABLE_AUTH permits protected API without bearer token", r.status_code == 200, f"got {r.status_code}")
        check("UNSAFE_DISABLE_AUTH permits socket.io with an empty token", sio_connect_accepted("") is True)
        check("UNSAFE_DISABLE_AUTH permits socket.io with no auth payload at all", sio_connect_accepted(None) is True)

        # 8. The password endpoints must stay shut while authentication is disabled: an
        # anonymous caller could otherwise plant a credential that keeps working once
        # --no-unsafe-disable-auth is passed.
        r = requests.post(BASE + "api/change-password", json={"password": "plantedbyanyone", "expire": False})
        check("UNSAFE_DISABLE_AUTH -> unauthenticated change-password is refused", r.status_code == 403, f"got {r.status_code}: {r.text}")
        r = requests.post(BASE + "api/set-password", json={"password": "plantedbyanyone"})
        check("UNSAFE_DISABLE_AUTH -> unauthenticated set-password is refused", r.status_code == 403, f"got {r.status_code}: {r.text}")
        r = requests.post(BASE + "api/login", data={"username": "x", "password": "testpassword"})
        check("UNSAFE_DISABLE_AUTH -> login is refused (there is no session to hand out)", r.status_code == 403, f"got {r.status_code}: {r.text}")

        # 9. --no-unsafe-disable-auth puts authentication back in charge of the running instance.
        restart_with(allowed_ips="", unsafe_disable_auth=False)
        r = requests.get(BASE + "api/interfaces")
        check("--no-unsafe-disable-auth restores authentication on protected API", r.status_code == 401, f"got {r.status_code}")
        r = requests.post(BASE + "api/login", data={"username": "x", "password": "testpassword"})
        check("--no-unsafe-disable-auth -> the real password logs in again", r.status_code == 200, f"got {r.status_code}: {r.text}")
        check("--no-unsafe-disable-auth -> socket.io accepts the freshly issued token",
              sio_connect_accepted(r.json().get("access_token", "")) is True)
        check("plaintext planted while auth was disabled is not a valid password",
              requests.post(BASE + "api/login", data={"username": "x", "password": "plantedbyanyone"}).status_code == 406)

        # 10. run.py must not drop an explicit -P when authentication is disabled.
        check_startup_password_survives_disabled_auth()

    finally:
        if not args.skip_cleanup_restart:
            restart_with(allowed_ips="", unsafe_disable_auth=False)

    print()
    if failures:
        print(f"\033[31m{len(failures)} check(s) failed: {failures}\033[0m")
        sys.exit(1)
    else:
        print("\033[32mAll IP filter checks passed\033[0m")
