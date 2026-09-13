"""Access control in front of the API, and the switch that hands it to a reverse proxy.

`IPFilterMiddleware` (`backend/app.py`) restricts by CIDR, configured through `run.py`'s
`--allowed-ips` / `--proxy-ip-header`. It **fails closed**: a missing, unparseable or
non-matching address is denied, because the alternative is a garbage header value that
opens the allowlist to anyone able to reach the port.

`--unsafe-disable-auth` hands access control over entirely. The password endpoints answer
403 in that mode on purpose — otherwise an anonymous caller could plant a credential that
starts working the moment authentication is turned back on.

Each of these is read once at process startup, which is why this module restarts firegex
rather than asking it to change its mind.
"""

import importlib.util
import os
import socket
import tempfile

import pytest
import requests
import socketio

from standalone.conftest import BASE, PASSWORD, REPO_ROOT

pytestmark = pytest.mark.instance

# The middleware matches on the raw TCP peer address. That is 127.0.0.1 only when firegex
# shares the host's network namespace (standalone mode); behind a published docker port
# the peer is the bridge gateway instead — 172.17.0.1, 192.168.x.1, whatever the daemon
# picked. So "an allowlist that covers the client" has to name loopback *and* the private
# ranges a docker bridge can live in. That keeps the pair meaningful: the denying case
# uses 203.0.113.0/24 (TEST-NET-3, reserved for documentation), which no real peer can
# ever fall into.
CLIENT_NETWORKS = "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
#: An address in that reserved range, for the cases that trust a header instead.
DOCUMENTED = "203.0.113.55"


def socketio_accepted(token=None) -> bool:
    """Whether a socket.io client gets past the `connect` handler.

    A raw websocket upgrade only covers the HTTP handshake, which happens *before* that
    handler runs — so it cannot tell an accepted connection from a rejected one.
    """
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


def websocket_upgrade_rejected(timeout: float = 5):
    """Did the server complete a websocket upgrade, or refuse it?

    `True` for refused, `False` for accepted, `None` if nothing came back at all.
    """
    request = "\r\n".join([
        "GET /sock/socket.io/?EIO=4&transport=websocket HTTP/1.1",
        "Host: 127.0.0.1:4444",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
    ]) + "\r\n\r\n"
    try:
        with socket.create_connection(("127.0.0.1", 4444), timeout=timeout) as sock:
            sock.sendall(request.encode())
            answer = sock.recv(4096)
    except (ConnectionResetError, OSError):
        return True
    if not answer:
        return True
    return b"101" not in answer.split(b"\r\n", 1)[0]


# --- the allowlist --------------------------------------------------------------------


def test_no_allowlist_configured_leaves_access_unrestricted(restart):
    """The backward-compatible default: an operator who configured nothing is not locked
    out of their own firewall."""
    restart(allowed_ips="")
    assert requests.get(BASE + "api/status").status_code == 200


def test_an_allowlist_that_excludes_the_client_refuses_it(restart):
    restart(allowed_ips="203.0.113.0/24")
    assert requests.get(BASE + "api/status").status_code == 403
    assert websocket_upgrade_rejected() is True, \
        "the websocket upgrade was not refused alongside the API"


def test_an_allowlist_that_covers_the_client_lets_it_in(restart):
    restart(allowed_ips=CLIENT_NETWORKS)
    assert requests.get(BASE + "api/status").status_code == 200


# --- the trusted header ---------------------------------------------------------------
# This variant trusts a client-supplied value, so it only holds if the proxy in front
# overwrites it. That is the deployment's job, and it is worth saying out loud.


def test_the_header_is_trusted_over_the_raw_peer(restart):
    restart(allowed_ips=f"{DOCUMENTED}/32", proxy_ip_header="X-Forwarded-For")
    assert requests.get(BASE + "api/status",
                        headers={"X-Forwarded-For": DOCUMENTED}).status_code == 200
    assert requests.get(BASE + "api/status",
                        headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 403


def test_an_absent_header_falls_back_to_the_raw_peer(restart):
    restart(allowed_ips=f"{DOCUMENTED}/32", proxy_ip_header="X-Forwarded-For")
    assert requests.get(BASE + "api/status").status_code == 403, \
        "a request with no header at all was let in"


def test_a_malformed_header_value_fails_closed(restart):
    """Otherwise a client that can reach the port directly bypasses the allowlist
    entirely by sending garbage."""
    restart(allowed_ips=f"{DOCUMENTED}/32", proxy_ip_header="X-Forwarded-For")
    assert requests.get(BASE + "api/status",
                        headers={"X-Forwarded-For": "not-an-ip"}).status_code == 403


# --- handing access control to a reverse proxy ----------------------------------------


def test_authentication_on_is_asked_for_by_the_api_and_by_socket_io(restart):
    restart(allowed_ips="", unsafe_disable_auth=False)
    status = requests.get(BASE + "api/status")
    assert status.status_code == 200
    assert status.json()["loggined"] is False
    assert status.json()["auth_disabled"] is False
    assert requests.get(BASE + "api/interfaces").status_code == 401
    assert socketio_accepted("") is False


def test_disabling_authentication_opens_the_api_and_says_so(restart):
    """No IP allowlist here on purpose: whether the container sees the test client as
    127.0.0.1 depends on how docker published the port, which is the allowlist tests'
    business rather than this one's."""
    restart(allowed_ips="", unsafe_disable_auth=True)
    status = requests.get(BASE + "api/status")
    assert status.status_code == 200
    assert status.json()["status"] == "run"
    assert status.json()["loggined"] is True
    assert status.json()["auth_disabled"] is True, \
        "the frontend is not told it is running without authentication"
    assert requests.get(BASE + "api/interfaces").status_code == 200
    assert socketio_accepted("") is True
    assert socketio_accepted(None) is True


@pytest.mark.parametrize("endpoint,body", [
    ("api/change-password", {"password": "plantedbyanyone", "expire": False}),
    ("api/set-password", {"password": "plantedbyanyone"}),
])
def test_the_password_endpoints_stay_shut_while_authentication_is_off(restart, endpoint,
                                                                      body):
    """An anonymous caller could otherwise plant a credential that keeps working once
    `--no-unsafe-disable-auth` is passed."""
    restart(allowed_ips="", unsafe_disable_auth=True)
    assert requests.post(BASE + endpoint, json=body).status_code == 403


def test_login_is_refused_while_authentication_is_off(restart):
    """There is no session to hand out, and nothing new is signed while it is off — which
    is exactly what makes an older token proof of having been an administrator before."""
    restart(allowed_ips="", unsafe_disable_auth=True)
    assert requests.post(BASE + "api/login",
                         data={"username": "x", "password": PASSWORD}).status_code == 403


def test_turning_authentication_back_on_restores_the_real_password(restart):
    restart(allowed_ips="", unsafe_disable_auth=True)
    requests.post(BASE + "api/change-password",
                  json={"password": "plantedbyanyone", "expire": False})

    restart(allowed_ips="", unsafe_disable_auth=False)
    assert requests.get(BASE + "api/interfaces").status_code == 401

    logged_in = requests.post(BASE + "api/login",
                              data={"username": "x", "password": PASSWORD})
    assert logged_in.status_code == 200, logged_in.text
    assert socketio_accepted(logged_in.json()["access_token"]) is True
    assert requests.post(BASE + "api/login",
                         data={"username": "x", "password": "plantedbyanyone"}
                         ).status_code == 406, \
        "a password planted while authentication was off became a real one"


def test_run_py_keeps_an_explicit_password_when_authentication_is_disabled():
    """Otherwise re-enabling authentication later leaves the instance in its
    initial-setup state, where anyone able to reach it chooses the password.

    `get_password()` is pure argument handling, so it is checked directly against a
    throwaway config file — reproducing it against the live instance would mean wiping
    its database.
    """
    spec = importlib.util.spec_from_file_location(
        "firegex_run", os.path.join(REPO_ROOT, "run.py"))
    run_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run_module)

    globs = run_module.get_password.__globals__
    globs["volume_exists"] = lambda: False  # pretend this is a first start
    with tempfile.TemporaryDirectory() as tmp:
        run_module.g.configfile = os.path.join(tmp, "conf.json")
        for extra in ([], ["--unsafe-disable-auth"]):
            globs["args"] = run_module.gen_args(["start", "-P", PASSWORD, *extra])
            assert run_module.get_password() == PASSWORD, \
                f"an explicit -P was dropped with {extra or 'no extra flag'}"
