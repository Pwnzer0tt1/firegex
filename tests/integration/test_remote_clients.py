"""A client on another host.

Every other test here dials from the host firegex runs on, and a reply to such a client is
delivered locally whether or not the rules brought it home — so a return path that only
works for a client on this host passes all of them, and fails for every client a CTF
service actually has. Here the client is in a network namespace behind a veth pair: its
packets arrive on an interface, its address is none of this host's, and a reply that is
not brought home is routed out to it, past the engine waiting for it.
"""

import os
import socket
import subprocess
import threading
import time

import pytest

from integration.conftest import add_regex_filter, start_and_settle
from helpers.host import as_root
from helpers.net import free_port

pytestmark = [pytest.mark.instance, pytest.mark.root]

NETNS = "fgextest"
HOST_SIDE, CLIENT_SIDE = "fgxt0", "fgxt1"
HOST_IP, CLIENT_IP = "10.199.77.1", "10.199.77.2"


def _take_down() -> None:
    as_root("ip", "netns", "del", NETNS)
    as_root("ip", "link", "del", HOST_SIDE)


@pytest.fixture
def elsewhere(datapath_in_our_path):
    """Run a snippet of Python on a client that is not this host, and read what it printed."""
    if not datapath_in_our_path:
        pytest.skip("firegex's datapath is not in front of this host")
    _take_down()
    for step in (
        ("ip", "netns", "add", NETNS),
        ("ip", "link", "add", HOST_SIDE, "type", "veth", "peer", "name", CLIENT_SIDE),
        ("ip", "link", "set", CLIENT_SIDE, "netns", NETNS),
        ("ip", "addr", "add", f"{HOST_IP}/24", "dev", HOST_SIDE),
        ("ip", "link", "set", HOST_SIDE, "up"),
        ("ip", "netns", "exec", NETNS, "ip", "addr", "add", f"{CLIENT_IP}/24",
         "dev", CLIENT_SIDE),
        ("ip", "netns", "exec", NETNS, "ip", "link", "set", CLIENT_SIDE, "up"),
        ("ip", "netns", "exec", NETNS, "ip", "link", "set", "lo", "up"),
    ):
        if as_root(*step) is None:
            _take_down()
            pytest.skip("cannot stage a second host here: no root, or no network namespaces")

    def run(code: str) -> str:
        return (as_root("ip", "netns", "exec", NETNS, "python3", "-c", code) or "").strip()

    yield run
    _take_down()


SERVICE_NETNS = "fgextest-svc"
SERVICE_HOST_SIDE, SERVICE_SIDE = "fgxs0", "fgxs1"
CONTAINER_IP = "10.199.78.2"
CONTAINER_TABLE = "fgextest_dnat"

#: What the "container" runs: TCP and UDP on 8080, echoing — except `WHO`, answered with
#: the address the service saw, which is how transparency is asked about.
CONTAINER_SERVICE = r"""
import socket, threading
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8080)); s.listen(64)
    def serve(c, peer):
        with c:
            while True:
                d = c.recv(4096)
                if not d: return
                c.sendall(peer[0].encode() if d == b"WHO" else d)
    while True:
        c, peer = s.accept()
        threading.Thread(target=serve, args=(c, peer), daemon=True).start()
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 8080))
    while True:
        d, peer = s.recvfrom(4096)
        s.sendto(peer[0].encode() if d == b"WHO" else d, peer)
threading.Thread(target=udp, daemon=True).start()
tcp()
"""

#: Forwarding between the client's link and the container's, both ways. A host running
#: Docker drops forwarded traffic by policy, and this is how a runtime lets its own
#: published ports through it.
FORWARD_RULES = [("-i", HOST_SIDE, "-o", SERVICE_HOST_SIDE),
                 ("-i", SERVICE_HOST_SIDE, "-o", HOST_SIDE)]


def _root_command(*argv: str) -> list[str]:
    return list(argv) if os.geteuid() == 0 else ["sudo", "-n", *argv]


def _rewrites(published: int) -> list[tuple[str, ...]]:
    """Docker's own rule for a published port, in its own tool: `iptables` in `nat`."""
    return [("-t", "nat", chain, "-d", HOST_IP, "-p", proto, "--dport", str(published),
             "-j", "DNAT", "--to-destination", f"{CONTAINER_IP}:8080")
            for chain in ("PREROUTING", "OUTPUT") for proto in ("tcp", "udp")]


_staged: list[tuple[str, ...]] = []


def _undo_rewrites() -> None:
    while _staged:
        rule = _staged.pop()
        as_root("iptables", *rule[:2], "-D", *rule[2:])


def _take_container_down() -> None:
    as_root("pkill", "-f", "fgextest-container")
    as_root("nft", "delete", "table", "ip", CONTAINER_TABLE)
    _undo_rewrites()
    for rule in FORWARD_RULES:
        as_root("iptables", "-D", "FORWARD", *rule, "-j", "ACCEPT")
    as_root("ip", "netns", "del", SERVICE_NETNS)
    as_root("ip", "link", "del", SERVICE_HOST_SIDE)


@pytest.fixture
def container(elsewhere):
    """A service the way a container runtime publishes one, on the far side of a DNAT.

    The service lives in a namespace of its own, and a port of this host's is rewritten to
    it at `dstnat` in `nat PREROUTING` and `nat OUTPUT` — the priority, the hooks and the
    shape of Docker's own rule — without needing Docker. It is the deployment a CTF
    service almost always has, and the rewrite is what the rest of the suite never puts
    in the way: every other service here listens on this host, where a reply is local.
    """
    _take_container_down()
    for step in (
        ("ip", "netns", "add", SERVICE_NETNS),
        ("ip", "link", "add", SERVICE_HOST_SIDE, "type", "veth", "peer", "name", SERVICE_SIDE),
        ("ip", "link", "set", SERVICE_SIDE, "netns", SERVICE_NETNS),
        ("ip", "addr", "add", "10.199.78.1/24", "dev", SERVICE_HOST_SIDE),
        ("ip", "link", "set", SERVICE_HOST_SIDE, "up"),
        ("ip", "netns", "exec", SERVICE_NETNS, "ip", "addr", "add", f"{CONTAINER_IP}/24",
         "dev", SERVICE_SIDE),
        ("ip", "netns", "exec", SERVICE_NETNS, "ip", "link", "set", SERVICE_SIDE, "up"),
        ("ip", "netns", "exec", SERVICE_NETNS, "ip", "link", "set", "lo", "up"),
        ("ip", "netns", "exec", SERVICE_NETNS, "ip", "route", "add", "default",
         "via", "10.199.78.1"),
    ):
        if as_root(*step) is None:
            _take_container_down()
            pytest.skip("cannot stage a container's network here")
    # Best effort: without them the client elsewhere cannot reach the container even with
    # no firegex in the way, and the test says so rather than blaming firegex.
    for rule in FORWARD_RULES:
        as_root("iptables", "-I", "FORWARD", "1", *rule, "-j", "ACCEPT")

    published = free_port()
    # `iptables` first — it is what Docker writes with, and it is on every machine Docker
    # is; `nft` for a host with no iptables at all.
    for rule in _rewrites(published):
        if as_root("iptables", *rule[:2], "-A", *rule[2:]) is None:
            _undo_rewrites()
            break
        _staged.append(rule)
    ruleset = (
        f"table ip {CONTAINER_TABLE} {{\n"
        + "".join(
            f"  chain {hook} {{\n"
            f"    type nat hook {hook} priority dstnat; policy accept;\n"
            f"    ip daddr {HOST_IP} meta l4proto {{ tcp, udp }} th dport {published} "
            f"dnat to {CONTAINER_IP}:8080\n"
            f"  }}\n"
            for hook in ("prerouting", "output")
        )
        + "}\n"
    )
    if not _staged and subprocess.run(
            _root_command("nft", "-f", "-"), input=ruleset, text=True,
            capture_output=True).returncode != 0:
        _take_container_down()
        pytest.skip("cannot stage a container runtime's rewrite here: neither iptables "
                    "nor nft took it")

    serving = subprocess.Popen(
        _root_command("ip", "netns", "exec", SERVICE_NETNS, "python3", "-c",
                      "# fgextest-container\n" + CONTAINER_SERVICE),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    yield published
    serving.terminate()
    _take_container_down()


def _local(port: int, payload: str, udp: bool = False) -> str:
    """The same question as `_ask`, from this host."""
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as s:
        s.settimeout(4)
        try:
            if udp:
                s.sendto(payload.encode(), (HOST_IP, port))
                return repr(s.recvfrom(64)[0])
            s.connect((HOST_IP, port))
            s.sendall(payload.encode())
            return repr(s.recv(64))
        except OSError as e:
            return type(e).__name__


@pytest.mark.parametrize("udp", [False, True], ids=["tcp", "udp"])
@pytest.mark.parametrize("transport", ["proxy", "nfqueue"])
def test_a_service_behind_a_container_runtimes_rewrite_is_protected_from_anywhere(
        api, service, elsewhere, container, transport, udp):
    """Answered, filtered and transparent, from another host and from this one.

    Two ways this failed, one per layer, and neither was visible from this host alone.

    **Proxy, a client elsewhere:** the engine dials the published address as the client,
    the runtime's DNAT sends it on to the container, and the container answers from its
    own address. The rule that brings the engine's answers home looked the socket up by
    that address, found none, and the answer went on to the real client, which reset it:
    every connection waited out the dial and was retried as this host — slowly, and with
    the client's address lost.

    **NFQUEUE, a client on this host:** the runtime rewrites this host's own connection in
    `nat OUTPUT`, so it leaves towards the container without passing prerouting, where the
    queues are, and the container's answer arrives for a local socket without passing
    postrouting. Neither half was inspected, and a payload refused from anywhere else
    reached the service from here.
    """
    clients = {
        "another host": (lambda payload: elsewhere(_ask(container, udp, payload)), CLIENT_IP),
        "this host": (lambda payload: _local(container, payload, udp), HOST_IP),
    }
    # Each path has to work with nothing of firegex in it before firegex can be judged on
    # it: a host that does not forward to the container's network is not a firegex bug.
    for where, (ask, _) in clients.items():
        if ask("hello") != "b'hello'":
            pytest.skip(f"the stand-in container is not reachable from {where} even "
                        f"without firegex: this host does not forward to it")

    service_id = service(f"container-{transport}-{container}", HOST_IP, container, transport,
                         proto="udp" if udp else "tcp")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id, wait=1.5)

    # A datagram refused is one that is not answered; a connection refused is closed.
    refused = ("TimeoutError",) if udp else ("b''", "ConnectionResetError", "TimeoutError")
    for where, (ask, client_ip) in clients.items():
        assert ask("hello") == "b'hello'", f"the service did not answer {where}"
        assert ask("WHO") == repr(client_ip.encode()), \
            f"the service did not see the address of a client on {where}"
        assert ask("x BLOCKME") in refused, f"a blocked payload from {where} reached the service"


def _echo_on(host: str, udp: bool) -> int:
    """A service answering with what it is sent, on this host's side of the link."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, 0))

    def serve():
        if udp:
            while True:
                data, peer = sock.recvfrom(2048)
                sock.sendto(data, peer)
        sock.listen(8)
        while True:
            conn, _ = sock.accept()
            with conn:
                conn.sendall(conn.recv(2048))

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def _ask(port: int, udp: bool, payload: str = "hello") -> str:
    kind = "SOCK_DGRAM" if udp else "SOCK_STREAM"
    exchange = (
        f"s.sendto({payload.encode()!r}, ('{HOST_IP}', {port})); print(s.recvfrom(64)[0])"
        if udp else
        f"s.connect(('{HOST_IP}', {port})); s.sendall({payload.encode()!r}); print(s.recv(64))"
    )
    return (
        "import socket\n"
        f"s = socket.socket(socket.AF_INET, socket.{kind}); s.settimeout(4)\n"
        f"try:\n    {exchange}\n"
        "except OSError as e:\n    print(type(e).__name__)\n"
    )


@pytest.mark.parametrize("udp", [False, True], ids=["tcp", "udp"])
def test_a_published_address_answers_a_client_on_another_host(api, service, elsewhere, udp):
    """Published: the engine dials the service on a port the address does not name.

    The rule that brings the service's answers home knew the service only by the address
    it is protected on, which is where the engine dials it while the address *is* the
    service. Published elsewhere, the answers came from a port nothing matched and were
    routed straight to the client — who was expecting them from the engine and dropped
    them. A client on this host never noticed, the reply being local either way.

    The service's own port is not protected here, which is the case that broke: protected
    too, its rule happened to cover the answers. And it keeps answering its own clients
    directly, which is what a fix matching every reply from that port would have broken.
    """
    served = _echo_on(HOST_IP, udp)
    extra = free_port(udp=udp)
    service_id = service(
        f"remote-pub-{served}", HOST_IP, extra, "proxy", proto="udp" if udp else "tcp",
        addresses=[{"ip_int": HOST_IP, "port": extra, "target_port": served}],
    )
    start_and_settle(api, service_id, wait=1.2)

    assert elsewhere(_ask(extra, udp)) == "b'hello'", \
        "a client on another host was not answered through the published address"
    assert elsewhere(_ask(served, udp)) == "b'hello'", \
        "the service stopped answering its own port directly"


def _echo_all_on(host: str, udp: bool) -> int:
    """`_echo_on`, answering every message of a connection rather than the first."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, 0))

    def answer(conn):
        with conn:
            try:
                while data := conn.recv(2048):
                    conn.sendall(data)
            except OSError:
                pass

    def serve():
        if udp:
            while True:
                data, peer = sock.recvfrom(2048)
                sock.sendto(data, peer)
        sock.listen(8)
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=answer, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def _held_across(elsewhere, udp: bool, port: int, between) -> list[str]:
    """Ask once from the other host, run `between`, and ask again on the same socket."""
    kind = "SOCK_DGRAM" if udp else "SOCK_STREAM"
    exchange = (f"s.sendto(p, ('{HOST_IP}', {port})); print(s.recvfrom(64)[0])" if udp
                else "s.sendall(p); print(s.recv(64))")
    held = (
        "import socket, time\n"
        f"s = socket.socket(socket.AF_INET, socket.{kind}); s.settimeout(4)\n"
        + ("" if udp else f"s.connect(('{HOST_IP}', {port}))\n")
        + "def ask(p):\n"
        + "    try:\n"
        + "        " + exchange + "\n"
        + "    except OSError as e:\n"
        + "        print(type(e).__name__)\n"
        + "ask(b'before')\n"
        + "time.sleep(4)\n"
        + "ask(b'after')\n"
    )
    said: list[str] = []
    client = threading.Thread(target=lambda: said.append(elsewhere(held)))
    client.start()
    time.sleep(1.5)
    between()
    client.join(timeout=20)
    return said[0].splitlines() if said else []


@pytest.mark.parametrize("udp", [False, True], ids=["tcp", "udp"])
def test_a_connection_through_the_engine_survives_the_service_stopping(
        api, service, elsewhere, udp):
    """The engine is taken out of the rules and carries what it has; see `retire`.

    From another host because that is where the return path can fail: the answers to the
    engine's own dial have to keep coming home after the service's rules are gone.
    """
    served = _echo_all_on(HOST_IP, udp)
    service_id = service(f"remote-stop-{served}", HOST_IP, served, "proxy",
                         proto="udp" if udp else "tcp")
    start_and_settle(api, service_id, wait=1.2)

    lines = _held_across(elsewhere, udp, served, lambda: api.services_stop(service_id))
    assert lines[:1] == ["b'before'"], f"the connection did not work to begin with: {lines}"
    assert lines[1:2] == ["b'after'"], \
        f"stopping the service cut a connection the engine was carrying: {lines}"


@pytest.mark.parametrize("udp", [False, True], ids=["tcp", "udp"])
@pytest.mark.parametrize("transport", ["proxy", "nfqueue"])
def test_a_connection_already_open_survives_the_service_starting(
        api, service, elsewhere, transport, udp):
    """Starting protection must not cut the clients a service already has.

    A connection made before the service started is not the datapath's — nothing
    redirected it, and nothing will: conntrack translates a connection once, at its first
    packet. It goes on straight to the service. What it must not do is stop working, and on
    the proxy layer it did for a client on another host: the rule that brings the service's
    answers home to the engine matched every answer from the service's port, these
    included, and delivered them here instead of sending them to the client.
    """
    served = _echo_all_on(HOST_IP, udp)
    service_id = service(f"remote-open-{served}", HOST_IP, served, transport,
                         proto="udp" if udp else "tcp")
    lines = _held_across(elsewhere, udp, served,
                         lambda: start_and_settle(api, service_id, wait=0.5))
    assert lines[:1] == ["b'before'"], f"the connection did not work to begin with: {lines}"
    assert lines[1:2] == ["b'after'"], \
        f"a connection already open stopped working when the service started: {lines}"
