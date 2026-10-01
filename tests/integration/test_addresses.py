"""Where a service is reachable, and changing that while it runs.

A service is one thing to protect and one way of intercepting it; *where* it answers is a
list. One daemon routinely answers on more than one address — a v4 and a v6 one, a public
and an internal one — and all of them deserve the same chain. Two services with
hand-copied chains is how one of them silently stops being protected.
"""

import time

import pytest

from integration.conftest import RELOAD, add_regex_filter, start_and_settle
from helpers.net import free_port
from helpers.traffic import Channel

pytestmark = pytest.mark.instance


@pytest.fixture
def running(api, protected, filtering_layer):
    service_id, server, port = protected(filtering_layer, name="addr")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    channel = Channel(server, port, filtering_layer.ipv6, filtering_layer.tls)
    return service_id, server, port, channel


def test_a_service_reports_where_it_is_reachable(api, running, filtering_layer):
    service_id, _, port, _ = running
    addresses = api.services_addresses(service_id)
    assert len(addresses) == 1 and addresses[0]["port"] == port, str(addresses)


def test_the_only_address_cannot_be_removed_and_the_refusal_says_why(api, running):
    """A service with nowhere to answer is not a service, it is a row."""
    service_id, _, _, _ = running
    only = api.services_addresses(service_id)[0]["address_id"]
    why = api.services_delete_address_error(service_id, only)
    assert why is not None, "the last address was removed"
    assert "only address" in why, why


def test_adding_an_address_to_a_running_service_drops_nothing(
        api, running, stand_in, certificate, filtering_layer):
    """Not a restart.

    The datapath is already up and already enforcing the chain, so this installs the
    rules that point one more address at it. The connections on the other addresses are
    untouched.
    """
    service_id, first, first_port, first_channel = running
    cert = certificate(filtering_layer.ip) if filtering_layer.tls else None
    second = stand_in(filtering_layer.ipv6, tls=cert)

    why = api.services_add_address_error(service_id, filtering_layer.ip, second.port)
    assert why is None, why
    assert len(api.services_addresses(service_id)) == 2
    time.sleep(1.0)

    second_channel = Channel(second, second.port, filtering_layer.ipv6, filtering_layer.tls)
    assert second_channel.gets_through(b"harmless traffic"), \
        "the new address is not carrying traffic"
    assert second_channel.is_blocked(b"carrying BLOCKME"), \
        "the same chain is not filtering the new address"
    assert first_channel.gets_through(b"harmless traffic"), \
        "the original address stopped working"


def test_the_log_says_an_address_was_added_without_dropping_anything(
        api, running, stand_in, certificate, filtering_layer):
    service_id, _, _, _ = running
    cert = certificate(filtering_layer.ip) if filtering_layer.tls else None
    second = stand_in(filtering_layer.ipv6, tls=cert)
    assert api.services_add_address_error(service_id, filtering_layer.ip, second.port) is None
    time.sleep(RELOAD)
    entries = api.services_logs(service_id)
    assert any("also protecting" in entry["text"] for entry in entries), str(entries[-4:])


def test_a_removed_address_stops_being_filtered_and_the_rest_keeps_going(
        api, running, stand_in, certificate, filtering_layer):
    """`address_removed` drops the address from the service's own list rather than
    re-reading the table, because the caller takes the rules back *before* deleting the
    row — re-reading would put it straight back, and the next restart would re-protect an
    address that no longer exists."""
    service_id, _, _, first_channel = running
    cert = certificate(filtering_layer.ip) if filtering_layer.tls else None
    second = stand_in(filtering_layer.ipv6, tls=cert)
    assert api.services_add_address_error(service_id, filtering_layer.ip, second.port) is None
    time.sleep(1.0)

    gone = [a for a in api.services_addresses(service_id)
            if a["port"] == second.port][0]["address_id"]
    assert api.services_delete_address(service_id, gone)
    time.sleep(1.0)

    second_channel = Channel(second, second.port, filtering_layer.ipv6, filtering_layer.tls)
    assert second_channel.gets_through(b"carrying BLOCKME"), \
        "the removed address is still being filtered"
    assert first_channel.is_blocked(b"carrying BLOCKME"), \
        "removing one address stopped the others being protected"


def test_an_address_can_be_a_network_interface_name(api, running):
    """An interface instead of a fixed IP or CIDR.

    Matched with `meta iifname` inbound and `meta oifname` outbound, so the traffic is
    intercepted on the interface without firegex needing to know an address for it.
    """
    service_id, _, _, _ = running
    port = free_port()
    why = api.services_add_address_error(service_id, "lo", port)
    assert why is None, why
    listed = [a for a in api.services_addresses(service_id) if a["ip_int"] == "lo"]
    assert len(listed) == 1, str(api.services_addresses(service_id))
    assert api.services_delete_address(service_id, listed[0]["address_id"])


def test_an_interface_is_refused_on_the_hand_off_layer(api, protected, external_layer):
    """The return rule rewrites the source address, which needs a concrete IP.

    Refused when the address is added rather than accepted and broken at start time.
    """
    service_id, _, _ = protected(external_layer, name="iface")
    why = api.services_add_address_error(service_id, "lo", free_port(),
                                         proxy_ip=external_layer.ip,
                                         proxy_port=free_port())
    assert why is not None, "an interface was accepted on the hand-off layer"
    assert "interface" in why.lower(), why


def test_two_services_cannot_claim_the_same_address_and_protocol(
        api, protected, service, inspecting_layer):
    """`(ip, port, proto)` is the uniqueness key, which is why the protocol is
    denormalised onto each address: a TCP service and a UDP one may share an address,
    exactly as the kernel allows, and two TCP ones may not."""
    _, _, port = protected(inspecting_layer, name="claim")
    clash = api.services_add_error(
        name=f"clash-{port}", transport=inspecting_layer.transport, proto="tcp",
        addresses=[{"ip_int": inspecting_layer.ip, "port": port}],
    )
    assert clash is not None, "two services claimed the same address and protocol"


def _echo(port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    """One exchange with whatever answers on a port of localhost.

    `Channel` dials the stand-in's own port, which is exactly the wrong thing here: a
    published address is a port the service has never listened on, and the whole question
    is whether traffic arriving there comes back from a service that has not moved.
    """
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(payload)
            return sock.recv(65535)
    except OSError:
        return b""


def _published(api, service, stand_in, name: str):
    """A plain TCP service reachable where it listens *and* on a second port."""
    server = stand_in()
    extra = free_port()
    service_id = service(
        f"{name}-{server.port}", "127.0.0.1", server.port, "proxy", proto="tcp",
        addresses=[
            {"ip_int": "127.0.0.1", "port": server.port},
            {"ip_int": "127.0.0.1", "port": extra, "target_port": server.port},
        ],
    )
    return service_id, server, extra


def test_a_plain_tcp_service_is_published_on_a_second_port(api, service, stand_in):
    """Publishing belongs to the **layer**, not to HTTP.

    It was refused outside `http` for a while, on the argument that `http` is the one
    protocol whose addresses are not all the same — which is true of the *edge* and has
    nothing to do with this. What publishing takes is something that dials, and the proxy
    layer dials whatever the protocol is: it terminates the connection and opens the one
    to the service, so it can open it on another port.

    One chain over both, because they are one service.
    """
    service_id, server, extra = _published(api, service, stand_in, "pub")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)

    assert _echo(server.port, b"hello") == b"hello", \
        "the service stopped answering where it listens"
    assert _echo(extra, b"hello") == b"hello", \
        "the published port did not reach the service"
    assert _echo(server.port, b"carrying BLOCKME") != b"carrying BLOCKME", \
        "the chain did not run on the service's own port"
    assert _echo(extra, b"carrying BLOCKME") != b"carrying BLOCKME", \
        "the chain did not run on the published port"


def test_the_port_an_address_is_sent_to_can_be_changed_while_it_runs(
        api, service, stand_in):
    """Everything an address says is editable, not only where it is.

    `edit_address` rewrote `ip_int`, `port` and the proxy endpoint and nothing else for a
    while, which left an operator who had published an address at creation with no way
    back to it short of deleting the address. The edit already takes that address's rules
    back and reinstalls them, so rewriting the rest of the row costs nothing more.

    Both directions, because only one of them is the interesting one: taking the
    publication off has to leave the address pointing at itself, where nothing listens.
    """
    service_id, server, extra = _published(api, service, stand_in, "edit")
    start_and_settle(api, service_id)
    assert _echo(extra, b"hello") == b"hello", "the published port did not reach the service"

    published = [a for a in api.services_addresses(service_id) if a["port"] == extra][0]
    # `0`, not an absent field: absent is "do not touch it", which is what makes moving
    # an address with the same call safe.
    assert api.services_edit_address(service_id, published["address_id"], "127.0.0.1",
                                     extra, target_port=0)
    time.sleep(RELOAD)
    assert [a for a in api.services_addresses(service_id)
            if a["port"] == extra][0]["target_port"] is None, "the publication was not taken off"
    assert _echo(extra, b"hello") != b"hello", \
        "the address still reached the service after the publication was taken off"
    assert _echo(server.port, b"hello") == b"hello", \
        "editing one address stopped another one working"

    assert api.services_edit_address(service_id, published["address_id"], "127.0.0.1",
                                     extra, target_port=server.port)
    time.sleep(RELOAD)
    assert _echo(extra, b"hello") == b"hello", "the publication was not put back"


def test_moving_an_address_keeps_what_it_was_told_to_do(api, service, stand_in):
    """An absent field is not a value.

    This endpoint moves an address as well as changing what it says, and a caller that
    sends only an address and a port means the first — so the rest of the row is kept.
    Read the other way, a move would quietly unpublish the address it moved.
    """
    service_id, server, extra = _published(api, service, stand_in, "keep")
    start_and_settle(api, service_id)
    published = [a for a in api.services_addresses(service_id) if a["port"] == extra][0]
    moved = free_port()

    assert api.services_edit_address(service_id, published["address_id"], "127.0.0.1", moved)
    time.sleep(RELOAD)
    now = [a for a in api.services_addresses(service_id) if a["port"] == moved]
    assert len(now) == 1, str(api.services_addresses(service_id))
    assert now[0]["target_port"] == server.port, "moving the address unpublished it"
    assert _echo(moved, b"hello") == b"hello", "the address does not work where it moved to"


def test_publishing_is_refused_where_nothing_dials(api, service, stand_in):
    """NFQUEUE hands the kernel a verdict on packets already on their way.

    It opens no connection, so there is nowhere else for it to open one — and a stored
    port nothing reads would tell an operator their service is published while it is only
    being inspected. The hand-off layer refuses it for the neighbouring reason: the proxy
    the operator runs is what dials there, and it decides for itself where the service
    is. Both are refused when the address is added, with the reason.
    """
    server = stand_in()
    queued = service(f"nodial-{server.port}", "127.0.0.1", server.port, "nfqueue",
                     proto="tcp")
    why = api.services_add_address_error(queued, "127.0.0.1", free_port(),
                                         target_port=server.port)
    assert why is not None, "a port to send traffic on to was accepted on NFQUEUE"
    assert "proxy layer" in why, why

    handed = stand_in()
    proxy_port = free_port()
    off = service(f"nodial-ext-{handed.port}", "127.0.0.1", handed.port, "external",
                  proto="tcp", proxy_ip="127.0.0.1", proxy_port=proxy_port)
    why = api.services_add_address_error(off, "127.0.0.1", free_port(),
                                         proxy_ip="127.0.0.1", proxy_port=free_port(),
                                         target_port=handed.port)
    assert why is not None, "a port to send traffic on to was accepted on the hand-off layer"
    assert "proxy layer" in why, why


def test_a_refused_address_leaves_no_service_behind(api, stand_in):
    """The address rows are written after the service's own row.

    So an address refused at that point would leave a service nobody asked for, named and
    listed and protecting nothing. Everything an address says is checked before any of it
    is written.
    """
    server = stand_in()
    name = f"noleak-{server.port}"
    why = api.services_add_error(
        name=name, transport="nfqueue", proto="tcp",
        addresses=[{"ip_int": "127.0.0.1", "port": server.port,
                    "target_port": free_port()}],
    )
    assert why is not None, "a port to send traffic on to was accepted on NFQUEUE"
    assert not [s for s in api.services_list() if s["name"] == name], \
        "the refused service was created anyway"


def test_an_interface_address_filters_traffic_from_this_host(api, service, stand_in):
    """Protecting `lo` has to mean protecting `127.0.0.1`, including from here.

    An interface address is matched by name, and a name is only a thing a packet has when
    it *arrives*: traffic this host generates never reaches the prerouting hook. So the
    output hook matched nothing for an interface and the service was intercepted for the
    outside world and silently not for anything on the box — which is the worst shape a
    firewall bug can have, and the one an operator finds by curling their own service and
    watching a blocked payload sail through.
    """
    server = stand_in()
    service_id = service(f"iface-local-{server.port}", "lo", server.port, "proxy",
                         proto="tcp")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)

    assert _echo(server.port, b"hello") == b"hello", \
        "the service stopped answering on the interface it is protected on"
    assert _echo(server.port, b"carrying BLOCKME") != b"carrying BLOCKME", \
        "a client on this host was not filtered by a service protecting its interface"


@pytest.fixture
def competing_dnat():
    """A destination rewrite at `dstnat`, where a container runtime puts its own.

    Docker and podman publish a container's port by appending a chain to `nat OUTPUT` and
    `nat PREROUTING`, which `iptables-nft` registers at exactly `dstnat`. This stands in
    for that, on the hook a test running on the protected host can actually exercise.
    """
    import shutil
    import subprocess
    if shutil.which("nft") is None:
        pytest.skip("nft is not installed, so a competing rewrite cannot be staged")
    table = "fgextest_dnat"
    installed = []

    def _install(port: int, to_port: int):
        ruleset = (
            f"table ip {table} {{\n"
            f"  chain output {{\n"
            f"    type nat hook output priority dstnat; policy accept;\n"
            f"    ip daddr 127.0.0.1 tcp dport {port} counter dnat to 127.0.0.1:{to_port}\n"
            f"  }}\n"
            f"}}\n"
        )
        done = subprocess.run(["nft", "-f", "-"], input=ruleset, text=True,
                              capture_output=True)
        if done.returncode != 0:
            pytest.skip(f"could not stage a competing rewrite: {done.stderr.strip()}")
        installed.append(True)

    yield _install

    if installed:
        subprocess.run(["nft", "delete", "table", "ip", table], capture_output=True)


def test_a_container_runtimes_rewrite_does_not_take_the_traffic(
        api, service, stand_in, competing_dnat):
    """Firegex's redirect runs before anybody else's destination rewrite.

    Its nat chains used to sit at `dstnat`, the same priority a container runtime's do.
    Two base chains at one priority in two tables are ordered by neither of them, and
    when the rewrite went first the destination became the container's address, firegex's
    rule stopped matching, and a blocked payload was answered by the service. Nothing said
    so: the service still read `ACTIVE`.

    Measured before the fix and after, which is why this test exists rather than an
    assertion about a number in a header.
    """
    real = stand_in()
    elsewhere = stand_in()
    service_id = service(f"dnat-race-{real.port}", "127.0.0.1", real.port, "proxy",
                         proto="tcp")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    competing_dnat(real.port, elsewhere.port)
    time.sleep(RELOAD)

    assert _echo(real.port, b"hello") == b"hello", \
        "the service stopped answering once a rewrite was staged beside it"
    assert _echo(real.port, b"carrying BLOCKME") != b"carrying BLOCKME", \
        "the rewrite took the traffic and the chain never ran"


def test_an_upstream_is_refused_where_nothing_is_decrypted(api, service, stand_in,
                                                          certificate):
    """The cleartext address of an HTTPS service is carried as it arrived.

    So "send it to the service over TLS" has nothing to act on there. It was accepted,
    shown back as a tag, and read by nothing — the engine's cleartext path never asks.
    """
    cert, key = certificate()
    server = stand_in()
    name = f"clear-up-{server.port}"
    why = api.services_add_error(
        name=name, transport="proxy", proto="http", tls_cert=cert, tls_key=key,
        addresses=[{"ip_int": "127.0.0.1", "port": server.port, "edge": "tcp",
                    "upstream": "tls"}],
    )
    assert why is not None, "an upstream was accepted on a cleartext address"
    assert "in the clear" in why, why

    service_id = service(name, "127.0.0.1", server.port, "proxy", proto="http",
                         tls_cert=cert, tls_key=key,
                         addresses=[{"ip_int": "127.0.0.1", "port": server.port,
                                     "edge": "tcp"}])
    address = api.services_addresses(service_id)[0]
    why = api.services_edit_address_error(service_id, address["address_id"], "127.0.0.1",
                                          server.port, edge="tcp", upstream="tls")
    assert why is not None and "in the clear" in why, why
