"""Addresses, interfaces, and the nftables rules they turn into.

The backend's own modules, imported directly — no instance, no root, no kernel. What is
being checked is the translation from an address an operator typed to the match firegex
will install for it, which is pure enough to test without any of that.

`sys.path` is arranged by the root conftest. It used to be arranged here, by inserting
the backend at the front, which is how this module and the rest of the suite came to be
unable to run in one process: the backend's `utils` package and this directory's were
both called `utils`, and whichever was imported first won.
"""

import pytest

from utils import is_interface_name, parse_ip_or_int
from modules.services.models import Address, Service, TRANSPORT, L4, new_id
from modules.services import nftables as nft
from modules.services.nftables import (IFACE_COMMENT, FiregexTables, InstalledRule,
                                       NoRelayAddress, interface_addresses,
                                       udp_relay_host, udp_relay_key)


def test_is_interface_name():
    # Valid interface names
    assert is_interface_name("eth0") is True
    assert is_interface_name("lo") is True
    assert is_interface_name("wg0") is True
    assert is_interface_name("tun0") is True
    assert is_interface_name("enp3s0") is True
    assert is_interface_name("br-lan") is True
    assert is_interface_name("veth123456") is True
    assert is_interface_name("eth0.100") is True

    # Invalid interface names
    assert is_interface_name("") is False
    assert is_interface_name("   ") is False
    assert is_interface_name("a" * 16) is False  # > 15 chars
    assert is_interface_name("eth 0") is False   # space
    assert is_interface_name("eth/0") is False   # slash
    assert is_interface_name(123) is False       # not a string


def test_parse_ip_or_int():
    # Valid IPs should be normalized to network CIDR
    assert parse_ip_or_int("127.0.0.1") == "127.0.0.1/32"
    assert parse_ip_or_int("192.168.1.0/24") == "192.168.1.0/24"
    assert parse_ip_or_int("::1") == "::1/128"

    # Valid interfaces should return the trimmed name
    assert parse_ip_or_int("eth0") == "eth0"
    assert parse_ip_or_int("  wg0  ") == "wg0"
    assert parse_ip_or_int("lo") == "lo"

    # Invalid values should raise ValueError
    with pytest.raises(ValueError):
        parse_ip_or_int("not a valid name with spaces")
    with pytest.raises(ValueError):
        parse_ip_or_int("this_interface_name_is_way_too_long_for_linux")


def test_address_model_interface():
    addr_ip = Address(
        address_id=new_id(),
        service_id=new_id(),
        ip_int="192.168.1.1/32",
        port=80,
        proto=L4.TCP,
    )
    assert addr_ip.is_interface is False
    assert addr_ip.is_ipv6 is False

    addr_ip6 = Address(
        address_id=new_id(),
        service_id=new_id(),
        ip_int="fd00::1/128",
        port=80,
        proto=L4.TCP,
    )
    assert addr_ip6.is_interface is False
    assert addr_ip6.is_ipv6 is True

    addr_iface = Address(
        address_id=new_id(),
        service_id=new_id(),
        ip_int="eth0",
        port=80,
        proto=L4.TCP,
    )
    assert addr_iface.is_interface is True
    assert addr_iface.is_ipv6 is False



def detached_table() -> FiregexTables:
    """A `FiregexTables` that is **not** the one the rest of the process shares.

    `FiregexTables` is a `Singleton`, so `FiregexTables()` — and `FiregexTables.__new__`
    with it — hands back the very instance `modules/services/firewall.py` holds. These
    tests replace `cmd` and `list_rules` on what they are given, and assigning to the
    shared object left those stand-ins in place for the rest of the run: every later test
    that installed a rule wrote it into a list belonging to a test that had finished, and
    saw nothing happen. Nothing did until `test_rule_round_trip.py` started installing
    rules, which is a long time for a fixture to be quietly disabling the module.

    `object.__new__` skips the singleton entirely, which is what these want: an instance
    whose methods can be called and whose attributes belong to one test.
    """
    return object.__new__(FiregexTables)


def test_nftables_match_generation():
    table = detached_table()

    # IP match (inbound daddr)
    m_ip_in = table._match("127.0.0.1/32", 80, "ip", "tcp", "daddr", "dport")
    assert len(m_ip_in) == 2
    assert "payload" in m_ip_in[0]["match"]["left"]
    assert m_ip_in[0]["match"]["left"]["payload"]["field"] == "daddr"
    assert m_ip_in[1]["match"]["right"] == 80

    # Interface match (inbound daddr -> iifname)
    m_iface_in = table._match("eth0", 80, "ip", "tcp", "daddr", "dport")
    assert len(m_iface_in) == 2
    assert "meta" in m_iface_in[0]["match"]["left"]
    assert m_iface_in[0]["match"]["left"]["meta"]["key"] == "iifname"
    assert m_iface_in[0]["match"]["right"] == "eth0"
    assert m_iface_in[1]["match"]["left"]["payload"]["field"] == "dport"
    assert m_iface_in[1]["match"]["right"] == 80

    # Interface match (outbound saddr -> oifname)
    m_iface_out = table._match("eth0", 80, "ip", "tcp", "saddr", "sport")
    assert len(m_iface_out) == 2
    assert "meta" in m_iface_out[0]["match"]["left"]
    assert m_iface_out[0]["match"]["left"]["meta"]["key"] == "oifname"
    assert m_iface_out[0]["match"]["right"] == "eth0"
    assert m_iface_out[1]["match"]["left"]["payload"]["field"] == "sport"
    assert m_iface_out[1]["match"]["right"] == 80


def test_installed_rule_matches():
    srv = Service(
        service_id="srv-1",
        name="web",
        status="active",
        proto=L4.TCP,
        transport=TRANSPORT.PROXY,
    )

    addr_ip = Address(address_id="a1", service_id="srv-1", ip_int="10.0.0.1/32", port=80, proto=L4.TCP)
    addr_iface = Address(address_id="a2", service_id="srv-1", ip_int="eth0", port=80, proto=L4.TCP)

    rule_ip = InstalledRule(
        chain="fgex_nat", handle=10, proto="tcp", port=80, ip_int="10.0.0.1/32"
    )
    rule_iface = InstalledRule(
        chain="fgex_nat", handle=11, proto="tcp", port=80, ip_int="eth0"
    )

    # IP rule matches IP address, not interface
    assert rule_ip.matches(srv, addr_ip) is True
    assert rule_ip.matches(srv, addr_iface) is False

    # Interface rule matches interface address, not IP
    assert rule_iface.matches(srv, addr_iface) is True
    assert rule_iface.matches(srv, addr_ip) is False

    # Mismatched port or proto
    addr_diff_port = Address(address_id="a3", service_id="srv-1", ip_int="eth0", port=8080, proto=L4.TCP)
    assert rule_iface.matches(srv, addr_diff_port) is False

    addr_diff_proto = Address(address_id="a4", service_id="srv-1", ip_int="eth0", port=80, proto=L4.UDP)
    assert rule_iface.matches(srv, addr_diff_proto) is False


def test_installed_rule_parsing():
    # Verify parsing simulated nftables json rule with meta iifname
    raw_rule = {
        "chain": "fgex_nat",
        "handle": 42,
        "expr": [
            {
                "match": {
                    "op": "!=",
                    "left": {"meta": {"key": "mark"}},
                    "right": 0x133A,
                }
            },
            {
                "match": {
                    "op": "==",
                    "left": {"meta": {"key": "iifname"}},
                    "right": "eth0",
                }
            },
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 80,
                }
            },
            {"counter": {"packets": 12, "bytes": 1024}},
            {"redirect": {"port": 38472}},
        ]
    }

    # Simulate get() parsing logic
    table = detached_table()
    table.list_rules = lambda tables, chains: [raw_rule]
    rules = table.get()
    assert len(rules) == 1
    r = rules[0]
    assert r.chain == "fgex_nat"
    assert r.handle == 42
    assert r.ip_int == "eth0"
    assert r.port == 80
    assert r.proto == "tcp"
    assert r.packets == 12
    assert r.bytes == 1024


def test_an_interfaces_output_rule_is_read_back_as_the_interfaces():
    """The comment is what carries the identity back.

    An output-hook rule installed for an interface matches a concrete address, so what it
    matches cannot say whose it is — and `delete()` finds rules by what they match. Read
    back under the address it matches, every one of them would survive the service that
    installed it: a redirect to a port nobody is listening on any more.
    """
    raw_rule = {
        "chain": "fgex_nat_out",
        "handle": 7,
        "comment": f"{IFACE_COMMENT}wg0",
        "expr": [
            {"match": {"op": "!=", "left": {"meta": {"key": "mark"}}, "right": 0x133A}},
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                       "right": {"prefix": {"addr": "10.10.0.3", "len": 32}}}},
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": 80}},
            {"counter": {"packets": 0, "bytes": 0}},
            {"redirect": {"port": 38472}},
        ],
    }
    table = detached_table()
    table.list_rules = lambda tables, chains: [raw_rule]
    rule = table.get()[0]
    assert rule.ip_int == "wg0", "the rule was read back under the address it matches"

    srv = Service(service_id="s", name="w", status="active", proto=L4.TCP,
                  transport=TRANSPORT.PROXY)
    on_iface = Address(address_id=new_id(), service_id="s", ip_int="wg0", port=80,
                       proto=L4.TCP)
    assert rule.matches(srv, on_iface), "the service could not take its own rule back"


def test_interface_addresses_drops_link_local(monkeypatch):
    monkeypatch.setattr(nft, "get_interface_ips",
                        lambda name: ["10.0.0.1", "fe80::1%eth0", "169.254.3.4", "fd00::7"])
    assert interface_addresses("eth0") == ["10.0.0.1", "fd00::7"]
    # An address is already itself, whatever prefix it was stored with.
    assert interface_addresses("127.0.0.1/32") == ["127.0.0.1"]


def test_proxy_rule_generation_interface_vs_ip(monkeypatch):
    # What the interface carries, decided here rather than by whatever this host happens
    # to have: the rules for an interface are built from its addresses now.
    monkeypatch.setattr(
        nft, "get_interface_ips",
        lambda name: ["192.168.1.5", "fe80::1%eth0", "fd00::5"] if name == "eth0" else [],
    )
    table = detached_table()
    commands = []
    table.cmd = lambda *cmds: commands.extend(cmds)

    srv = Service(
        service_id="srv-test",
        name="web",
        status="active",
        proto=L4.TCP,
        transport=TRANSPORT.PROXY,
    )

    # 1. Interface target
    commands.clear()
    table._add_proxy(srv, "eth0", 80, "ip", "tcp", 38000)
    # Inbound and the return leg match the interface by name; the output hook cannot —
    # `iifname` means nothing for a packet this host generates, and a connection to one
    # of its own addresses is routed through `lo`, so `oifname` would never match the
    # interface either. So it matches the addresses that interface carries, one rule
    # each, which is what makes a service protected on `lo` filter a local client.
    chains = [c["add"]["rule"]["chain"] for c in commands]
    assert chains.count("fgex_nat") == 1
    assert chains.count("fgex_route") == 1
    assert chains.count("fgex_nat_out") == 2, "one per address the interface carries"
    assert len(commands) == 4

    # Inbound stays the interface and nothing narrower. Pinning it to the addresses the
    # interface carries was tried and reverted: a name is what an operator reaches for
    # when the address is not theirs to know, which includes a service on another machine
    # reached through that link, and pinning to this host's own addresses removes it.
    in_rule = [c["add"]["rule"] for c in commands if c["add"]["rule"]["chain"] == "fgex_nat"][0]
    assert not [
        e for e in in_rule["expr"]
        if e.get("match", {}).get("left", {}).get("payload", {}).get("field") == "daddr"
    ], "the inbound rule narrowed the interface to an address"

    out_rules = [c["add"]["rule"] for c in commands if c["add"]["rule"]["chain"] == "fgex_nat_out"]
    # Link-local is left out: an interface carries one it was never configured with, and
    # nothing dials a service there.
    matched = [
        e["match"]["right"]["prefix"]["addr"]
        for r in out_rules for e in r["expr"]
        if "payload" in e.get("match", {}).get("left", {})
        and e["match"]["left"]["payload"]["field"] == "daddr"
    ]
    assert sorted(matched) == ["192.168.1.5", "fd00::5"]
    # And each says whose it is, because nothing else in it does — without the comment
    # `delete()` could not find these again and would leave them behind on every stop.
    assert all(r.get("comment") == f"{IFACE_COMMENT}eth0" for r in out_rules)

    # Check expressions in nat rule
    nat_rule = [c["add"]["rule"] for c in commands if c["add"]["rule"]["chain"] == "fgex_nat"][0]
    assert any(
        e.get("match", {}).get("left", {}).get("meta", {}).get("key") == "iifname"
        and e["match"]["right"] == "eth0"
        for e in nat_rule["expr"]
    )

    # Check expressions in route rule
    route_rule = [c["add"]["rule"] for c in commands if c["add"]["rule"]["chain"] == "fgex_route"][0]
    assert any(
        e.get("match", {}).get("left", {}).get("meta", {}).get("key") == "oifname"
        and e["match"]["right"] == "eth0"
        for e in route_rule["expr"]
    )

    # 2. IP target
    commands.clear()
    table._add_proxy(srv, "127.0.0.1/32", 80, "ip", "tcp", 38000)
    # Should write to nat_chain, route_chain, AND nat_output_chain
    assert len(commands) == 3
    chains_ip = [c["add"]["rule"]["chain"] for c in commands]
    assert "fgex_nat" in chains_ip
    assert "fgex_route" in chains_ip
    assert "fgex_nat_out" in chains_ip


def test_queue_rule_generation_interface():
    table = detached_table()
    commands = []
    table.cmd = lambda *cmds: commands.extend(cmds)

    srv = Service(
        service_id="srv-test-q",
        name="dns",
        status="active",
        proto=L4.UDP,
        transport=TRANSPORT.NFQUEUE,
    )

    commands.clear()
    table._add_queue(srv, "wg0", 53, "ip", "udp", [0])
    assert len(commands) == 2
    chains = [c["insert"]["rule"]["chain"] for c in commands]
    assert "fgex_queue_out_0" in chains
    assert "fgex_queue_in_0" in chains

    in_rule = [c["insert"]["rule"] for c in commands if c["insert"]["rule"]["chain"] == "fgex_queue_in_0"][0]
    assert any(
        e.get("match", {}).get("left", {}).get("meta", {}).get("key") == "iifname"
        and e["match"]["right"] == "wg0"
        for e in in_rule["expr"]
    )

    out_rule = [c["insert"]["rule"] for c in commands if c["insert"]["rule"]["chain"] == "fgex_queue_out_0"][0]
    assert any(
        e.get("match", {}).get("left", {}).get("meta", {}).get("key") == "oifname"
        and e["match"]["right"] == "wg0"
        for e in out_rule["expr"]
    )



# --- one spelling of a UDP relay's upstream ----------------------------------
# The engine reports one `UDP <upstream> <port>` line per relay and is asked for a new
# one by the same token, so the transport's map, the rule that points at a relay and the
# manager adding an address to a running service all have to agree on it exactly. This
# formula was written out by hand in four places before it was one function.


def test_udp_relay_key_brackets_only_ipv6():
    assert udp_relay_key("127.0.0.1", 53) == "127.0.0.1:53"
    assert udp_relay_key("::1", 53) == "[::1]:53"


def test_udp_relay_key_strips_the_prefix_an_address_is_stored_with():
    """Addresses are normalised to network form, and a relay binds to one host."""
    assert udp_relay_key("10.0.0.1/32", 5353) == "10.0.0.1:5353"
    assert udp_relay_key("fd00::1/128", 5353) == "[fd00::1]:5353"


def test_udp_relay_host_passes_an_ip_through():
    assert udp_relay_host("192.168.1.5/32") == "192.168.1.5"


def test_udp_relay_host_refuses_an_interface_with_nothing_to_bind_to():
    """Named, rather than an IndexError somewhere further down.

    An interface with no address is a service the operator will have to fix, and the
    message is the only thing that says which interface and why.
    """
    with pytest.raises(NoRelayAddress, match="no IP address assigned"):
        udp_relay_host("definitely-not-an-interface")


def test_udp_relay_host_prefers_a_real_ipv4_address():
    """IPv4 first and link-local last.

    An interface almost always carries an `fe80::` address it was never configured with.
    Binding the relay there would put the service on an address nobody dials, and the
    symptom would be UDP that silently goes nowhere.
    """
    import psutil

    loopbacks = [name for name in psutil.net_if_addrs() if name in ("lo", "lo0")]
    if not loopbacks:
        pytest.skip("no loopback interface to resolve")
    assert udp_relay_host(loopbacks[0]) == "127.0.0.1"


# --- taking the rules back again ---------------------------------------------
# Rules are found by what they match rather than by a handle anybody remembered, so a
# restart that lost its bookkeeping still cleans up after itself. What that costs is
# that `matches` has to recognise every shape the module installs — and the hand-off's
# two legs are not the same shape: the inbound rule matches the service, the outbound
# one matches the operator's proxy, on the proxy's own port.


def _external_service(port=80, proxy_port=8080, ip="10.0.0.1/32", proxy_ip="127.0.0.1"):
    srv = Service(service_id="s", name="handoff", status="active", proto="tcp",
                  transport=TRANSPORT.EXTERNAL)
    addr = Address(address_id="a", service_id="s", ip_int=ip, port=port, proto="tcp",
                   edge="tcp", proxy_ip=proxy_ip, proxy_port=proxy_port)
    srv.addresses = [addr]
    return srv, addr


def test_the_inbound_handoff_rule_is_recognised():
    srv, addr = _external_service()
    rule = InstalledRule(chain=FiregexTables.hijack_in_chain, handle=1, proto="tcp",
                         port=80, ip_int="10.0.0.1/32")
    assert rule.matches(srv, addr) is True


def test_the_outbound_handoff_rule_is_recognised_too():
    """The one that was invisible, and what it cost.

    The return rule matches the proxy's address **and the proxy's port**, and the port
    was compared against the *service's* before either identity was considered — so this
    only ever matched when the two happened to be the same number. Every other hand-off
    left its outbound rule installed when the service stopped: still rewriting the source
    of anything leaving that proxy endpoint, for a service that was no longer protected,
    and joined by a second copy on the next start.
    """
    srv, addr = _external_service(port=80, proxy_port=8080)
    rule = InstalledRule(chain=FiregexTables.hijack_out_chain, handle=2, proto="tcp",
                         port=8080, ip_int="127.0.0.1/32")
    assert rule.matches(srv, addr) is True


def test_the_outbound_rule_of_one_address_is_not_another_addresss():
    """Two hand-offs cannot share an endpoint, so one must never claim the other's rule."""
    srv, addr = _external_service(proxy_port=8080)
    other = Address(address_id="b", service_id="s", ip_int="10.0.0.2/32", port=80,
                    proto="tcp", edge="tcp", proxy_ip="127.0.0.1", proxy_port=9090)
    rule = InstalledRule(chain=FiregexTables.hijack_out_chain, handle=2, proto="tcp",
                         port=8080, ip_int="127.0.0.1/32")
    assert rule.matches(srv, other) is False


def test_only_the_handoff_layer_recognises_a_proxy_endpoint():
    """A proxy-layer service has no endpoint, so the branch must not be reachable for it."""
    srv, addr = _external_service()
    srv.transport = TRANSPORT.PROXY
    rule = InstalledRule(chain=FiregexTables.hijack_out_chain, handle=2, proto="tcp",
                         port=8080, ip_int="127.0.0.1/32")
    assert rule.matches(srv, addr) is False


def test_a_rule_on_the_wrong_transport_is_not_ours():
    srv, addr = _external_service()
    rule = InstalledRule(chain=FiregexTables.hijack_in_chain, handle=1, proto="udp",
                         port=80, ip_int="10.0.0.1/32")
    assert rule.matches(srv, addr) is False


# --- where a hand-off actually points ----------------------------------------


def test_the_handoff_endpoint_defaults_to_loopback_in_the_right_family():
    assert nft.hijack_endpoint(None, "10.0.0.1/32") == "127.0.0.1"
    assert nft.hijack_endpoint(None, "fd00::1/128") == "::1"


def test_the_handoff_endpoint_is_one_host_not_a_network():
    """A `mangle` writes a single address into the packet and refuses anything else."""
    assert nft.hijack_endpoint("192.168.1.5/32", "10.0.0.1/32") == "192.168.1.5"


# --- what an operator typed, normalised once ---------------------------------


def test_whitespace_cannot_turn_an_address_into_an_interface():
    """The two tests disagreed about stripping, and that decided which of the two it was.

    `is_interface_name` strips and `is_ip_parse` does not, so ` 10.0.0.1 ` failed the
    address test, passed the interface test — every character in it is in that charset —
    and was stored verbatim. Nothing broke loudly: the rules still matched, because both
    sides re-parse the value. What broke quietly is the uniqueness key, which is a string
    comparison: `10.0.0.1` and `10.0.0.1/32` are two different addresses to it, so two
    services could each believe they were protecting that one.
    """
    assert parse_ip_or_int("  10.0.0.1  ") == parse_ip_or_int("10.0.0.1") == "10.0.0.1/32"
    assert parse_ip_or_int(" fd00::1 ") == parse_ip_or_int("fd00::1")


def test_an_interface_name_survives_the_same_normalising():
    assert parse_ip_or_int("  eth0  ") == "eth0"


def test_something_that_is_neither_is_refused_by_name():
    with pytest.raises(ValueError, match="neither a valid IP address nor"):
        parse_ip_or_int("")
    with pytest.raises(ValueError, match="neither a valid IP address nor"):
        parse_ip_or_int("not a name, and not an address")


# --- the engine's own ports ---------------------------------------------------------
# Every listener and relay the proxy engine binds is on the wildcard, so each is guarded:
# what reaches one without having been redirected there is dropped. A relay stays bound
# for as long as the engine runs, even after its address is taken off the service.


def _guard_elements(commands: list, verb: str) -> list:
    return [c[verb]["element"]["elem"][0]["concat"] for c in commands
            if verb in c and "element" in c[verb]]


def test_an_engine_port_is_guarded_until_its_service_stops(monkeypatch):
    table = detached_table()
    sent: list = []
    table.cmd = lambda *cmds: sent.extend(cmds)
    table.raw_cmd = lambda *cmds: sent.extend(cmds)
    table.get = lambda: []
    monkeypatch.setattr(FiregexTables, "_guarded", {})
    first = Address(address_id=new_id(), service_id="dns", ip_int="10.0.0.1/32", port=53,
                    proto=L4.UDP)
    second = Address(address_id=new_id(), service_id="dns", ip_int="10.0.0.2/32", port=53,
                     proto=L4.UDP)
    srv = Service(service_id="dns", name="dns", status="active", proto=L4.UDP,
                  transport=TRANSPORT.PROXY, addresses=[first, second])
    relays = {nft.udp_relay_slot(nft.udp_relay_host(a.ip_int), 53, "same"): port
              for a, port in ((first, 41000), (second, 41001))}

    table.add(srv, udp_ports=relays)
    assert sorted(_guard_elements(sent, "add")) == [["udp", 41000], ["udp", 41001]]

    sent.clear()
    table.delete(srv, [first])
    assert _guard_elements(sent, "delete") == [], \
        "a relay still bound in the engine was left reachable directly"

    sent.clear()
    table.delete(srv)
    assert sorted(_guard_elements(sent, "delete")) == [["udp", 41000], ["udp", 41001]], \
        "a port the service no longer holds was left guarded for whoever binds it next"
