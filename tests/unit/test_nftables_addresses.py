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


def test_nftables_match_generation():
    table = FiregexTables.__new__(FiregexTables)

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
    table = FiregexTables.__new__(FiregexTables)
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
    table = FiregexTables.__new__(FiregexTables)
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
    table = FiregexTables.__new__(FiregexTables)
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
    table = FiregexTables.__new__(FiregexTables)
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
