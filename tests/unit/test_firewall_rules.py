"""What the plain firewall writes into nftables, for the rules an operator lists.

Nothing here talks to the kernel: the commands are built and read back as data. The two
things pinned are both about traffic a rule was meant to let through and did not.
"""

from modules.firewall.models import Action, FirewallSettings, Mode, Protocol, Rule, Table
from modules.firewall.nftables import CONTAINER_BRIDGES, FiregexTables


def rule(**kw) -> Rule:
    fields = dict(proto=Protocol.TCP, src="", dst="", port_src_from=1, port_dst_from=80,
                  port_src_to=65535, port_dst_to=80, action=Action.ACCEPT, mode=Mode.IN,
                  table=Table.FILTER)
    fields.update(kw)
    return Rule(**fields)


def families_of(commands: list[dict]) -> list[str]:
    return [c["add"]["rule"]["family"] for c in commands]


def test_a_rule_naming_no_address_is_installed_for_both_families_wherever_it_is():
    """The family was narrowed once and never widened again, so every rule after the first
    one naming an IPv4 address was IPv4 only — an "accept port 80" below it did not
    exist for IPv6, and under a drop policy every IPv6 client of that port was refused."""
    commands = FiregexTables().get_rules(
        rule(src="10.0.0.0/8", port_dst_from=22, port_dst_to=22),
        rule(),
    )
    assert families_of(commands) == ["ip", "ip", "ip6"], families_of(commands)


def test_a_rule_for_both_protocols_is_not_rewritten_underneath_its_owner():
    both = rule(proto=Protocol.BOTH)
    commands = FiregexTables().get_rules(both)
    assert both.proto == Protocol.BOTH, "the caller's rule was turned into a TCP one"
    protocols = {c["add"]["rule"]["expr"][0]["match"]["left"]["payload"]["protocol"]
                 for c in commands}
    assert protocols == {"tcp", "udp"}, protocols


def settings(**kw) -> FirewallSettings:
    fields = dict(keep_rules=False, allow_loopback=True, allow_established=True,
                  allow_icmp=True, multicast_dns=True, allow_upnp=True, drop_invalid=True,
                  allow_dhcp=True)
    fields.update(kw)
    return FirewallSettings(**fields)


def test_container_traffic_is_left_to_the_container_runtime():
    """Under a drop policy, a chain of firegex's own is evaluated on its own — and while the
    rules lived in iptables' `FORWARD`, Docker's accepts beside them let containers talk to
    each other and out. Only published ports were given back at first, which cut a web
    container off from its database on the same bridge."""
    commands = FiregexTables().dnat_rules(settings())
    matched = [c["add"]["rule"]["expr"][0]["match"] for c in commands]
    bridges = {m["right"] for m in matched if m["left"] == {"meta": {"key": "iifname"}}}
    assert set(CONTAINER_BRIDGES) <= bridges, bridges
    assert {"docker0", "br-*"} <= bridges
    assert any(m["left"] == {"ct": {"key": "status"}} for m in matched), \
        "published ports are no longer left to the runtime"
    assert set(families_of(commands)) == {"ip", "ip6"}
    assert all(c["add"]["rule"]["chain"] == "fgex_forward" for c in commands)

    assert FiregexTables().dnat_rules(settings(allow_dnat=False)) == []
