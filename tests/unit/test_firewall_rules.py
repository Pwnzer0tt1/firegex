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


# --- replacing the firewall whole, or not at all ------------------------------


def test_the_firewall_is_replaced_in_one_batch_with_its_teardown(monkeypatch):
    """The teardown used to be a batch of its own, sent first. When nft then refused a rule
    the old tables were already gone and the new ones never arrived: a default-deny
    firewall became no firewall. One batch is applied whole or not at all."""
    tables = FiregexTables()
    sent = []

    def cmd(*commands):
        sent.append(commands)
        return {"nftables": []}

    def raw_cmd(*commands):
        sent.append(commands)
        return 0, {"nftables": []}, ""

    monkeypatch.setattr(tables, "cmd", cmd)
    monkeypatch.setattr(tables, "raw_cmd", raw_cmd)
    tables.set([rule()], policy=Action.DROP, opt=settings())

    assert len(sent) == 1, f"the firewall went out in {len(sent)} batches"
    batch = sent[0]
    deleted = [i for i, c in enumerate(batch) if "delete" in c]
    chains = [i for i, c in enumerate(batch) if "chain" in c.get("add", {})]
    assert deleted and chains, "the batch neither tears down nor builds"
    assert max(deleted) < min(chains), "the teardown has to come before what replaces it"


def test_a_refused_firewall_leaves_nothing_half_applied(monkeypatch):
    """nft refusing the batch must not leave a separate teardown behind it."""
    tables = FiregexTables()
    sent = []

    def cmd(*commands):
        sent.append(commands)
        raise Exception("Error: syntax error")

    monkeypatch.setattr(tables, "cmd", cmd)
    monkeypatch.setattr(tables, "raw_cmd", lambda *c: sent.append(c) or (1, {}, "no"))
    try:
        tables.set([rule()], policy=Action.DROP, opt=settings())
    except Exception:
        pass
    assert len(sent) == 1, "something was sent to the kernel besides the refused batch"


# --- what the router lets through, and what it does when nft says no -----------


def test_an_address_field_is_an_address_or_an_interface_the_kernel_takes():
    import pytest
    from fastapi import HTTPException

    from modules.firewall.models import RuleModel
    from routers.firewall import parse_and_check_rule

    def model(**kw) -> RuleModel:
        fields = dict(active=True, name="r", proto="tcp", table="filter", src="", dst="",
                      port_src_from=1, port_dst_from=80, port_src_to=65535,
                      port_dst_to=80, action="accept", mode="in")
        fields.update(kw)
        return RuleModel(**fields)

    assert parse_and_check_rule(model(src="eth0")).src == "eth0"
    assert parse_and_check_rule(model(src=" br-* ")).src == "br-*"
    assert parse_and_check_rule(model(src="10.0.0.1")).src == "10.0.0.1/32"
    for bad in ("a-name-far-too-long-for-a-kernel", 'eth0"', "eth 0", "10.0.0.0/33x"):
        with pytest.raises(HTTPException) as refused:
            parse_and_check_rule(model(src=bad))
        assert refused.value.status_code == 400, bad


def test_a_change_nft_refuses_puts_the_database_back(monkeypatch):
    """Kept, the refused configuration is what the watcher retries every few seconds and
    what the next boot comes up with — failing each time, with no firewall behind it."""
    import asyncio

    import pytest
    from fastapi import HTTPException

    import routers.firewall as router

    attempts = []

    async def reload():
        attempts.append(len(attempts))
        if len(attempts) == 1:
            raise Exception("Error: Could not process rule")

    async def refresh():
        pass

    undone = []
    monkeypatch.setattr(router.firewall, "reload", reload)
    monkeypatch.setattr(router, "refresh_frontend", refresh)
    with pytest.raises(HTTPException) as refused:
        asyncio.run(router.apply_changes(lambda: undone.append(True)))
    assert refused.value.status_code == 400
    assert undone == [True], "the database was left holding what nft refused"
    assert len(attempts) == 2, "the previous firewall was not put back after the undo"
