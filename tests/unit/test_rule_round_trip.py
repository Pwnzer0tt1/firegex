"""Every rule this module writes has to be findable again by the code that removes it.

Rules are found by **what they match** rather than by a handle anybody remembered, so a
restart that lost its bookkeeping still cleans up after itself. The price of that choice
is an invariant nothing else enforces: `add()` and `delete()` have to agree about what a
rule looks like, and they are written far apart and reason differently — one builds an
expression, the other reads one back.

When they disagree the rule is simply never removed. It survives the service that
installed it, pointing traffic at a queue nobody reads or a port nobody is bound to, and
the next start adds another beside it. Nothing raises; the ruleset just grows.

So this round-trips: install a service's rules against a stand-in nftables, hand what was
written back to the reader, and ask `delete()` for every one of them. It is the test that
would have caught the hand-off's return rule being invisible — the outbound leg matches
the operator's proxy on the proxy's port, and `matches()` compared the port against the
service's before considering which of the two identities it was looking at.
"""

import pytest

from modules.services.models import TRANSPORT, Address, L4, Service
from modules.services.nftables import FiregexTables


class FakeNft:
    """The smallest thing `FiregexTables` can talk to.

    Rules are kept in the order they were installed, each with a handle, and `insert` puts
    one at the front exactly as nftables does — which is what the queue chains rely on.
    """

    def __init__(self):
        self.rules: list[dict] = []
        self._handle = 0

    def json_cmd(self, payload):
        for command in payload["nftables"]:
            for verb in ("add", "insert"):
                rule = command.get(verb, {}).get("rule")
                if rule is None:
                    continue
                self._handle += 1
                stored = {**rule, "handle": self._handle}
                self.rules.insert(0 if verb == "insert" else len(self.rules), stored)
            gone = command.get("delete", {}).get("rule")
            if gone is not None:
                self.rules = [r for r in self.rules if r["handle"] != gone["handle"]]
        return 0, {"nftables": [{"rule": rule} for rule in self.rules]}, ""


@pytest.fixture
def tables(monkeypatch):
    """A `FiregexTables` whose ruleset is the fake above.

    It is a `Singleton`, so the instance is shared with anything else that built one —
    the stand-in is installed on the instance rather than replacing the class.
    """
    handle = FiregexTables()
    fake = FakeNft()
    monkeypatch.setattr(handle, "nft", fake)
    # Restored explicitly, because they are what a test elsewhere in this directory used
    # to replace on this same shared object and leave replaced. Asking for the class's
    # own implementations back makes these tests independent of what ran before them.
    monkeypatch.setattr(handle, "cmd", FiregexTables.cmd.__get__(handle))
    monkeypatch.setattr(handle, "list_rules", FiregexTables.list_rules.__get__(handle))
    yield handle, fake


def service(transport: str, proto: str = "tcp", **address_fields) -> Service:
    srv = Service(service_id="s", name="round-trip", status="active", proto=proto,
                  transport=transport)
    srv.addresses = [Address(address_id="a", service_id="s", ip_int="10.0.0.1/32",
                             port=8080, proto=L4.l4_of(proto), edge=proto,
                             **address_fields)]
    return srv


def installed_in(fake: FakeNft, table_chains: set[str] | None = None) -> list[dict]:
    return [r for r in fake.rules
            if table_chains is None or r["chain"] in table_chains]


# --- one layer at a time ------------------------------------------------------


def test_the_handoffs_rules_are_all_taken_back(tables):
    """Three rules on two different ports, and every one of them has to go.

    Inbound and output-hook rules match the service; the return rule matches the
    operator's proxy on **its** port. Only the first two were ever recognised again.
    """
    handle, fake = tables
    srv = service(TRANSPORT.EXTERNAL, proxy_ip="127.0.0.1", proxy_port=9000)

    handle.add(srv)
    assert fake.rules, "the hand-off installed no rules at all"
    ports = {r["chain"] for r in fake.rules}
    assert handle.hijack_out_chain in ports, "no return rule was written"

    handle.delete(srv)
    assert fake.rules == [], \
        f"rules survived the service that installed them: {fake.rules}"


def test_the_handoff_does_not_accumulate_across_restarts(tables):
    """The other half of the same failure: what is never removed is installed again."""
    handle, fake = tables
    srv = service(TRANSPORT.EXTERNAL, proxy_ip="127.0.0.1", proxy_port=9000)

    handle.add(srv)
    first = len(fake.rules)
    handle.delete(srv)
    handle.add(srv)
    assert len(fake.rules) == first, \
        f"the ruleset grew from {first} to {len(fake.rules)} over one restart"


def test_the_nfqueue_layers_rules_are_all_taken_back(tables):
    handle, fake = tables
    srv = service(TRANSPORT.NFQUEUE)

    handle.add(srv, queue_nums=[1000, 1001])
    # Two for traffic arriving, and two for this host's own to the address after a
    # container runtime rewrote it — the ones matched through conntrack, which `get()`
    # only finds by their comment.
    assert len(fake.rules) == 8, "two positions, two pairs of rules each"

    handle.delete(srv)
    assert fake.rules == [], str(fake.rules)


def test_the_proxy_layers_rules_are_all_taken_back(tables):
    handle, fake = tables
    srv = service(TRANSPORT.PROXY)

    handle.add(srv, proxy_port=40000)
    assert fake.rules, "the proxy layer installed no rules"

    handle.delete(srv)
    assert fake.rules == [], str(fake.rules)


def test_a_published_address_is_still_matched_by_where_it_is_dialled(tables):
    """The rules match where the world knocks, never where the service turned out to be —
    getting that backwards redirected the service's own port twice and left the published
    one unprotected."""
    handle, fake = tables
    srv = service(TRANSPORT.PROXY)
    srv.addresses[0].target_port = 80

    handle.add(srv, proxy_port=40000)
    assert any("8080" in str(r["expr"]) for r in fake.rules), \
        "no rule matched the port the address is dialled on"

    handle.delete(srv)
    assert fake.rules == [], str(fake.rules)


# --- one address of several ---------------------------------------------------


def test_removing_one_address_leaves_the_others_steered(tables):
    """Passing a subset is how an address is taken off a running service."""
    handle, fake = tables
    srv = service(TRANSPORT.PROXY)
    second = Address(address_id="b", service_id="s", ip_int="10.0.0.2/32", port=9090,
                     proto="tcp", edge="tcp")
    srv.addresses.append(second)

    handle.add(srv, proxy_port=40000)
    both = len(fake.rules)

    handle.delete(srv, [second])
    assert 0 < len(fake.rules) < both, \
        "removing one address took the other's rules with it, or none at all"
    assert all("10.0.0.2" not in str(r["expr"]) for r in fake.rules)

    handle.delete(srv)
    assert fake.rules == []


def test_an_address_already_steered_is_not_steered_twice(tables):
    """`add` is called again whenever an address is added to a running service, so it has
    to be idempotent for the ones already there."""
    handle, fake = tables
    srv = service(TRANSPORT.PROXY)

    handle.add(srv, proxy_port=40000)
    once = len(fake.rules)
    handle.add(srv, proxy_port=40000)
    assert len(fake.rules) == once, "the same address was steered twice"


# --- what an interface leaves behind ------------------------------------------


def test_an_interface_rule_is_found_again_by_its_comment(tables):
    """The output-hook rule an interface installs matches an **address**, so nothing in
    it says whose it is. The comment does, and without reading it back every one of them
    would outlive its service as a redirect to a port nobody is listening on."""
    from modules.services import nftables as nft

    handle, fake = tables
    srv = service(TRANSPORT.PROXY)
    srv.addresses = [Address(address_id="a", service_id="s", ip_int="fgexlo0", port=8080,
                             proto="tcp", edge="tcp")]

    # The interface carries one address, so the output hook writes one rule for it.
    nft_addresses = nft.interface_addresses
    try:
        nft.interface_addresses = lambda ip: ["10.9.9.9"] if ip == "fgexlo0" else nft_addresses(ip)
        handle.add(srv, proxy_port=40000)
        comments = [r.get("comment") for r in fake.rules if r.get("comment")]
        assert any(c == f"{nft.IFACE_COMMENT}fgexlo0" for c in comments), \
            f"the interface rule carries no comment naming it: {fake.rules}"
        handle.delete(srv)
        assert fake.rules == [], f"the interface's rules leaked: {fake.rules}"
    finally:
        nft.interface_addresses = nft_addresses
