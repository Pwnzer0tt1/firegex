"""Which UDP flows are forgotten, and what the kernel is asked to forget them by.

Conntrack translates a flow at its first packet, and a UDP flow lasts for as long as
datagrams keep arriving: on the proxy layer, which is a translation, a flow older than a
service went on unfiltered for as long as it talked, one carried across a restart stayed
with the engine being retired, and one whose engine died went nowhere until the client
fell silent. Forgetting the flow is the fix, and forgetting the wrong one is a new bug —
so the decision is pinned here without a kernel, and so is the wire format it is sent in.
"""

import asyncio
import ipaddress
import socket
import struct

import pytest

from modules.services import conntrack as ct
from modules.services import firewall
from modules.services.models import TRANSPORT, Address, Service

NESTED = 0x8000
SELF_MARK = 0x133A


def _tuple(kind: int, src: str, dst: str, sport: int, dport: int, proto: int = 17) -> bytes:
    v6 = ipaddress.ip_address(src).version == 6
    ip = (ct.attr(ct.CTA_IP_V6_SRC if v6 else ct.CTA_IP_V4_SRC, ipaddress.ip_address(src).packed)
          + ct.attr(ct.CTA_IP_V6_DST if v6 else ct.CTA_IP_V4_DST, ipaddress.ip_address(dst).packed))
    ports = (ct.attr(ct.CTA_PROTO_NUM, bytes([proto]))
             + ct.attr(ct.CTA_PROTO_SRC_PORT, struct.pack("!H", sport))
             + ct.attr(ct.CTA_PROTO_DST_PORT, struct.pack("!H", dport)))
    return ct.attr(kind | NESTED, ct.attr(ct.CTA_TUPLE_IP | NESTED, ip)
                   + ct.attr(ct.CTA_TUPLE_PROTO | NESTED, ports))


def entry(orig: tuple, reply: tuple, status: int = 0, mark: int = 0, zone: int | None = None,
          proto: int = 17) -> bytes:
    """One conntrack entry, as a dump carries it."""
    family = socket.AF_INET6 if ipaddress.ip_address(orig[0]).version == 6 else socket.AF_INET
    payload = (_tuple(ct.CTA_TUPLE_ORIG, *orig, proto=proto)
               + _tuple(ct.CTA_TUPLE_REPLY, *reply, proto=proto)
               + ct.attr(ct.CTA_STATUS, struct.pack("!I", status))
               + ct.attr(ct.CTA_MARK, struct.pack("!I", mark))
               + (ct.attr(ct.CTA_ZONE, struct.pack("!H", zone)) if zone is not None else b""))
    return ct.message(0, 0x2, 7, family, payload)


def flow_of(raw: bytes) -> ct.Flow:
    [(_, payload)] = list(ct.messages(raw))
    parsed = ct.parse_flow(payload)
    assert parsed is not None
    return parsed


# A client that dialled the protected address; the redirect sent it to a relay on 40000.
CLIENT = ("192.0.2.7", "10.0.0.1", 5555, 53)
REDIRECTED = flow_of(entry(CLIENT, ("10.0.0.1", "192.0.2.7", 40000, 5555), status=ct.IPS_DST_NAT))
# The same, from before the service started: nothing rewrote it.
UNSTEERED = flow_of(entry(CLIENT, ("10.0.0.1", "192.0.2.7", 53, 5555)))
# The engine's own dial to the service, from the client's address.
ENGINES_OWN = flow_of(entry(("192.0.2.7", "10.0.0.1", 33333, 53),
                            ("10.0.0.1", "192.0.2.7", 53, 33333), mark=SELF_MARK))
ELSEWHERE = flow_of(entry(("192.0.2.7", "10.0.0.1", 5555, 54), ("10.0.0.1", "192.0.2.7", 54, 5555)))


# --- the wire -----------------------------------------------------------------------


def test_an_entry_is_read_back_as_the_kernel_sent_it():
    flow = REDIRECTED
    assert flow.family == socket.AF_INET and flow.l4proto == 17
    assert (str(flow.orig_src), str(flow.orig_dst)) == ("192.0.2.7", "10.0.0.1")
    assert (flow.orig_sport, flow.orig_dport) == (5555, 53)
    assert (str(flow.reply_src), flow.reply_sport) == ("10.0.0.1", 40000)
    assert flow.redirected and not UNSTEERED.redirected


def test_an_ipv6_entry_and_its_zone_are_read():
    flow = flow_of(entry(("2001:db8::7", "2001:db8::1", 5555, 443),
                         ("2001:db8::1", "2001:db8::7", 443, 5555), zone=3))
    assert flow.family == socket.AF_INET6
    assert str(flow.orig_dst) == "2001:db8::1" and flow.orig_dport == 443
    assert flow.raw_zone, "the zone was not kept, and a delete without it names another entry"


def test_a_delete_names_the_entry_by_its_original_tuple_and_zone():
    flow = flow_of(entry(CLIENT, ("10.0.0.1", "192.0.2.7", 40000, 5555), zone=3))
    [(kind, payload)] = list(ct.messages(ct.delete_request(flow, 9)))
    assert kind == (ct.NFNL_SUBSYS_CTNETLINK << 8) | ct.IPCTNL_MSG_CT_DELETE
    assert payload[0] == socket.AF_INET
    sent = [k for k, _, _ in ct.attrs(payload[4:])]
    assert sent == [ct.CTA_TUPLE_ORIG, ct.CTA_ZONE], sent
    assert payload[4:] == flow.raw_orig + flow.raw_zone


def test_several_messages_in_one_read_are_all_read():
    raw = entry(CLIENT, ("10.0.0.1", "192.0.2.7", 1, 5555)) * 3
    assert len(list(ct.messages(raw))) == 3


# --- which flows are forgotten ---------------------------------------------------------


def chosen(flow, moved=(), unsteered=(), bound=frozenset({40000})):
    return ct.chooser(moved=ct.targets(moved), unsteered=ct.targets(unsteered),
                      spare_mark=SELF_MARK, bound=set(bound))(flow)


def test_a_datagram_address_forgets_every_flow_headed_for_it():
    """A datagram flow changes engines between two datagrams and loses nothing but the
    filter's own state for it — so the ones an old engine carries move too."""
    target = [("10.0.0.1/32", 53)]
    assert chosen(UNSTEERED, moved=target)
    assert chosen(REDIRECTED, moved=target)


def test_the_engines_own_dials_are_never_forgotten():
    assert not chosen(ENGINES_OWN, moved=[("10.0.0.1/32", 53)])
    assert not chosen(ENGINES_OWN, unsteered=[("10.0.0.1/32", 53)], bound=set())


def test_a_flow_headed_elsewhere_is_left_alone():
    assert not chosen(ELSEWHERE, moved=[("10.0.0.1/32", 53)])
    assert not chosen(REDIRECTED, moved=[("10.0.0.2/32", 53)])
    assert not chosen(REDIRECTED, moved=[("2001:db8::/32", 53)])


def test_a_range_is_matched_as_a_range():
    assert chosen(REDIRECTED, moved=[("10.0.0.0/24", 53)])


def test_a_quic_address_keeps_what_a_live_engine_carries():
    """Moving a QUIC connection to another engine ends it; one still draining is carrying
    it. Only what nothing redirected, or what points at a port nobody listens on, goes."""
    target = [("10.0.0.1/32", 53)]
    assert chosen(UNSTEERED, unsteered=target)
    assert not chosen(REDIRECTED, unsteered=target, bound={40000})
    assert chosen(REDIRECTED, unsteered=target, bound={40001})


def test_what_an_engine_leaves_behind_is_recognised_by_its_ports(monkeypatch):
    seen = {}
    monkeypatch.setattr(ct, "delete_where", lambda pick: seen.setdefault("pick", pick) and 0)
    local = {ipaddress.ip_address("10.0.0.1")}
    ct.forget_udp_redirected_to([40000], local)
    pick = seen["pick"]
    assert pick(REDIRECTED)
    assert not pick(UNSTEERED), "a flow nothing redirected is not the engine's"
    assert not pick(flow_of(entry(CLIENT, ("10.0.0.1", "192.0.2.7", 40001, 5555),
                                  status=ct.IPS_DST_NAT)))
    # Forwarded to a container that happens to answer from the same port number.
    assert not pick(flow_of(entry(CLIENT, ("172.17.0.2", "192.0.2.7", 40000, 5555),
                                  status=ct.IPS_DST_NAT)))


def test_nothing_to_forget_asks_the_kernel_nothing(monkeypatch):
    monkeypatch.setattr(ct, "delete_where", lambda pick: pytest.fail("the kernel was asked"))
    assert ct.forget_udp(spare_mark=SELF_MARK) == 0
    assert ct.forget_udp_redirected_to([], set()) == 0


# --- when the service manager asks -----------------------------------------------------


class _Rules:
    def __init__(self, guarded):
        self.guarded = guarded
        self.released = []

    def add(self, *args, **kwargs):
        pass

    def delete(self, *args, keep_guards=False, **kwargs):
        return set(self.guarded) if keep_guards else set()

    def release_guards(self, ports):
        self.released.append(set(ports))


class _Log:
    def add(self, *args, **kwargs):
        pass

    def query(self, *args, **kwargs):
        return []


class _Engine:
    async def start(self, chain):
        return {}

    async def stop(self):
        pass

    async def retire(self, keep_filtering, then=None):
        if then:
            then()


@pytest.fixture
def asked(monkeypatch):
    calls = []
    monkeypatch.setattr(firewall.conntrack, "forget_udp",
                        lambda **kw: calls.append(("forget", kw)) or 0)
    monkeypatch.setattr(firewall.conntrack, "forget_udp_redirected_to",
                        lambda ports, local: calls.append(("gone", sorted(ports))) or 0)
    monkeypatch.setattr(firewall.conntrack, "local_addresses", lambda: set())
    monkeypatch.setattr(firewall, "log_for", lambda service_id: _Log())
    monkeypatch.setattr(firewall.transports, "build", lambda srv, **kw: _Engine())
    rules = _Rules({("udp", 40000), ("udp", 40001), ("tcp", 40002)})
    monkeypatch.setattr(firewall, "nft", rules)
    return calls, rules


def manager(transport=TRANSPORT.PROXY) -> firewall.ServiceManager:
    srv = Service(service_id="s", name="n", status="stop", proto="http", transport=transport)
    srv.addresses = [
        Address("plain", "s", "10.0.0.1/32", 53, proto="udp", edge="udp"),
        Address("quic", "s", "10.0.0.1/32", 443, proto="udp", edge="quic"),
        Address("tcp", "s", "10.0.0.1/32", 80, proto="tcp", edge="tcp"),
    ]
    return firewall.ServiceManager(srv, _Log())


async def settled(service: firewall.ServiceManager):
    while service._background:
        await asyncio.gather(*list(service._background))


def test_starting_claims_every_udp_flow_and_spares_the_quic_ones_an_engine_carries(asked):
    calls, _ = asked
    asyncio.run(manager().enable())
    assert calls == [("forget", {"moved": [("10.0.0.1/32", 53)],
                                 "unsteered": [("10.0.0.1/32", 443)],
                                 "spare_mark": firewall.PROXY_SELF_MARK})], calls


def test_stopping_lets_the_datagram_flows_go_and_the_engines_ports_after_it(asked):
    calls, rules = asked
    service = manager()

    async def run():
        await service.enable()
        calls.clear()
        await service.disable()
        await settled(service)

    asyncio.run(run())
    assert calls[0] == ("forget", {"moved": [("10.0.0.1/32", 53)],
                                   "spare_mark": firewall.PROXY_SELF_MARK}), calls
    assert calls[1] == ("gone", [40000, 40001]), "the engine's UDP ports were not let go"
    assert rules.released, "the engine's ports stayed guarded after it went"


def test_a_restart_leaves_the_flows_for_the_engine_replacing_it(asked):
    """Released at the stop half of a restart, a flow would reach the service unfiltered
    until the start half claimed it again."""
    calls, _ = asked
    service = manager()

    async def run():
        await service.enable()
        calls.clear()
        await service.restart()
        await settled(service)

    asyncio.run(run())
    forgets = [kw for kind, kw in calls if kind == "forget"]
    assert forgets == [{"moved": [("10.0.0.1/32", 53)], "unsteered": [("10.0.0.1/32", 443)],
                        "spare_mark": firewall.PROXY_SELF_MARK}], \
        f"only the start half should have touched the flows: {calls}"
    assert ("gone", [40000, 40001]) in calls, "the retired engine's ports were not let go"


def test_the_other_layers_leave_conntrack_alone(asked):
    calls, _ = asked
    service = manager(TRANSPORT.NFQUEUE)
    service.srv.proto = "udp"

    async def run():
        await service.enable()
        await service.disable()
        await settled(service)

    asyncio.run(run())
    assert [c for c in calls if c[0] == "forget"] == [], calls
