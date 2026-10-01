"""Forgetting UDP flows, so the next datagram of each is steered by the rules in force now.

Conntrack translates a flow once, at its first packet, and the proxy layer's `redirect`
is a translation. TCP lives with that: a connection is one thing from its handshake to
its close, and one opened before the service started is simply carried to the end. UDP
has no close — a flow lasts for as long as datagrams keep arriving inside the timeout —
and that turned the same rule into three failures:

* **a flow older than the service was never filtered**, for as long as it kept talking:
  nothing redirected it, and nothing ever would. A client could open one before the
  protection went up and keep it open indefinitely;
* **a flow carried across a restart stayed with the engine being retired**, under the
  filters it started with, and kept that engine alive until the drain gave up on it;
* **and once that engine was gone, the flow went nowhere.** Conntrack went on sending it
  to a relay port nobody listened on, every datagram refreshing the entry that did so,
  until the client happened to fall silent for two minutes.

A UDP flow can simply be forgotten: its next datagram is a new flow, judged by whatever
rules are there now, and neither end had any state that depended on the old entry. So
this deletes the entries, over ctnetlink — the kernel's own interface, the one the
`conntrack` tool speaks, with nothing to install and nothing to spawn.

TCP is never touched here: forgetting a connection breaks it.
"""

import ipaddress
import socket
import struct
from dataclasses import dataclass
from typing import Callable, Iterable

NETLINK_NETFILTER = 12

NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4
NLM_F_DUMP = 0x300
NLMSG_ERROR = 2
NLMSG_DONE = 3

NFNL_SUBSYS_CTNETLINK = 1
IPCTNL_MSG_CT_GET = 1
IPCTNL_MSG_CT_DELETE = 2

NLA_TYPE_MASK = 0x3FFF

CTA_TUPLE_ORIG = 1
CTA_TUPLE_REPLY = 2
CTA_STATUS = 3
CTA_MARK = 8
CTA_ZONE = 18

CTA_TUPLE_IP = 1
CTA_TUPLE_PROTO = 2

CTA_IP_V4_SRC = 1
CTA_IP_V4_DST = 2
CTA_IP_V6_SRC = 3
CTA_IP_V6_DST = 4

CTA_PROTO_NUM = 1
CTA_PROTO_SRC_PORT = 2
CTA_PROTO_DST_PORT = 3

#: `IPS_DST_NAT`: the flow's destination was rewritten — by a `redirect`, among others.
IPS_DST_NAT = 1 << 5

IPPROTO_UDP = 17

_HEADER = struct.Struct("=IHHII")
_NFGEN = struct.Struct("=BBH")
_ATTR = struct.Struct("=HH")


@dataclass
class Flow:
    """One conntrack entry, as much of it as deciding and deleting need."""

    family: int
    l4proto: int
    orig_src: ipaddress._BaseAddress | None
    orig_dst: ipaddress._BaseAddress | None
    orig_sport: int | None
    orig_dport: int | None
    reply_src: ipaddress._BaseAddress | None
    reply_sport: int | None
    status: int
    mark: int
    #: The original tuple and the zone exactly as the kernel sent them, which is what a
    #: delete names the entry by.
    raw_orig: bytes
    raw_zone: bytes = b""

    @property
    def redirected(self) -> bool:
        return bool(self.status & IPS_DST_NAT)


# --- the wire -------------------------------------------------------------------


def _align(n: int) -> int:
    return (n + 3) & ~3


def attr(kind: int, payload: bytes) -> bytes:
    """One netlink attribute, padded."""
    raw = _ATTR.pack(_ATTR.size + len(payload), kind) + payload
    return raw + b"\0" * (_align(len(raw)) - len(raw))


def attrs(data: bytes) -> Iterable[tuple[int, bytes, bytes]]:
    """`(type, payload, the whole attribute)` for each attribute in `data`."""
    pos = 0
    while pos + _ATTR.size <= len(data):
        length, kind = _ATTR.unpack_from(data, pos)
        if length < _ATTR.size or pos + length > len(data):
            return
        yield kind & NLA_TYPE_MASK, data[pos + _ATTR.size:pos + length], data[pos:pos + length]
        pos += _align(length)


def message(kind: int, flags: int, seq: int, family: int, payload: bytes = b"") -> bytes:
    body = _NFGEN.pack(family, 0, 0) + payload
    return _HEADER.pack(_HEADER.size + len(body), (NFNL_SUBSYS_CTNETLINK << 8) | kind,
                        flags, seq, 0) + body


def messages(data: bytes) -> Iterable[tuple[int, bytes]]:
    """`(type, payload)` for each netlink message in one read."""
    pos = 0
    while pos + _HEADER.size <= len(data):
        length, kind, _flags, _seq, _pid = _HEADER.unpack_from(data, pos)
        if length < _HEADER.size or pos + length > len(data):
            return
        yield kind, data[pos + _HEADER.size:pos + length]
        pos += _align(length)


def _tuple(data: bytes) -> tuple:
    src = dst = sport = dport = None
    proto = 0
    for kind, payload, _ in attrs(data):
        if kind == CTA_TUPLE_IP:
            for ip_kind, value, _ in attrs(payload):
                if ip_kind in (CTA_IP_V4_SRC, CTA_IP_V6_SRC):
                    src = ipaddress.ip_address(value)
                elif ip_kind in (CTA_IP_V4_DST, CTA_IP_V6_DST):
                    dst = ipaddress.ip_address(value)
        elif kind == CTA_TUPLE_PROTO:
            for proto_kind, value, _ in attrs(payload):
                if proto_kind == CTA_PROTO_NUM:
                    proto = value[0]
                elif proto_kind == CTA_PROTO_SRC_PORT:
                    sport = struct.unpack("!H", value[:2])[0]
                elif proto_kind == CTA_PROTO_DST_PORT:
                    dport = struct.unpack("!H", value[:2])[0]
    return src, dst, sport, dport, proto


def parse_flow(payload: bytes) -> Flow | None:
    """A conntrack entry out of one `IPCTNL_MSG_CT_NEW` message's payload."""
    if len(payload) < _NFGEN.size:
        return None
    family = payload[0]
    orig = reply = None
    raw_orig = raw_zone = b""
    status = mark = 0
    for kind, value, whole in attrs(payload[_NFGEN.size:]):
        if kind == CTA_TUPLE_ORIG:
            orig, raw_orig = _tuple(value), whole
        elif kind == CTA_TUPLE_REPLY:
            reply = _tuple(value)
        elif kind == CTA_STATUS:
            status = struct.unpack("!I", value[:4])[0]
        elif kind == CTA_MARK:
            mark = struct.unpack("!I", value[:4])[0]
        elif kind == CTA_ZONE:
            raw_zone = whole
    if orig is None:
        return None
    reply_src, _, reply_sport, _, _ = reply if reply else (None, None, None, None, 0)
    return Flow(
        family=family, l4proto=orig[4],
        orig_src=orig[0], orig_dst=orig[1], orig_sport=orig[2], orig_dport=orig[3],
        reply_src=reply_src, reply_sport=reply_sport,
        status=status, mark=mark, raw_orig=raw_orig, raw_zone=raw_zone,
    )


def delete_request(flow: Flow, seq: int) -> bytes:
    return message(IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST | NLM_F_ACK, seq, flow.family,
                   flow.raw_orig + flow.raw_zone)


# --- talking to the kernel ------------------------------------------------------


def _read_until_done(sock: socket.socket) -> Iterable[bytes]:
    """The payload of every entry a dump answers with."""
    while True:
        data = sock.recv(1 << 18)
        if not data:
            return
        for kind, payload in messages(data):
            if kind == NLMSG_DONE:
                return
            if kind == NLMSG_ERROR:
                error = struct.unpack_from("=i", payload)[0] if len(payload) >= 4 else 0
                if error:
                    raise OSError(-error, "conntrack dump refused")
                return
            yield payload


def _acknowledged(sock: socket.socket) -> int:
    """The error a request was answered with, 0 for none."""
    while True:
        for kind, payload in messages(sock.recv(1 << 16)):
            if kind == NLMSG_ERROR:
                return -struct.unpack_from("=i", payload)[0] if len(payload) >= 4 else 0


def delete_where(chosen: Callable[[Flow], bool]) -> int:
    """Delete every UDP entry `chosen` picks. Returns how many went.

    The table is read once and the deletes follow: a flow that ended in between is
    answered `ENOENT`, which is the state being asked for.
    """
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER) as sock:
        sock.settimeout(5)
        sock.bind((0, 0))
        sock.send(message(IPCTNL_MSG_CT_GET, NLM_F_REQUEST | NLM_F_DUMP, 1, socket.AF_UNSPEC))
        doomed = []
        for payload in _read_until_done(sock):
            flow = parse_flow(payload)
            if flow is not None and flow.l4proto == IPPROTO_UDP and chosen(flow):
                doomed.append(flow)
        gone = 0
        for seq, flow in enumerate(doomed, start=2):
            sock.send(delete_request(flow, seq))
            error = _acknowledged(sock)
            if error == 0:
                gone += 1
            elif error != 2:  # ENOENT: it ended by itself meanwhile
                raise OSError(error, "conntrack refused a delete")
        return gone


# --- what to forget -------------------------------------------------------------


Target = tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, int]


def targets(pairs: Iterable[tuple[str, int]]) -> list[Target]:
    """`(address or network, port)` pairs as something a flow can be compared with."""
    return [(ipaddress.ip_network(str(ip), strict=False), int(port)) for ip, port in pairs]


def headed_for(flow: Flow, wanted: list[Target]) -> bool:
    """Whether a flow was going to one of `wanted` before anything rewrote it."""
    if flow.orig_dst is None or flow.orig_dport is None:
        return False
    return any(
        flow.orig_dport == port and flow.orig_dst.version == network.version
        and flow.orig_dst in network
        for network, port in wanted
    )


def chooser(*, moved: list[Target], unsteered: list[Target], spare_mark: int,
            bound: set[int]) -> Callable[[Flow], bool]:
    """Which flows `forget_udp` lets go of. Split out so the decision can be tested
    without a kernel."""

    def chosen(flow: Flow) -> bool:
        if flow.mark == spare_mark:
            return False
        if headed_for(flow, moved):
            return True
        if headed_for(flow, unsteered):
            return not flow.redirected or flow.reply_sport not in bound
        return False

    return chosen


def forget_udp(*, moved: Iterable[tuple[str, int]] = (),
               unsteered: Iterable[tuple[str, int]] = (), spare_mark: int) -> int:
    """Forget UDP flows headed for these addresses, so their next datagram is steered by
    the rules in force now.

    * `moved`: every flow headed there, including the ones a redirect already took to an
      engine — a datagram flow can change engines between two datagrams and lose nothing
      but the filter's own state for it, which is what a new configuration costs anyway.
    * `unsteered`: only the ones nothing is carrying — never redirected at all, or
      redirected to a port nobody listens on any more. What a QUIC edge needs: its
      connections are terminated by an engine, and moved to another one mid-connection
      they would end, while one still draining is carrying them.

    `spare_mark` is the engine's own: its dials to the service are flows headed for the
    same address, and they are its to keep.
    """
    moved_to, unsteered_to = targets(moved), targets(unsteered)
    if not moved_to and not unsteered_to:
        return 0
    return delete_where(chooser(
        moved=moved_to, unsteered=unsteered_to, spare_mark=spare_mark,
        bound=bound_udp_ports() if unsteered_to else set(),
    ))


def bound_udp_ports() -> set[int]:
    """Every UDP port some socket on this host is bound to, from `/proc/net/udp{,6}`."""
    found = set()
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(path) as table:
                next(table, None)
                for line in table:
                    fields = line.split()
                    if len(fields) > 1 and ":" in fields[1]:
                        found.add(int(fields[1].rsplit(":", 1)[1], 16))
        except OSError:
            continue
    return found


def forget_udp_redirected_to(ports: Iterable[int], local: set) -> int:
    """Forget the UDP flows a redirect sent to one of these ports on this host.

    What is left of an engine once it has gone: every such flow points at a relay nobody
    listens on any more. Recognised by the reply coming from that port on one of this
    host's own addresses — which is what a redirect writes into the reply tuple, and what
    no flow forwarded to a container or another host can have.
    """
    wanted = {int(port) for port in ports}
    if not wanted:
        return 0
    return delete_where(
        lambda flow: flow.redirected and flow.reply_sport in wanted
        and flow.reply_src is not None and flow.reply_src in local
    )


def local_addresses() -> set:
    """Every address this host holds right now."""
    import psutil

    found = set()
    for entries in psutil.net_if_addrs().values():
        for entry in entries:
            if entry.family in (socket.AF_INET, socket.AF_INET6):
                try:
                    found.add(ipaddress.ip_address(entry.address.split("%")[0]))
                except ValueError:
                    pass
    return found
