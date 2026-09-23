"""What the backend actually hands each datapath, and how a block comes back attributed.

Two wire formats, two engines, one operator-visible promise: whichever layer a service is
on, a block names the rule that made it. Getting the encoding wrong is not a crash — it is
a pattern that never matches, or a block credited to nothing, and both of those look from
the outside like a filter that is simply switched off.

None of this had a unit test: it is exercised only end to end, so a mistake here shows up
on a machine with a live instance, as traffic, rather than here.
"""

import pytest

from modules.services.models import KIND, PROTO, Filter, Regex, Service, TRANSPORT
from modules.services.transports import ChainLink, _QueueStage, announcement


def regex(regex_id: str, pattern: bytes, mode: str = "B", case_sensitive: bool = True,
          active: bool = True) -> Regex:
    return Regex(regex_id=regex_id, filter_id="f1", regex=pattern, mode=mode,
                 case_sensitive=case_sensitive, active=active)


def a_filter(kind: str = KIND.REGEX, active: bool = True, proto: str = PROTO.TCP) -> Filter:
    return Filter(filter_id="f1", service_id="s", position=0, kind=kind, name="p",
                  active=active, proto=proto)


@pytest.fixture
def stage():
    """A stage that has never been started: only its payload building is being asked."""
    srv = Service(service_id="s", name="n", status="stop", proto="tcp",
                  transport=TRANSPORT.NFQUEUE)
    return _QueueStage(srv, ChainLink(a_filter()), owner=None)


# --- what cppregex is told ----------------------------------------------------
# `<case><direction><hex>`, space separated. A pattern is bytes, and hex is the only
# encoding both ends agree on without quoting rules.


def test_a_pattern_is_sent_as_case_direction_and_hex(stage):
    assert stage._regex_payload([regex("r1", b"FLAG", mode="C")]) == b"1C464c4147\n"


def test_case_insensitivity_is_the_leading_digit(stage):
    assert stage._regex_payload(
        [regex("r1", b"x", mode="C", case_sensitive=False)]) == b"0C78\n"


def test_a_pattern_matched_both_ways_is_sent_once_per_direction(stage):
    """And **both codes attribute back to the one rule**.

    The engine reports whichever code matched; if the map held only one of them, a block
    in the other direction would arrive with nothing to credit it to — which the operator
    sees as a counter that never moves on a rule that is plainly working.
    """
    payload = stage._regex_payload([regex("r1", b"FLAG", mode="B")])
    assert payload == b"1C464c4147 1S464c4147\n"
    assert stage._codes == {"1C464c4147": "r1", "1S464c4147": "r1"}


def test_a_pattern_switched_off_is_not_sent(stage):
    payload = stage._regex_payload([regex("r1", b"on", mode="C"),
                                    regex("r2", b"off", mode="C", active=False)])
    assert b"6f6666" not in payload, "the disabled pattern was sent anyway"
    assert "r2" not in stage._codes.values()


def test_an_empty_filter_is_still_a_valid_payload(stage):
    """A service whose patterns are all off keeps its datapath: the operator turned the
    rules off, not the service, and turning one back on must not need a restart."""
    assert stage._regex_payload([]) == b"\n"


def test_a_pattern_can_be_bytes_that_are_not_text(stage):
    """Matching a raw byte sequence is a normal thing to want, which is why patterns are
    stored base64 and sent as hex."""
    assert stage._regex_payload(
        [regex("r1", bytes([0x00, 0xFF]), mode="C")]) == b"1C00ff\n"


# --- which of a file's functions run ------------------------------------------
# Three states, distinct all the way down to the worker's argv: absent means every
# function the file defines, a list means exactly those, and an empty list means the
# operator switched them all off. Collapsing two of them either runs filters that were
# turned off or stops running filters nobody touched.


def test_a_filter_whose_functions_were_never_derived_runs_all_of_them():
    """No rows at all is a filter predating the per-function switches, or one whose code
    did not parse when it was saved. Defaulting to "none" there would silently stop every
    filter in the file."""
    assert ChainLink(a_filter(), functions=[]).enabled_functions is None
    assert ChainLink(a_filter()).enabled_functions is None


def test_only_the_functions_left_switched_on_are_named():
    link = ChainLink(a_filter(), functions=[{"name": "a", "active": 1},
                                            {"name": "b", "active": 0},
                                            {"name": "c", "active": 1}])
    assert link.enabled_functions == ["a", "c"]


def test_every_function_switched_off_is_an_empty_list_not_an_absence():
    """The distinction the whole three-state design exists for."""
    link = ChainLink(a_filter(), functions=[{"name": "a", "active": 0},
                                            {"name": "b", "active": 0}])
    assert link.enabled_functions == []
    assert link.enabled_functions is not None


# --- what cpproxy is told ------------------------------------------------------


def _python_stage(tmp_path, code: str, functions=None):
    path = tmp_path / "filter.py"
    path.write_text(code, encoding="utf-8")
    srv = Service(service_id="s", name="n", status="stop", proto="tcp",
                  transport=TRANSPORT.NFQUEUE)
    link = ChainLink(a_filter(KIND.PYFILTER), code_path=str(path), functions=functions)
    return _QueueStage(srv, link, owner=None), link


def _body(payload: bytes) -> bytes:
    size = int.from_bytes(payload[:4], "big")
    assert size == len(payload) - 4, "the length prefix disagrees with what follows"
    return payload[4:]


def test_the_length_prefix_counts_bytes_not_characters(tmp_path):
    """Counted in characters, one accented letter in a comment announced fewer bytes than
    followed; the binary read the rest as the next length prefix and exited."""
    stage, link = _python_stage(tmp_path, "# perché\nX = 'é'\n")
    _body(stage._python_payload(link))


def test_the_binary_is_told_names_and_never_runs_the_file_here(tmp_path):
    """Which functions exist is the library's to work out, in the process that compiles
    the module: nothing of the operator's code runs in the backend to ask."""
    stage, link = _python_stage(tmp_path, "raise SystemExit('ran in the backend')\n")
    assert b"__firegex_pyfilter_enabled = None" in _body(stage._python_payload(link))

    stage, link = _python_stage(tmp_path, "X = 1\n", functions=[{"name": "a", "active": 1},
                                                              {"name": "b", "active": 0}])
    assert b"__firegex_pyfilter_enabled = ['a']" in _body(stage._python_payload(link))


# --- what the proxy engine is told about an address ---------------------------


def _service(proto: str = "tcp") -> Service:
    return Service(service_id="s", name="n", status="stop", proto=proto,
                   transport=TRANSPORT.PROXY)


def _address(**kw):
    from modules.services.models import Address
    return Address(**{"address_id": "a", "service_id": "s", "ip_int": "10.0.0.1/32",
                      "port": 443, "proto": "tcp", "edge": "tcp", **kw})


def test_an_ordinary_address_is_not_announced_at_all():
    """The engine's answer for an address it has never heard of is the transparent case,
    which is exactly what it would be told. An entry restating the default is one more
    thing that can be wrong."""
    assert announcement(_service(), _address()) is None


def test_an_address_that_moved_its_service_is_announced():
    said = announcement(_service(), _address(target_port=80))
    assert (said.word, said.onward, said.target_port) == ("any", "same", 80)


def test_a_target_that_is_the_port_itself_is_not_a_move():
    assert announcement(_service(), _address(target_port=443)) is None


def test_only_an_http_service_declares_an_encrypted_address():
    """`tls` is the one edge with a name of its own, because it is the only one that is a
    promise: a client opening that port in the clear is refused."""
    assert announcement(_service("http"), _address(edge="tls")).word == "tls"
    assert announcement(_service("http"), _address(edge="tcp")) is None
    assert announcement(_service("tls"), _address(edge="tls")) is None, \
        "a TLS service speaks TLS at every address; there is nothing to declare"


def test_what_the_service_behind_speaks_is_announced_on_its_own():
    """The one that was forgotten when this was two copies: it has no other way in."""
    said = announcement(_service("tls"), _address(edge="tls", upstream="tcp"))
    assert (said.word, said.onward, said.target_port) == ("any", "plain", None)


def test_a_relayed_address_is_never_announced_this_way():
    """A UDP or QUIC address has a relay of its own, bound to the service it fronts, so
    both questions were already answered when it was opened."""
    assert announcement(_service("http"),
                        _address(edge="quic", proto="udp", target_port=80)) is None


# --- what a service says about itself -----------------------------------------
# These drive two decisions with visible consequences: whether a UDP relay is opened at
# all, and whether adding an address costs every existing connection a restart. Both are
# wrong in a way nobody sees — a needless rebuild drops connections that were fine, and a
# missed one leaves a listener that cannot accept what the rules now send it.


def test_a_service_with_no_addresses_yet_answers_from_its_protocol():
    """A check made at creation, before there is an address to look at, still means
    something."""
    assert _service("tcp").carries("tcp") and not _service("tcp").carries("udp")
    assert _service("quic").carries("udp") and not _service("quic").carries("tcp")
    assert _service("http").carries("tcp") and _service("http").carries("udp"), \
        "http is the one protocol reached on both"


def test_which_addresses_need_a_relay_of_their_own():
    """Datagrams and QUIC; `SO_ORIGINAL_DST` is TCP-only, so there is nothing to recover
    per datagram and a socket is bound per address instead."""
    srv = _service("http")
    srv.addresses = [_address(port=443, proto="tcp", edge="tls"),
                     _address(port=443, proto="udp", edge="quic")]
    assert [a.edge for a in srv.udp_addresses] == ["quic"]


def test_an_ipv6_quic_address_does_not_make_the_tcp_listener_ipv6():
    """The narrower question, and the one worth asking before rebuilding a service.

    The only listener that can have its family wrong is the TCP one: everything relayed
    per address binds a socket in the family of the address when it arrives. On an `http`
    service the two sit side by side, so an IPv6 HTTP/3 address must not cost every TCP
    connection on it a restart it did not need.
    """
    from modules.services.models import Address

    srv = _service("http")
    srv.addresses = [
        Address(address_id="v4", service_id="s", ip_int="10.0.0.1/32", port=443,
                proto="tcp", edge="tls"),
        Address(address_id="v6", service_id="s", ip_int="fd00::1/128", port=443,
                proto="udp", edge="quic"),
    ]
    assert srv.has_ipv6 is True, "it does answer on an IPv6 address"
    assert srv.has_ipv6_tcp is False, "but not one the TCP listener has to accept"


def test_an_ipv6_tcp_address_does():
    from modules.services.models import Address

    srv = _service("tcp")
    srv.addresses = [Address(address_id="v6", service_id="s", ip_int="fd00::1/128",
                             port=80, proto="tcp", edge="tcp")]
    assert srv.has_ipv6_tcp is True


def test_an_interface_is_not_an_address_of_either_family():
    """It stands for whatever it carries, resolved when the rules are installed — so the
    service cannot answer the family question from the name alone."""
    from modules.services.models import Address

    srv = _service("tcp")
    srv.addresses = [Address(address_id="i", service_id="s", ip_int="eth0", port=80,
                             proto="tcp", edge="tcp")]
    assert srv.addresses[0].is_interface is True
    assert srv.has_ipv6 is False


def test_which_protocols_are_decrypted_by_the_engine():
    """Named for what it does rather than for TLS, because two protocols do it now."""
    assert [p for p in ("tcp", "udp", "tls", "quic", "http") if _service(p).decrypts] \
        == ["tls", "quic", "http"]
