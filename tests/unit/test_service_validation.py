"""What the API refuses before anything is started, and the reason it gives.

These are the pure functions in `routers/services.py` — no instance, no kernel, no
database. They are worth pinning on their own because of *when* they run: each one is
the last chance to turn a combination that cannot work into a sentence, and the
alternative to every one of them is a row that is accepted happily and then either
refuses to start for ever or, worse, starts and quietly does nothing.

The rule they share is that a setting which would be **read by nothing** is refused
rather than stored. An operator told their service is published, who then finds it
merely intercepted, has been lied to by a form.
"""

import base64

import pytest
from fastapi import HTTPException

from routers.services import (AddressForm, _address_edge, _address_target,
                              _address_under, _address_upstream, _check_tls_material,
                              _decoded_pattern, _hijack_ip, _hijack_port, describe_error,
                              needs_a_stream, upstream_applies)
from modules.services.models import L4, TRANSPORT, UPSTREAM


def form(**kw) -> AddressForm:
    return AddressForm(**{"ip_int": "10.0.0.1", "port": 80, **kw})


def refusal(fn, *args) -> str:
    with pytest.raises(HTTPException) as raised:
        fn(*args)
    assert raised.value.status_code == 400
    return str(raised.value.detail)


# --- what is spoken at an address --------------------------------------------


def test_only_an_http_service_is_asked_what_an_address_speaks():
    """Every other protocol has one answer for the whole service."""
    assert _address_edge(L4.TCP, form()) == L4.TCP
    assert _address_edge(L4.TLS, form()) == L4.TLS
    assert _address_edge(L4.QUIC, form()) == L4.QUIC


def test_an_edge_that_disagrees_with_its_service_is_refused():
    """A row that says one thing while its service says another would be intercepted on
    one transport and served on the other."""
    assert "cannot be" in refusal(_address_edge, L4.TCP, form(edge="tls"))


def test_an_http_address_says_how_it_is_reached():
    assert _address_edge(L4.HTTP, form(edge="tls")) == L4.TLS
    assert _address_edge(L4.HTTP, form(edge="quic")) == L4.QUIC
    assert _address_edge(L4.HTTP, form()) == L4.TCP, "cleartext unless it says otherwise"


def test_an_http_address_cannot_be_reached_in_a_way_http_is_not():
    assert "not 'udp'" in refusal(_address_edge, L4.HTTP, form(edge="udp"))


# --- where the service actually is -------------------------------------------


def test_publishing_needs_a_layer_that_dials():
    """`target_port` is a question for the layer, not for the protocol.

    The proxy terminates the connection and opens the one to the service, so it is free
    to open it elsewhere. NFQUEUE hands the kernel a verdict on packets already on their
    way; the hand-off gives the traffic to somebody else's proxy. On both, a stored port
    would be read by nothing at all.
    """
    assert _address_target(TRANSPORT.PROXY, form(target_port=8080)) == 8080
    assert "NFQUEUE" in refusal(_address_target, TRANSPORT.NFQUEUE, form(target_port=8080))
    assert "your own proxy" in refusal(_address_target, TRANSPORT.EXTERNAL,
                                       form(target_port=8080))


def test_not_publishing_is_allowed_on_every_layer():
    """Absent is the transparent case: the address *is* the service."""
    for transport in TRANSPORT.ALL:
        assert _address_target(transport, form()) is None


def test_a_published_port_has_to_be_a_port():
    assert "Invalid port" in refusal(_address_target, TRANSPORT.PROXY,
                                     form(target_port=70000))


# --- what the service behind an address speaks -------------------------------


def test_only_a_decrypted_service_has_an_upstream_leg():
    """Firegex terminates nothing elsewhere, so there is nothing to put back or leave off."""
    assert _address_upstream(L4.TLS, L4.TLS, form(upstream=UPSTREAM.TCP)) == UPSTREAM.TCP
    assert _address_upstream(L4.HTTP, L4.TLS, form(upstream=UPSTREAM.TLS)) == UPSTREAM.TLS
    assert _address_upstream(L4.HTTP, L4.QUIC, form(upstream=UPSTREAM.TCP)) == UPSTREAM.TCP
    assert "carried as it arrives" in refusal(_address_upstream, L4.TCP, L4.TCP,
                                              form(upstream=UPSTREAM.TCP))


def test_a_cleartext_address_has_no_upstream_leg_either():
    """Firegex carries what arrives at the cleartext address of an HTTPS service as it
    arrived: the engine's plaintext path never asks. The choice used to be accepted there,
    shown back as a tag, and read by nothing."""
    assert not upstream_applies(L4.HTTP, L4.TCP)
    assert upstream_applies(L4.HTTP, L4.TLS) and upstream_applies(L4.HTTP, L4.QUIC)
    assert "reached in the clear" in refusal(_address_upstream, L4.HTTP, L4.TCP,
                                             form(upstream=UPSTREAM.TLS))


def test_the_default_upstream_is_allowed_everywhere():
    """`same` is what every address did before there was a choice."""
    for proto in L4.ALL:
        for edge in L4.edges_of(proto) + (proto,):
            assert _address_upstream(proto, edge, form()) == UPSTREAM.SAME
            assert _address_upstream(proto, edge, form(upstream=UPSTREAM.SAME)) == UPSTREAM.SAME


def test_an_unknown_upstream_is_named():
    assert "Unknown upstream" in refusal(_address_upstream, L4.TLS, L4.TLS,
                                         form(upstream="carrier-pigeon"))


# --- an address, when its service changes protocol ------------------------------


def _row(**kw) -> dict:
    return {"address_id": "a", "ip_int": "10.0.0.1/32", "port": 443, "proto": "tcp",
            "edge": "tls", "upstream": "tcp", "target_port": 80, **kw}


def test_an_address_follows_its_service_to_one_protocol():
    moved = _address_under(_row(), L4.QUIC)
    assert (moved["edge"], moved["proto"]) == (L4.QUIC, L4.UDP)
    assert moved["upstream"] == UPSTREAM.TCP, "still decrypted, so the answer still applies"
    assert moved["target_port"] == 80, "where the service is is not the protocol's to change"


def test_an_answer_with_nothing_left_to_apply_to_goes():
    """A service that stops being decrypted has no leg to hand over differently."""
    assert _address_under(_row(), L4.TCP)["upstream"] == UPSTREAM.SAME


def test_an_https_service_keeps_what_each_address_said():
    assert _address_under(_row(edge="tls"), L4.HTTP)["edge"] == L4.TLS
    assert _address_under(_row(edge="quic", proto="udp"), L4.HTTP)["edge"] == L4.QUIC
    # A plain UDP address of a service becoming HTTPS is that service's HTTP/3 edge.
    became = _address_under(_row(edge="udp", proto="udp", upstream="same"), L4.HTTP)
    assert (became["edge"], became["proto"]) == (L4.QUIC, L4.UDP)
    cleartext = _address_under(_row(edge="tcp", upstream="tls"), L4.HTTP)
    assert cleartext["upstream"] == UPSTREAM.SAME


# --- where the operator's own proxy is ---------------------------------------


def test_a_handoff_endpoint_is_resolved_when_the_row_is_written():
    """Left NULL, the partial unique index cannot forbid what it exists to forbid.

    SQLite counts every NULL as distinct in a UNIQUE index, so any number of addresses
    could be stored with no endpoint — and the rules then defaulted all of them to the
    same loopback port, which is exactly the collision that index was added for. The
    return rule tells two hand-offs apart by address and port; it could not.
    """
    assert _hijack_ip(TRANSPORT.EXTERNAL, "10.0.0.1/32", form(proxy_port=8080)) == "127.0.0.1"
    assert _hijack_ip(TRANSPORT.EXTERNAL, "fd00::1/128", form(proxy_port=8080)) == "::1"


def test_a_stated_endpoint_is_kept():
    assert _hijack_ip(TRANSPORT.EXTERNAL, "10.0.0.1/32",
                      form(proxy_ip="192.168.1.5", proxy_port=8080)) == "192.168.1.5"


def test_nothing_else_has_an_endpoint():
    """A value on a layer that hands nothing off would be a setting that does nothing —
    and one that still sat in the unique index, able to refuse a real hand-off its port."""
    assert _hijack_ip(TRANSPORT.PROXY, "10.0.0.1/32", form()) is None
    assert _hijack_ip(TRANSPORT.NFQUEUE, "10.0.0.1/32", form()) is None
    assert _hijack_ip(TRANSPORT.PROXY, "10.0.0.1/32",
                      form(proxy_ip="127.0.0.1", proxy_port=8080)) is None
    assert _hijack_port(TRANSPORT.PROXY, form(proxy_port=8080)) is None
    assert _hijack_port(TRANSPORT.EXTERNAL, form(proxy_port=8080)) == 8080


# --- the TLS material ---------------------------------------------------------


def test_pem_material_passes_through_untouched():
    """Only the envelope is judged. A second opinion on what the engine accepts is the
    one that would be wrong."""
    _check_tls_material("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
                        "-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----")
    _check_tls_material(None, None)
    _check_tls_material("", "")


def test_the_two_fields_the_other_way_round_are_named_as_such():
    """The mistake is made by hand and used to cost a restart to discover."""
    swapped = refusal(_check_tls_material,
                      "-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----",
                      "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----")
    assert "other way round" in swapped


def test_something_that_is_not_pem_is_refused():
    assert "PEM certificate" in refusal(_check_tls_material, "\x00\x01binary", None)


def test_a_passphrase_protected_key_says_how_to_decrypt_it():
    why = refusal(_check_tls_material, None,
                  "-----BEGIN ENCRYPTED PRIVATE KEY-----\nz\n-----END ENCRYPTED PRIVATE KEY-----")
    assert "openssl pkey" in why


# --- the pattern a request carries -------------------------------------------


def test_a_pattern_is_decoded_strictly():
    """Python's decoder ignores what is not in the alphabet unless told not to, so a
    malformed field arrived as an empty pattern instead of as a refusal."""
    assert _decoded_pattern(base64.b64encode(b"FLAG").decode()) == "FLAG"
    assert "base64" in refusal(_decoded_pattern, "!!!not base64!!!")


def test_an_empty_pattern_is_refused_at_the_door():
    """It compiles, and then it matches every byte of every connection.

    Which makes the service refuse all of its traffic — and the only way to arrive at it
    is an empty field, so nothing is being taken away from anybody.
    """
    for encoded in ("", base64.b64encode(b"").decode()):
        assert "every byte" in refusal(_decoded_pattern, encoded)


def test_a_pattern_is_bytes_and_may_be_any_of_them():
    assert _decoded_pattern(base64.b64encode(b"\xc3\xa8FLAG").decode()).endswith("FLAG")


# --- models a datagram cannot carry ------------------------------------------


def test_only_rawpacket_survives_a_datagram():
    """Every other model reaches for something only a stream has, and answers
    `NotReadyToRun` on a datagram — so the filter would sit in the chain and never be
    called, which is the failure the whole module is arranged to prevent."""
    assert needs_a_stream(["RawPacket"]) == []
    assert needs_a_stream(["HttpRequest", "RawPacket"]) == ["HttpRequest"]
    assert needs_a_stream(["TCPInputStream", "HttpResponse"]) == ["HttpResponse",
                                                                 "TCPInputStream"]


def test_an_error_is_described_with_its_line_when_it_has_one():
    assert describe_error({"type": "SyntaxError", "line": 7, "message": "bad"}) == \
        "SyntaxError (line 7): bad"
    assert describe_error({"type": "ImportError", "line": 0, "message": "no"}) == \
        "ImportError: no"


def test_base64_wrapped_across_lines_is_still_base64():
    """Strict decoding must catch a field that is not base64, not one that is wrapped."""
    encoded = base64.b64encode(b"FLAG{" + b"x" * 80 + b"}").decode()
    wrapped = "\n".join(encoded[i:i + 40] for i in range(0, len(encoded), 40))
    assert _decoded_pattern(wrapped) == _decoded_pattern(encoded)


# --- which uniqueness rule was broken ----------------------------------------


def test_a_collision_on_the_proxy_endpoint_says_so():
    """Told apart by the columns, because that is what SQLite actually reports.

    It names the columns of the violated index — `UNIQUE constraint failed:
    service_addresses.proxy_ip, service_addresses.proxy_port` — and names the index only
    for one built on an expression. Keying on the index name therefore matched nothing,
    and this sentence had never been shown: an operator whose two hand-offs collided was
    told "one of these addresses is already protected", which points at the service
    address while the thing colliding is their proxy's port, and sent them looking for a
    service that does not exist.
    """
    import sqlite3

    from routers.services import _address_taken

    said = _address_taken(sqlite3.IntegrityError(
        "UNIQUE constraint failed: service_addresses.proxy_ip, "
        "service_addresses.proxy_port"))
    assert "proxy endpoint" in said


def test_a_collision_on_the_address_itself_says_that_instead():
    import sqlite3

    from routers.services import _address_taken

    said = _address_taken(sqlite3.IntegrityError(
        "UNIQUE constraint failed: service_addresses.ip_int, service_addresses.port, "
        "service_addresses.proto"))
    assert "already protected by a service" in said
    assert "proxy endpoint" not in said


def test_the_index_name_is_still_understood_if_it_is_ever_reported():
    import sqlite3

    from routers.services import _address_taken

    assert "proxy endpoint" in _address_taken(sqlite3.IntegrityError(
        "UNIQUE constraint failed: index 'unique_hijack_target'"))
