"""TLS termination, which belongs to the proxy layer because decrypting means terminating.

The engine decrypts from the client and re-encrypts towards the service inside the
process that filters, so a TLS service occupies no port beyond the one it already
answered on. That replaced nginx terminating on one derived loopback port and
re-encrypting from a second — a pair of *chosen* ports per address, produced by hashing
`ip:port`, which could collide with something real.
"""

import time

import pytest

from integration.conftest import SETTLE, add_regex_filter, start_and_settle
from helpers.certs import (UNPARSEABLE_CERT, UNPARSEABLE_KEY, ecdsa_cert, ed25519_cert,
                           rsa_cert)
from helpers.tls_helpers import tls_alpn_choice, tls_connect_send_recv
from helpers.traffic import Channel

pytestmark = [pytest.mark.instance, pytest.mark.tls]


def test_tls_is_refused_on_a_layer_that_cannot_carry_it(api, stand_in, certificate):
    """Two of the three combinations the old boolean made expressible are now
    unrepresentable — TLS is one of the protocol's values, beside `tcp` and `udp`, not a
    flag on top of one. The third is caught at creation, with an empty chain, because a
    row that is created happily and then refuses to start every time is a trap."""
    cert, key = certificate()
    server = stand_in()
    why = api.services_add_error(
        name=f"nfq-tls-{server.port}", transport="nfqueue", proto="tls",
        addresses=[{"ip_int": "127.0.0.1", "port": server.port}],
        tls_cert=cert, tls_key=key,
    )
    assert why is not None, "a TLS service was created on the NFQUEUE layer"


def test_a_decrypted_service_filters_the_plaintext(api, protected, tls_layer):
    service_id, server, port = protected(tls_layer, name="tlsflt")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    channel = Channel(server, port, tls_layer.ipv6, tls=True)
    assert channel.gets_through(b"harmless traffic")
    assert channel.is_blocked(b"carrying BLOCKME"), \
        "the filters are not seeing the decrypted stream"


@pytest.mark.parametrize("mint,label", [
    (lambda ip: rsa_cert(ip, 2048), "rsa-2048"),
    (lambda ip: rsa_cert(ip, 4096), "rsa-4096"),
    (lambda ip: ecdsa_cert(ip), "ecdsa-p256"),
    (lambda ip: ed25519_cert(ip), "ed25519"),
])
def test_every_key_the_engine_will_sign_with_is_accepted(api, service, stand_in,
                                                         mint, label):
    """RSA at 2048 bits or more, ECDSA, or Ed25519 — what `ring` will sign with."""
    cert, key = mint("127.0.0.1")
    server = stand_in(tls=(cert, key))
    service_id = service(f"key-{label}-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="tls", tls_cert=cert, tls_key=key)
    start_and_settle(api, service_id)
    payload = f"hello from {label}".encode()
    assert tls_connect_send_recv(server.port, False, payload) == payload


def test_a_key_too_small_for_the_engine_is_refused_carrying_its_own_reason(
        api, service, stand_in, certificate):
    """nginx could be told to take an under-2048-bit RSA key with `@SECLEVEL=1`.

    rustls has no equivalent — its signing backend refuses such a key outright — so this
    is a limit rather than an unconfigured setting. What matters is that the operator is
    told that, rather than being handed "the proxy engine did not report a listening
    port" and left to find the reason in a container log.
    """
    cert, key = certificate("127.0.0.1", key_size=1024)
    server = stand_in(tls=(cert, key))
    service_id = service(f"weak-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="tls", tls_cert=cert, tls_key=key)
    why = api.services_start_error(service_id)
    assert why is not None, "a 1024-bit key was accepted"
    assert "key" in str(why).lower(), why


@pytest.mark.parametrize("offers,speaks,expected,why", [
    (["h2", "http/1.1"], ["h2", "http/1.1"], "h2", "both ends want h2"),
    (["h2", "http/1.1"], ["http/1.1"], "http/1.1",
     "the service does not speak h2, so neither does the client"),
    (["http/1.1"], ["h2", "http/1.1"], "http/1.1", "the client only offered one"),
    (["h2"], ["http/1.1"], None, "nobody agrees, and no agreement is invented"),
    (["h2", "http/1.1"], None, None, "the service offers no ALPN at all"),
])
def test_alpn_is_the_services_answer_carried_not_the_proxys(
        api, service, stand_in, certificate, offers, speaks, expected, why):
    """Terminating in the middle of a connection means answering for a service.

    Answering something the service did not say is how a proxy breaks a protocol it was
    only supposed to carry: a client told `h2` against an HTTP/1.1 service sends frames
    nothing can read. So the ClientHello is held open, the service is asked with exactly
    the client's list, and the client is told exactly what came back — including nothing.
    """
    cert, key = certificate()
    server = stand_in(tls=(cert, key), alpn=speaks)
    service_id = service(f"alpn-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="tls", tls_cert=cert, tls_key=key)
    start_and_settle(api, service_id, wait=1.5)
    assert tls_alpn_choice(server.port, False, offers) == expected, why


def test_one_broken_tls_service_is_one_broken_tls_service(api, service, stand_in,
                                                          certificate):
    """It used to be able to take every other one down with it.

    nginx parses its configuration as a unit and refuses to start if any one
    `ssl_certificate` will not load, so a service whose material was damaged left *every*
    TLS service on the instance refusing connections on ports that had been working. Each
    service now carries its certificate into its own engine process, so the blast radius
    is structural — which is worth a test precisely because nothing in the code says so
    any more.
    """
    cert, key = certificate()
    neighbour = stand_in(tls=(cert, key))
    broken_server = stand_in()

    good = service(f"ok-{neighbour.port}", "127.0.0.1", neighbour.port, "proxy",
                   proto="tls", tls_cert=cert, tls_key=key)
    bad = service(f"brk-{broken_server.port}", "127.0.0.1", broken_server.port, "proxy")

    refusal = api.services_edit_error(bad, proto="tls")
    assert refusal is not None, "switching to TLS with nothing stored was accepted"

    # Forced past that refusal the only way left: material whose envelope is right and
    # whose body will not parse. The envelope check cannot judge this one, so it is the
    # engine that has to say so.
    assert api.services_edit(bad, proto="tls", tls_cert=UNPARSEABLE_CERT,
                             tls_key=UNPARSEABLE_KEY)

    start_and_settle(api, good)
    why = api.services_start_error(bad)
    assert why is not None, "a service with unparseable material started"
    assert "certificate" in str(why).lower() or "key" in str(why).lower(), why

    time.sleep(SETTLE)
    assert tls_connect_send_recv(neighbour.port, False, b"still here") == b"still here", \
        "the broken service took its neighbour down with it"


def test_a_cleartext_service_can_be_exposed_under_tls(api, service, stand_in,
                                                      certificate):
    """Firegex as the thing that *adds* the encryption.

    The other direction of the same machinery: the client's TLS is terminated here and
    **not** put back on the way out, so the service goes on answering in the clear on the
    port it already listened on while the world reaches it over TLS. Everything else is
    unchanged — the filters see the same plaintext they always did, which is what the
    block below is here to say.

    On this edge the engine needed nothing for it: with no upstream client configuration
    the dial towards the service is an ordinary socket, which is what it already did for a
    service speaking nothing encrypted. The QUIC edge is where it became real work, and
    that is pinned in `test_http_versions.py`.
    """
    cert, key = certificate("127.0.0.1")
    # Plaintext on purpose: a stand-in with no certificate of its own is exactly the
    # service this exists for, and it is what the upstream leg would fail against.
    server = stand_in()
    service_id = service(f"plainup-{server.port}", "127.0.0.1", server.port, "proxy",
                         proto="tls", tls_cert=cert, tls_key=key, upstream="tcp")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    channel = Channel(server, server.port, False, tls=True)
    assert channel.gets_through(b"harmless traffic"), \
        "a TLS client could not reach the cleartext service behind it"
    assert channel.is_blocked(b"carrying BLOCKME"), \
        "the filters stopped seeing the plaintext once the upstream leg was in the clear"
