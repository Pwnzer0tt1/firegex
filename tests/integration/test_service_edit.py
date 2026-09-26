"""Editing a service, and what a refused edit leaves behind: nothing.

An edit changes what the datapath *is*, so it is checked the way a start would check it
and written all at once. Each test here is a way it used to leave the service somewhere
between the old definition and the new one.
"""

import time

import pytest

from integration.conftest import RELOAD, start_and_settle
from helpers.certs import UNPARSEABLE_CERT, UNPARSEABLE_KEY
from helpers.traffic import Channel

pytestmark = pytest.mark.instance


def test_a_stopped_service_is_refused_what_it_could_not_start_with(api, service,
                                                                   stand_in, certificate):
    """The layer is asked whether or not the service is running.

    It used to be asked only by starting the service, so a stopped one took any
    combination — TLS on the queued layer, here — and failed on its next start instead,
    long after the operator had moved on.
    """
    cert, key = certificate()
    server = stand_in()
    service_id = service(f"edit-nfq-{server.port}", "127.0.0.1", server.port, "nfqueue")

    why = api.services_edit_error(service_id, proto="tls", tls_cert=cert, tls_key=key)
    assert why is not None, "a stopped queued service was switched to TLS"
    assert "proxy layer" in why, why
    assert api.services_get(service_id)["proto"] == "tcp", "the refused edit was written"


def test_an_edit_that_collides_leaves_the_service_as_it_was(api, service, stand_in):
    """The service and its addresses are one write.

    Moving a UDP service to TCP rewrites its addresses too, and one of them is another
    service's TCP address. The service row used to be written first, on its own, so the
    collision left a TCP service whose addresses still said UDP.
    """
    server = stand_in()
    service(f"edit-tcp-{server.port}", "127.0.0.1", server.port, "proxy")
    udp = service(f"edit-udp-{server.port}", "127.0.0.1", server.port, "proxy", proto="udp")

    why = api.services_edit_error(udp, proto="tcp")
    assert why is not None, "two services were allowed the same TCP address"
    assert api.services_get(udp)["proto"] == "udp", "the service was rewritten anyway"
    assert [a["proto"] for a in api.services_addresses(udp)] == ["udp"]


def test_saving_a_service_as_it_was_or_renaming_it_drops_nothing(api, protected, proxy_layer):
    """The form sends every setting on every save, so most saves change nothing.

    Each of them was taken for a change of definition anyway: a running service was
    stopped and started around it, and every connection it carried was reset — for opening
    the dialog and pressing save, or for a new name, which nothing running reads.
    """
    service_id, server, _ = protected(proxy_layer, name="edit-same")
    start_and_settle(api, service_id)
    was = api.services_get(service_id)

    server.connect_client(timeout=3)
    try:
        server.send_packet(b"before")
        assert server.recv_packet() == b"before", "the connection did not work to begin with"
        assert api.services_edit(service_id, **{key: was[key] for key in (
            "name", "proto", "transport", "fail_open", "max_connections",
            "over_limit_forwards", "first_byte_timeout")})
        assert api.services_edit(service_id, name=f"{was['name']}-renamed")
        time.sleep(RELOAD)
        server.send_packet(b"after")
        assert server.recv_packet() == b"after", "saving the service dropped its connections"
    finally:
        server.close_client()
    assert api.services_get(service_id)["name"] == f"{was['name']}-renamed"


def test_a_running_service_whose_edit_will_not_start_is_put_back(api, protected,
                                                                 proxy_layer):
    """Refused by the engine, not by the form: nothing short of starting it can tell.

    The material is shaped like a certificate and is not one. The service used to be left
    stopped, on the definition that failed, with a 500 — so a typo in a certificate took
    a working service off the air.
    """
    service_id, server, port = protected(proxy_layer, name="edit-back")
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)
    assert channel.gets_through(b"before"), "the service was not working to begin with"

    why = api.services_edit_error(service_id, proto="tls", tls_cert=UNPARSEABLE_CERT,
                                  tls_key=UNPARSEABLE_KEY)
    assert why is not None, "the engine accepted material that is not a certificate"
    assert "nothing was changed" in why, why

    now = api.services_get(service_id)
    assert (now["status"], now["proto"]) == ("active", "tcp"), str(now)
    assert channel.gets_through(b"after"), "the service was not started again as it was"
