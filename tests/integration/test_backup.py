"""Export and import: what a backup brings back, and the two things it must never carry.

A backup is configuration, and restoring it has to bring that configuration back as it
was — services, addresses, chains, patterns, the Python files beside the database, the
firewall's rules — not merely be accepted. The password is not configuration — importing one must not
lock the current session out — and neither is *whether a password is asked for*, which
belongs to where firegex is deployed. A backup able to carry that second one is a backup
able to turn a firewall's authentication off.
"""

import time

import pytest

from integration.conftest import SETTLE, add_python_filter, add_regex_filter, start_and_settle
from helpers.firegexapi import FiregexAPI
from helpers.traffic import Channel

pytestmark = pytest.mark.instance


def test_a_backup_round_trips(api):
    backup = api.export_backup()
    assert backup, "nothing came back from the export"
    assert api.import_backup(backup)


def test_the_password_survives_an_import(api, fg_address, fg_password, auth_enabled):
    if not auth_enabled:
        pytest.skip("there is no password to survive anything on this instance")
    assert api.import_backup(api.export_backup())
    assert api.status()["loggined"] is True, "the importing session was logged out"
    assert FiregexAPI(fg_address).login(fg_password), "the password was lost or changed"


def test_whether_authentication_is_asked_for_survives_an_import(api, auth_enabled):
    """Turned off *around* the import on purpose.

    Asserting it is still on afterwards would pass either way on a container whose
    environment agrees with the running state. The bug only shows where the two disagree,
    which is exactly what a runtime change is: the key lives in `keys_values`, so it rode
    along in the dump, and the reload at the end of the import re-seeded it from the
    container's environment — reverting a `run.py config` made hours earlier.
    """
    if not auth_enabled:
        pytest.skip("this instance is already running with authentication off, so there "
                    "is no disagreement between the running state and the environment")

    assert api.set_auth_mode(True), "could not turn authentication off"
    try:
        assert api.import_backup(api.export_backup()), \
            "could not import a backup with authentication off"
        assert api.status()["auth_disabled"] is True, \
            "the backup import turned authentication back on"
    finally:
        # Back on with the session signed before it went off, which is what the rest of
        # the suite expects.
        assert api.set_auth_mode(False)
    assert api.status()["auth_disabled"] is False


# --- what a backup brings back ------------------------------------------------------
#
# Everything above checks what an import must *not* touch. These check what it is for:
# that a configuration exported, then lost, comes back as it was — not only accepted.


#: Two functions in one file, so that a function switched off can be told apart from one
#: that was never there: the switch lives in the database, the code on disk, and a backup
#: has to bring both back for the filter to mean what it meant.
TWO_FUNCTIONS = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket


@pyfilter
def refuse_marker(packet: RawPacket):
    return REJECT if b"PYBLOCK" in packet.data else ACCEPT


@pyfilter
def switched_off(packet: RawPacket):
    return REJECT if b"OFFBLOCK" in packet.data else ACCEPT
"""


def _snapshot(api, service_id: str) -> dict:
    """Everything the API says about a service and its chain, code included."""
    service = dict(api.services_get(service_id))
    # The live log is the process's, not the configuration's: a deleted service's goes
    # with it, and a restored one starts a new one.
    service.pop("problem", None)
    filters = api.services_filters(service_id)
    chain = []
    for flt in filters:
        entry = {"filter": flt}
        if flt["kind"] == "regex":
            entry["regexes"] = sorted(api.services_regexes(service_id, flt["filter_id"]),
                                      key=lambda r: r["regex_id"])
        else:
            entry["functions"] = api.services_functions(service_id, flt["filter_id"])
            entry["code"] = api.services_get_code(service_id, flt["filter_id"])
        chain.append(entry)
    return {"service": service, "addresses": api.services_addresses(service_id),
            "chain": chain}


def _filters_as_configured(channel) -> None:
    assert channel.gets_through(b"harmless"), "the service is not answering"
    assert channel.is_blocked(b"carrying RESTORE_RX"), "the pattern is not blocking"
    assert channel.is_blocked(b"carrying PYBLOCK"), "the Python filter is not blocking"
    assert channel.gets_through(b"carrying OFFBLOCK"), \
        "a function switched off is running"


def test_a_deleted_service_comes_back_whole_and_filtering(api, protected, filtering_layer):
    """Export, lose the service, import: it has to be the same service again.

    Same id, same addresses, same chain in the same order, the same patterns and code,
    the same functions switched off, the certificate a TLS service needs to start — and
    running and filtering, because it was when the backup was taken. The code is the half
    most easily lost: it is a file beside the database, deleted with the service, and
    nothing but the backup's own entry for it brings it back.
    """
    service_id, server, port = protected(filtering_layer, name="restore")
    add_regex_filter(api, service_id, "RESTORE_RX", name="patterns")
    filter_id = add_python_filter(api, service_id, TWO_FUNCTIONS, name="python")
    assert api.services_edit_function(service_id, filter_id, "switched_off", False)
    start_and_settle(api, service_id)
    channel = Channel(server, port, filtering_layer.ipv6, filtering_layer.tls)
    _filters_as_configured(channel)

    # Read through the services API first, which writes the counters still waiting: what
    # is compared afterwards includes them.
    before = _snapshot(api, service_id)
    backup = api.export_backup()

    assert api.services_delete(service_id)
    assert service_id not in [s["service_id"] for s in api.services_list()]

    assert api.import_backup(backup), "the backup was not imported"
    time.sleep(SETTLE)

    after = _snapshot(api, service_id)
    assert after["service"]["status"] == "active", \
        "a service running when the backup was taken did not come back running"
    assert after == before, "the restored service is not the one that was exported"
    _filters_as_configured(channel)


def test_firewall_rules_and_policy_come_back(api):
    """The firewall's rules and policy live in a database of their own, beside the
    services', and travel in the same backup."""
    was = api.firewall_rules()
    if was.get("enabled"):
        pytest.skip("the firewall is enabled on this instance, and rewriting its rules "
                    "here would change what the host accepts")
    rules = [
        {"active": True, "name": "ssh from the lab", "proto": "tcp", "table": "filter",
         "src": "10.0.0.0/8", "dst": "", "port_src_from": 1, "port_src_to": 65535,
         "port_dst_from": 22, "port_dst_to": 22, "action": "accept", "mode": "in"},
        {"active": False, "name": "dns out", "proto": "udp", "table": "filter",
         "src": "", "dst": "eth0", "port_src_from": 1, "port_src_to": 65535,
         "port_dst_from": 53, "port_dst_to": 53, "action": "drop", "mode": "out"},
    ]
    try:
        assert api.firewall_set_rules(rules, "accept")
        configured = api.firewall_rules()
        backup = api.export_backup()

        assert api.firewall_set_rules([], "reject")
        assert api.firewall_rules()["rules"] == []

        assert api.import_backup(backup), "the backup was not imported"
        restored = api.firewall_rules()
        assert restored == configured, "the firewall came back different from the backup"
        assert restored["enabled"] is False
    finally:
        api.firewall_set_rules(was["rules"], was["policy"])


def test_a_backup_that_cannot_be_loaded_changes_nothing(api, fg_address, fg_password,
                                                        auth_enabled):
    """Every database is tried before any is replaced.

    They used to be loaded one after another, so a refusal from one left the ones before
    it replaced and the rest of the import never ran. With `firegex.db` first — the order
    an export lists them in — its `keys_values` were replaced and this instance's password
    and secret never put back: the instance came back asking the next visitor to choose a
    password. Found by the firewall's own rules, which no import could load at all.
    """
    before = api.export_backup()
    broken = {
        "firegex.db": {"keys_values": before["firegex.db"]["keys_values"]},
        "services.db": {"services": [{"service_id": "x", "name": "x", "status": "bogus",
                                      "proto": "tcp", "transport": "proxy"}]},
    }
    why = api.s.post(f"{api.address}api/import", json=broken)
    assert why.status_code == 400, why.text
    assert "nothing was imported" in why.json().get("detail", ""), why.text

    assert api.status()["status"] == "run", "the instance lost its password to the import"
    if auth_enabled:
        assert api.status()["loggined"] is True, "the importing session was logged out"
        assert FiregexAPI(fg_address).login(fg_password), "the password was lost or changed"
    after = api.export_backup()
    assert after["services.db"] == before["services.db"], "the services were changed"


def test_an_import_leaves_no_code_behind_from_after_the_backup(api, service):
    """The database is replaced whole and the backup's filter files written, and the files
    the backup did not have used to stay: the code of every Python filter created since,
    on disk for filters that no longer existed after the import."""
    from helpers.net import free_port

    backup = api.export_backup()
    port = free_port()
    service_id = service(f"orphan-{port}", "127.0.0.1", port, "proxy")
    filter_id = add_python_filter(api, service_id, TWO_FUNCTIONS, name="python")
    assert f"{filter_id}.py" in api.export_backup().get("service_filters", {})

    assert api.import_backup(backup), "the backup was not imported"
    restored = api.export_backup()
    files = set(restored.get("service_filters", {}))
    assert f"{filter_id}.py" not in files, "the code of a filter the backup never had stayed"
    used = {f"{row['filter_id']}.py" for row in restored["services.db"].get("filters", [])
            if row["kind"] == "pyfilter"}
    assert files <= used, f"filter files nothing refers to: {sorted(files - used)}"
    kept = set(backup.get("service_filters", {})) & used
    assert kept <= files, "the code of a filter in the backup was lost"
