"""Export and import, and the two things a backup must never carry.

A backup is configuration. The password is not configuration — importing one must not
lock the current session out — and neither is *whether a password is asked for*, which
belongs to where firegex is deployed. A backup able to carry that second one is a backup
able to turn a firewall's authentication off.
"""

import pytest

from helpers.firegexapi import FiregexAPI

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
