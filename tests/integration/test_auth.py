"""Who is let in, and whether a password is asked for at all.

Half of this is about passwords, so it is the one part of the suite that cannot run
against an instance started with `--unsafe-disable-auth`: those endpoints answer 403
there by design, precisely so an anonymous caller cannot plant a credential that starts
working the moment authentication is turned back on.
"""

import secrets

import pytest

from helpers.firegexapi import FiregexAPI

pytestmark = pytest.mark.instance


@pytest.fixture(autouse=True)
def needs_authentication(auth_enabled):
    if not auth_enabled:
        pytest.skip("this instance has authentication turned off, and this module is "
                    "about authentication; start one with a password to run it")


def test_a_logged_in_session_is_reported_as_logged_in(api):
    assert api.status()["loggined"] is True


def test_a_second_session_can_log_in_alongside_the_first(api, fg_address, fg_password):
    second = FiregexAPI(fg_address)
    assert second.login(fg_password)
    assert second.status()["loggined"] is True


def test_changing_the_password_can_expire_every_other_session(api, fg_address, fg_password):
    """`expire=True` is the "somebody else has my token" button.

    The session doing the changing keeps working — it is the one that asked — and every
    other one is turned out, which is the only thing that makes the button worth having.
    """
    other = FiregexAPI(fg_address)
    assert other.login(fg_password)

    new_password = secrets.token_hex(10)
    try:
        assert api.change_password(new_password, expire=True)
        assert api.status()["loggined"] is True, "the session that changed it was expired too"
        assert other.status()["loggined"] is False, "another session survived an expiring change"
        assert other.login(new_password), "the new password does not work"
    finally:
        # Everything after this module expects the password it was given.
        api.change_password(fg_password, expire=False)


def test_a_change_without_expiry_leaves_other_sessions_alone(api, fg_address, fg_password):
    other = FiregexAPI(fg_address)
    assert other.login(fg_password)
    new_password = secrets.token_hex(10)
    try:
        assert api.change_password(new_password, expire=False)
        assert other.status()["loggined"] is True
    finally:
        api.change_password(fg_password, expire=False)


# --- authentication is a runtime setting, not a boot-time one -------------------------
# It used to be read from the environment once, at startup, which meant a password handed
# to a running instance was stored and never asked for — while `run.py config` reported
# "it will take effect immediately" at a process that had already decided every caller
# was an administrator.


def test_authentication_can_be_turned_off_and_back_on_at_runtime(api, fg_address, fg_password):
    """And the two directions are deliberately not symmetrical.

    Turning it off is a deployment choice an administrator makes. Turning it back *on*,
    asked while it is off, would let any passer-by set a password and keep the real
    operator out for good — a lasting foothold, unlike the vandalism the mode already
    permits. So re-enabling takes a token this instance signed *before* it was turned
    off, and nothing new is signed while it is off.
    """
    assert api.status()["auth_disabled"] is False, "expected to start with it on"

    anonymous = FiregexAPI(fg_address)
    assert anonymous.status()["loggined"] is False

    assert api.set_auth_mode(True), "an administrator could not turn it off"
    try:
        assert api.status()["auth_disabled"] is True, "the status did not say so at once"
        assert anonymous.status()["loggined"] is True, "the anonymous caller is still refused"
        assert isinstance(anonymous.get_interfaces(), list), "and cannot actually do anything"

        why = anonymous.set_auth_mode_error(False)
        assert why is not None, "a caller who arrived afterwards was allowed to put it back"
        assert "before it was turned off" in why, why
    finally:
        assert api.set_auth_mode(False), "the session that turned it off could not put it back"

    assert api.status()["auth_disabled"] is False
    assert anonymous.status()["loggined"] is False, "it is not being asked for again"
    assert FiregexAPI(fg_address).login(fg_password), "the password stopped working"
