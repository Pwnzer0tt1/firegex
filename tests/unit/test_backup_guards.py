"""What a backup may carry, and what it may be named.

`/api/import` takes a JSON object an operator uploaded and writes files out of it. Two
things stand between that and the filesystem — a charset for the key, and `safe_join` —
and one thing stands between a restore and this instance's own credentials, which is what
`dump()` refuses to export.

All three have integration coverage, which means they are checked against a live instance
by someone who has one. They are pure functions; checking them here costs a millisecond
and covers the cases nobody would stage against a running firewall.
"""

import re
import sqlite3
from pathlib import Path

import pytest
from fastapi import HTTPException

from utils import SAFE_DB_NAME, SAFE_PY_NAME, safe_join
from utils.sqlite import SQLite


# --- what a backup entry may be called ---------------------------------------


@pytest.mark.parametrize("name", ["services.db", "firegex.db", "a.db", "A-b_9.db"])
def test_the_shapes_export_db_produces_are_accepted(name):
    assert SAFE_DB_NAME.fullmatch(name)


@pytest.mark.parametrize("name", [
    "../services.db", "db/services.db", "/etc/services.db", "..", ".db",
    "services.DB", "services.db.py", "services db.db", "services.db\x00",
])
def test_anything_that_is_not_a_plain_basename_is_refused(name):
    assert not SAFE_DB_NAME.fullmatch(name)


def test_a_trailing_newline_does_not_get_past_the_guard():
    """`$` matches before a trailing newline, so `match` accepted `"services.db\\n"`.

    It was never a way out of the directory — `safe_join` contains the result whatever
    the name — so this cost nothing. It is fixed because a pattern anchored to mean
    "this and nothing else" should mean that: the next thing written against one of
    these guards should not have to know about the exception.
    """
    assert re.match(r'^[A-Za-z0-9_-]+\.db$', "services.db\n"), "the old spelling accepted it"
    assert not SAFE_DB_NAME.fullmatch("services.db\n")
    assert not SAFE_PY_NAME.fullmatch("abc123.py\n")


def test_the_two_shapes_do_not_accept_each_other():
    assert not SAFE_PY_NAME.fullmatch("services.db")
    assert not SAFE_DB_NAME.fullmatch("abc123.py")


# --- and where it may be written ---------------------------------------------


def test_a_name_that_climbs_out_is_refused(tmp_path):
    """Defence in depth on top of the charset: the regex is what is *meant* to catch
    these, and this is what catches them if the regex is ever loosened."""
    for attempt in ("../escape.db", "a/../../escape.db", ".."):
        with pytest.raises(HTTPException) as raised:
            safe_join(tmp_path, attempt)
        assert raised.value.status_code == 403


def test_an_absolute_path_is_taken_as_a_relative_one(tmp_path):
    """Not refused but *contained*, which is the same outcome by a different route."""
    landed = safe_join(tmp_path, "/etc/passwd")
    assert landed.is_relative_to(Path(tmp_path).resolve())


def test_an_ordinary_name_lands_where_it_should(tmp_path):
    assert safe_join(tmp_path, "services.db") == Path(tmp_path).resolve() / "services.db"


# --- what a backup must never carry ------------------------------------------


def test_a_backup_carries_neither_credentials_nor_the_auth_mode(tmp_path):
    """The third one is the newest and the easiest to lose.

    `password` and `secret` are this instance's credentials. `auth_disabled` is not a
    credential — it is *whether credentials are asked for*, which belongs to the
    deployment and not to the configuration being restored. A backup able to carry it is
    a backup able to turn a firewall's authentication off.
    """
    db = SQLite(str(tmp_path / "firegex.db"), {})
    db.connect()
    db.create_schema({})
    for key, value in (("password", "$pbkdf2$secret"), ("secret", "jwt-signing-key"),
                       ("auth_disabled", "1"), ("something_else", "kept")):
        db.query("INSERT INTO keys_values (key, value) VALUES (?, ?);", key, value)

    carried = {row["key"] for row in db.dump()["keys_values"]}
    assert carried == {"something_else"}, carried
    db.disconnect()


def test_everything_else_in_a_table_is_carried(tmp_path):
    """The exclusion is three named keys, not a table nobody exports."""
    db = SQLite(str(tmp_path / "other.db"), {})
    db.connect()
    db.create_schema({"things": {"id": "VARCHAR(10) PRIMARY KEY", "v": "TEXT"}})
    db.query("INSERT INTO things (id, v) VALUES ('a', 'kept');")

    dumped = db.dump()
    assert dumped["things"] == [{"id": "a", "v": "kept"}]
    db.disconnect()
