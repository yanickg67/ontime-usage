"""The guarantees four services will depend on."""

import os
import sqlite3
import pytest

import ontime_usage as usage
from ontime_usage import counter


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("ONTIME_USAGE_DB", str(tmp_path / "u.db"))
    monkeypatch.setenv("ONTIME_USAGE_SERVICE", "testsvc")
    monkeypatch.setenv("ONTIME_USAGE_ROLE", "testrole")
    monkeypatch.delenv("ONTIME_USAGE_ENABLED", raising=False)
    counter._literal_paths = frozenset()
    yield


def rows(db=None):
    conn = sqlite3.connect(db or usage.db_path())
    try:
        return conn.execute(
            "SELECT service, role, cred, method, endpoint, status, calls"
            " FROM api_usage").fetchall()
    finally:
        conn.close()


# --- the security-critical one --------------------------------------------

def test_THE_KEY_IS_NEVER_WRITTEN_TO_DISK(tmp_path):
    secret = "sk-live-THIS-MUST-NEVER-APPEAR-9f3a2b"
    usage.record("GET", "locations", status_code=200,
                 cred=usage.fingerprint(secret))
    raw = (tmp_path / "u.db").read_bytes()
    assert secret.encode() not in raw
    assert b"THIS-MUST-NEVER-APPEAR" not in raw


def test_fingerprint_is_short_stable_and_not_the_key():
    a = usage.fingerprint("key-one")
    assert a == usage.fingerprint("key-one")
    assert a != usage.fingerprint("key-two")
    assert len(a) == 12 and "key-one" not in a
    assert usage.fingerprint(None) == "none"
    assert usage.fingerprint("") == "none"


# --- never raises ----------------------------------------------------------

def test_record_never_raises_on_an_unwritable_path(monkeypatch):
    monkeypatch.setenv("ONTIME_USAGE_DB", "/proc/cannot/write/here.db")
    usage.record("GET", "locations", status_code=200, cred="abc")   # must not raise


def test_record_never_raises_on_rubbish_input():
    usage.record(None, None, status_code="not a number", cred=None)
    usage.record("", "", error=True, cred="")


def test_disabled_writes_nothing(monkeypatch, tmp_path):
    monkeypatch.setenv("ONTIME_USAGE_ENABLED", "false")
    usage.record("GET", "locations", status_code=200, cred="abc")
    assert not (tmp_path / "u.db").exists()


# --- shaping ---------------------------------------------------------------

def test_ids_collapse_but_declared_literals_do_not():
    assert usage.endpoint_family("locations/3f2a-9d") == "locations/{id}"
    assert usage.endpoint_family("locations") == "locations"
    assert usage.endpoint_family("") == "(empty)"
    usage.configure(literal_paths={"userMiscCompensation/post"})
    assert usage.endpoint_family("userMiscCompensation/post") == "userMiscCompensation/post"
    assert usage.endpoint_family("order/post") == "order/{id}"   # not declared here


def test_429_is_its_own_bucket():
    assert usage.status_bucket(429) == "429"
    assert usage.status_bucket(404) == "4xx"
    assert usage.status_bucket(503) == "5xx"
    assert usage.status_bucket(200) == "2xx"
    assert usage.status_bucket(None) == "error"
    assert usage.status_bucket(200, error=True) == "error"


# --- the counting itself ---------------------------------------------------

def test_repeat_calls_increment_one_row():
    for _ in range(3):
        usage.record("GET", "locations", status_code=200, cred="aaa")
    assert rows() == [("testsvc", "testrole", "aaa", "GET", "locations", "2xx", 3)]


def test_two_credentials_are_two_rows():
    usage.record("GET", "locations", status_code=200, cred="aaa")
    usage.record("GET", "locations", status_code=200, cred="bbb")
    assert {r[2] for r in rows()} == {"aaa", "bbb"}
    assert usage.total() == 2


def test_service_and_role_separate_rows_on_one_credential():
    usage.record("GET", "x", status_code=200, cred="aaa", usage_role="cron")
    usage.record("GET", "x", status_code=200, cred="aaa", usage_role="web")
    assert {r[1] for r in rows()} == {"cron", "web"}
    assert [n for _, n in usage.summary(by="cred")] == [2]


def test_missing_cred_is_named_not_blank():
    usage.record("GET", "locations", status_code=200)
    assert rows()[0][2] == "unknown"


# --- readers create nothing ------------------------------------------------

def test_readers_do_not_create_the_database(tmp_path):
    assert usage.total() == 0
    assert usage.summary() == []
    assert usage.counter_exists() is False
    assert not list(tmp_path.glob("u.db*"))


def test_ownership_warning_speaks_when_unwritable(tmp_path, monkeypatch):
    monkeypatch.setenv("ONTIME_USAGE_DB", "/proc/nope/u.db")
    assert usage.ownership_warning() is not None


# --- migration -------------------------------------------------------------

def _make_v1(path):
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE api_usage (
            period TEXT, day TEXT, role TEXT, method TEXT,
            endpoint TEXT, status TEXT, calls INTEGER,
            PRIMARY KEY (period, day, role, method, endpoint, status));
    """)
    conn.execute("INSERT INTO api_usage VALUES"
                 " ('2026-09','2026-09-23','production','GET','locations','2xx',410)")
    conn.execute("INSERT INTO api_usage VALUES"
                 " ('2026-09','2026-09-23','index','GET','locations/{id}','2xx',60)")
    conn.commit(); conn.close()


def test_migration_preserves_every_call_and_names_the_unknown(tmp_path):
    db = str(tmp_path / "old.db")
    _make_v1(db)
    assert usage.schema_version(db) == 1
    note = usage.migrate(db, service_name="ontime")
    assert "470" in note
    assert usage.schema_version(db) == 2
    got = rows(db)
    assert sum(r[6] for r in got) == 470
    assert {r[0] for r in got} == {"ontime"}
    assert {r[2] for r in got} == {"unknown"}
    assert {r[1] for r in got} == {"production", "index"}


def test_migration_is_idempotent_and_safe_on_nothing(tmp_path):
    db = str(tmp_path / "old.db")
    _make_v1(db)
    usage.migrate(db, service_name="ontime")
    assert "already v2" in usage.migrate(db, service_name="ontime")
    assert "nothing to migrate" in usage.migrate(str(tmp_path / "absent.db"),
                                                 service_name="ontime")


def test_a_fresh_database_is_v2():
    usage.record("GET", "locations", status_code=200, cred="aaa")
    assert usage.schema_version(usage.db_path()) == 2
    assert usage.SCHEMA_VERSION == 2
