"""Count every outbound API call, at the call site, per credential.

WHY AT THE CALL AND NOT THE LOG. Reads and writes are usually logged in
different shapes -- a read logs ``GET <path> -> <status>``, a write may log only
``"created"``. No grep can tally both, so no log-based count of a credential is
ever complete. Counting happens where the request is issued.

WHY ``role`` AND ``cred`` BOTH. One credential is often shared by several
consumers (a service, a cron job, a sandbox), so ``role`` is the thing this
module knows that the vendor's meter cannot. And one service may use more than
one credential -- a fallback key, a rotation in progress -- so the credential
must be FINGERPRINTED AT THE CALL SITE rather than inferred from which service
made it. Neither field replaces the other.

NOTHING HERE MAY RAISE INTO A CALLER. ``record()`` swallows every exception it
can produce. A counter must never be able to fail the work it is measuring.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import time
from pathlib import Path

log = logging.getLogger("ontime_usage")

SCHEMA_VERSION = 2

# ABSOLUTE by default. A relative path is resolved against the caller's cwd,
# which in a container means one directory when the app runs and a different one
# when a test or a one-off job runs -- both silently, because record() cannot
# raise. Make the caller pass an absolute path or set the environment variable.
DEFAULT_DB = "/data/ontime-usage.db"
DEFAULT_ROLE = "production"
DEFAULT_SERVICE = "unknown"

# Paths whose second segment is a literal, not an id. Without this, "order/post"
# collapses to "order/{id}" and a write is counted under a family that does not
# exist. Per-service, because each API has its own.
DEFAULT_LITERAL_PATHS: frozenset[str] = frozenset()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_usage (
    period   TEXT    NOT NULL,
    day      TEXT    NOT NULL,
    service  TEXT    NOT NULL,
    role     TEXT    NOT NULL,
    cred     TEXT    NOT NULL,
    method   TEXT    NOT NULL,
    endpoint TEXT    NOT NULL,
    status   TEXT    NOT NULL,
    calls    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, day, service, role, cred, method, endpoint, status)
);
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);
INSERT INTO schema_meta (key, value) VALUES ('version', '2')
    ON CONFLICT(key) DO NOTHING;
"""

_literal_paths: frozenset[str] = DEFAULT_LITERAL_PATHS


def configure(*, literal_paths: frozenset[str] | set[str] | None = None) -> None:
    """Declare this service's non-id path segments. Call once at import time."""
    global _literal_paths
    if literal_paths is not None:
        _literal_paths = frozenset(literal_paths)


# --- identity --------------------------------------------------------------

def fingerprint(secret: str | None) -> str:
    """A short, stable, NON-REVERSIBLE label for a credential.

    THE KEY ITSELF IS NEVER STORED, LOGGED OR RETURNED. Twelve hex characters of
    sha256 is enough to tell two credentials apart and to watch one replace
    another during a rotation, and is useless to anyone who obtains the database.
    """
    if not secret:
        return "none"
    # errors="replace": this runs at startup, OUTSIDE record()'s catch-all,
    # so a key carrying an odd byte must not be able to raise here.
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:12]


def enabled() -> bool:
    return os.environ.get("ONTIME_USAGE_ENABLED", "true").strip().lower() not in (
        "0", "false", "no", "off",
    )


def role() -> str:
    return (os.environ.get("ONTIME_USAGE_ROLE") or DEFAULT_ROLE).strip() or DEFAULT_ROLE


def service() -> str:
    return (os.environ.get("ONTIME_USAGE_SERVICE") or DEFAULT_SERVICE).strip() or DEFAULT_SERVICE


def db_path() -> str:
    return (os.environ.get("ONTIME_USAGE_DB") or DEFAULT_DB).strip() or DEFAULT_DB


# --- shaping ---------------------------------------------------------------

def endpoint_family(path: str) -> str:
    """``locations/3f2a-...`` -> ``locations/{id}``; ``locations`` -> ``locations``.

    Collapsing ids is what keeps the table bounded: a handful of families times
    a few statuses times two methods times 31 days is a couple of thousand rows
    a month, not one per request.
    """
    cleaned = (path or "").strip().strip("/")
    if not cleaned:
        return "(empty)"
    if cleaned in _literal_paths:
        return cleaned
    parts = cleaned.split("/")
    if len(parts) == 1:
        return parts[0]
    return f"{parts[0]}/{{id}}"


def status_bucket(status_code: int | None = None, *, error: bool = False) -> str:
    """``429`` is its OWN bucket, never folded into ``4xx``.

    A quota refusal is the one client error that means "stop", and a tally that
    hides it inside a generic 4xx count will not show a ceiling approaching.
    """
    if error or status_code is None:
        return "error"
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return "error"
    if code == 429:
        return "429"
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if code >= 500:
        return "5xx"
    return "other"


def _stamps() -> tuple[str, str]:
    """(period, day), both UTC, and saying so is the point.

    Whose calendar month a vendor means is rarely documented, so a
    boundary-day discrepancy of a few calls is a timezone artifact, not a bug.
    """
    now = time.gmtime()
    return time.strftime("%Y-%m", now), time.strftime("%Y-%m-%d", now)


# --- storage ---------------------------------------------------------------

def _connect(path: str) -> sqlite3.Connection:
    """WAL and a busy timeout, because writers really can be concurrent.

    A long-running process and a short-lived one-off job often bind-mount the
    same data directory and overlap.
    """
    parent = Path(path).expanduser().parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    return conn


def _connect_ro(path: str) -> sqlite3.Connection:
    """READERS NEVER OPEN THIS FILE READ-WRITE.

    The counter's failure mode is deliberate silence -- record() swallows its
    own exceptions -- so anything that makes the file unwritable makes it stop
    counting without saying so. _connect() creates files and sets WAL mode: run
    a reader as a different user and it leaves that user's -wal and -shm beside
    a database the writer then cannot use. mode=ro creates nothing.
    """
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)


def record(method: str, path: str, *, status_code: int | None = None,
           error: bool = False, cred: str | None = None,
           usage_role: str | None = None, usage_service: str | None = None,
           database: str | None = None) -> None:
    """Increment one counter. NEVER RAISES. Returns nothing useful.

    `cred` is a FINGERPRINT, not a key -- pass fingerprint(the_key). Passing a
    real key here would write it to disk, so the parameter is named for what it
    should contain and callers should compute it once at client construction.
    """
    if not enabled():
        return
    try:
        period, day = _stamps()
        conn = _connect(database or db_path())
        try:
            conn.execute(
                "INSERT INTO api_usage"
                " (period, day, service, role, cred, method, endpoint, status, calls)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)"
                " ON CONFLICT(period, day, service, role, cred, method, endpoint, status)"
                " DO UPDATE SET calls = calls + 1",
                (period, day, usage_service or service(), usage_role or role(),
                 cred or "unknown", (method or "?").upper(),
                 endpoint_family(path), status_bucket(status_code, error=error)),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        log.exception("usage: increment failed; ignored")


# --- migration -------------------------------------------------------------

def schema_version(path: str) -> int:
    """0 when there is no database, 1 for the pre-`cred` layout, else the stamp."""
    if not Path(path).exists():
        return 0
    conn = _connect_ro(path)
    try:
        try:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key='version'").fetchone()
            if row:
                return int(row[0])
        except sqlite3.OperationalError:
            pass
        cols = {r[1] for r in conn.execute("PRAGMA table_info(api_usage)")}
        if not cols:
            return 0
        return 2 if "cred" in cols else 1
    finally:
        conn.close()


def migrate(path: str, *, service_name: str) -> str:
    """v1 -> v2, in place. Returns a one-line description of what it did.

    SQLite cannot ALTER a PRIMARY KEY, so this rebuilds the table. Rows that
    predate the fingerprint get cred='unknown' -- NOT an empty string, because a
    reader must be able to say "unknown" rather than print a blank and let
    somebody read it as zero.

    TAKE A BACKUP FIRST. The caller is expected to have done so; this does not,
    because a library that silently writes extra files is worse than one that
    asks.
    """
    version = schema_version(path)
    if version == 0:
        return "no database; nothing to migrate"
    if version >= 2:
        return "already v2; nothing to do"
    conn = sqlite3.connect(path, timeout=10.0)
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        before = conn.execute("SELECT COALESCE(SUM(calls),0) FROM api_usage").fetchone()[0]
        conn.executescript("""
            ALTER TABLE api_usage RENAME TO api_usage_v1;
        """)
        conn.executescript(_SCHEMA)
        conn.execute(
            "INSERT INTO api_usage"
            " (period, day, service, role, cred, method, endpoint, status, calls)"
            " SELECT period, day, ?, role, 'unknown', method, endpoint, status, calls"
            " FROM api_usage_v1",
            (service_name,),
        )
        after = conn.execute("SELECT COALESCE(SUM(calls),0) FROM api_usage").fetchone()[0]
        if after != before:                       # pragma: no cover - guard
            conn.rollback()
            raise RuntimeError(
                f"migration would have changed the total: {before} -> {after}")
        conn.execute("DROP TABLE api_usage_v1")
        conn.commit()
        return f"migrated v1 -> v2, {before} calls preserved, cred='unknown'"
    finally:
        conn.close()


# --- readers ---------------------------------------------------------------

def current_period() -> str:
    return _stamps()[0]


def counter_exists(database: str | None = None) -> bool:
    return Path(database or db_path()).exists()


def summary(*, period: str | None = None, by: str = "cred",
            database: str | None = None) -> list[tuple[str, int]]:
    """Rows of (label, calls), busiest first. RAISES -- this one is a reader."""
    column = {"cred": "cred", "service": "service", "role": "role",
              "endpoint": "endpoint", "day": "day", "status": "status",
              "method": "method"}.get(by)
    if column is None:
        raise ValueError(f"cannot group by {by!r}")
    target = database or db_path()
    period = period or current_period()
    if not Path(target).exists():
        return []
    conn = _connect_ro(target)
    try:
        rows = conn.execute(
            f"SELECT {column}, SUM(calls) FROM api_usage"
            " WHERE period = ? GROUP BY 1 ORDER BY 2 DESC", (period,)).fetchall()
    except sqlite3.OperationalError:
        return []            # file exists, table does not: nothing counted yet
    finally:
        conn.close()
    return [(str(a), int(b)) for a, b in rows]


def total(*, period: str | None = None, database: str | None = None) -> int:
    target = database or db_path()
    if not Path(target).exists():
        return 0
    conn = _connect_ro(target)
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(calls),0) FROM api_usage WHERE period = ?",
            (period or current_period(),)).fetchone()
        return int(row[0]) if row else 0
    except sqlite3.OperationalError:
        return 0
    finally:
        conn.close()


def ownership_warning(database: str | None = None) -> str | None:
    """Say it out loud when the counter is present but not writable by us.

    record() swallows PermissionError, so a counter owned by the wrong user
    stops counting and nothing says so.

    THE SIDECARS MATTER AS MUCH AS THE DATABASE. Readers open `mode=ro` so they
    cannot create the database itself, but SQLite still builds `-shm` and `-wal`
    in order to READ a WAL file — so a reader run as another user (a test suite
    as root, a one-off job) can leave sidecars beside a perfectly writable
    database that the writing service then cannot use. That cannot be prevented
    from inside a reader, so it is reported instead.
    """
    try:
        path = Path(database or db_path())
        if not path.exists():
            parent = path.parent
            if not parent.exists():
                return f"{parent} does not exist - nothing can be counted."
            if not os.access(parent, os.W_OK):
                return (f"{parent} is not writable by this process "
                        f"(uid {os.getuid()}) - the counter cannot be created.")
            return None
        unwritable = [p.name for p in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
                      if p.exists() and not os.access(p, os.W_OK)]
        if not unwritable:
            return None
        return ("counter files are NOT writable by this user: "
                + ", ".join(unwritable)
                + " - record() would fail silently and the count would stop")
    except Exception:                              # pragma: no cover - guard
        return None
