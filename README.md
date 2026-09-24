# ontime-usage

A very small, dependency-free counter for outbound API calls. It answers one
question that logs usually cannot: **how many calls did each credential make,
and who made them.**

```python
import os
import ontime_usage as usage

usage.configure(literal_paths={"order/post"})
CRED = usage.fingerprint(os.environ["MY_API_KEY"])   # once, at startup

r = client.get(path)
usage.record("GET", path, status_code=r.status_code, cred=CRED)
```

## Why it exists

A vendor's monthly meter tells you the account total and nothing else. When
several applications share one account — and sometimes one credential — that
number cannot tell you which of them to fix. This records the same events at the
point they are issued, so the account total can be attributed.

## The four decisions worth knowing

**It counts at the call, not from logs.** Reads and writes are usually logged in
different shapes, so no single grep tallies both, and any log-derived count of a
credential is incomplete by construction.

**The credential is fingerprinted at the call site.** Twelve hex characters of
`sha256`, never the key. Which service made a call does *not* reliably tell you
which key paid for it — fallbacks and rotations break that assumption — so the
key in the client's own header is what gets identified. A test asserts the
secret never reaches the database file.

**Both `role` and `cred` are recorded.** One credential shared by several
consumers needs `role` to stay attributable; one service using more than one
credential needs `cred`. Neither field substitutes for the other.

**It cannot raise.** `record()` swallows everything. A counter must never be
able to fail the work it measures — which also means an unwritable database
fails *silently*, so `ownership_warning()` exists to ask on purpose, and readers
open the file `mode=ro` so they can never create a file the writer then cannot
use.

`429` is kept as its own status bucket rather than folded into `4xx`: it is the
one client error that means *stop*, and a tally that hides it will not show a
ceiling approaching.

## Storage

One SQLite file per service, `PRIMARY KEY (period, day, service, role, cred,
method, endpoint, status)`, upserted. Ids in paths collapse to `{id}` so the
table stays bounded; declare any literal segments with `configure()`.

Give it an absolute path. A relative one resolves against the caller's working
directory, which in a container means one place for the app and another for a
one-off job — both silently.

## Migrating an older database

`migrate(path, service_name=...)` rebuilds a pre-`cred` table in place, tagging
existing rows `cred='unknown'` — named, not blank, so nobody reads a gap as a
zero. It verifies the call total is unchanged and refuses if it is not. **Take
your own backup first**; a library that silently writes extra files is worse
than one that asks.

## Environment

    ONTIME_USAGE_DB        absolute path to the sqlite file
    ONTIME_USAGE_SERVICE   which application this is
    ONTIME_USAGE_ROLE      which consumer within it
    ONTIME_USAGE_ENABLED   false/0/no/off disables it entirely

## Tests

    python -m pytest -q
