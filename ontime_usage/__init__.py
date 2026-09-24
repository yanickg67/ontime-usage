"""A small, shared API-usage counter.

    import ontime_usage as usage

    usage.configure(literal_paths={"order/post"})
    CRED = usage.fingerprint(os.environ["MY_API_KEY"])     # once, at startup

    usage.record("GET", path, status_code=response.status_code, cred=CRED)

Environment:

    ONTIME_USAGE_DB        absolute path to the sqlite file
    ONTIME_USAGE_SERVICE   which application this is
    ONTIME_USAGE_ROLE      which consumer within it (service, cron, sandbox...)
    ONTIME_USAGE_ENABLED   false/0/no/off to disable entirely
"""

from .counter import (                                        # noqa: F401
    SCHEMA_VERSION,
    configure,
    counter_exists,
    current_period,
    db_path,
    enabled,
    endpoint_family,
    fingerprint,
    migrate,
    ownership_warning,
    record,
    role,
    schema_version,
    service,
    status_bucket,
    summary,
    total,
)

__version__ = "1.0.1"

__all__ = [
    "SCHEMA_VERSION", "__version__", "configure", "counter_exists",
    "current_period", "db_path", "enabled", "endpoint_family", "fingerprint",
    "migrate", "ownership_warning", "record", "role", "schema_version",
    "service", "status_bucket", "summary", "total",
]
