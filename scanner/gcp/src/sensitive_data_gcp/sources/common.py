"""What Google Cloud's sources share: why a call failed, as a store's gap."""

from __future__ import annotations

from sensitive_data_core.safety import error_name

# A service perimeter (VPC Service Controls) refused the call: the job is not inside it.
NETWORK_ERRORS = frozenset({"VPC_SERVICE_CONTROLS"})
DENIED_ERRORS = frozenset({"PERMISSION_DENIED"})


def call_gap(err: BaseException) -> str | None:
    """`network`, `requester_pays` or `access_denied` for a refused call, else None."""
    name = error_name(err)
    if name in NETWORK_ERRORS:
        return "network"
    if name == "USER_PROJECT_MISSING":
        return "requester_pays"
    if name in DENIED_ERRORS:
        return "access_denied"
    return None


# What a driver's message says when the database could not be reached, or refused the
# login. The message is only looked at here, never kept, logged or returned.
_NETWORK_HINTS = (
    "timeout",
    "timed out",
    "could not connect",
    "can't connect",
    "connection refused",
    "unreachable",
    "no route to host",
    "name or service not known",
    "could not translate host",
    "nodename nor servname",
    "08001",
)
_DENIED_HINTS = (
    "password authentication failed",
    "authentication failed",
    "login failed",
    "no pg_hba.conf entry",
    "28000",
    "28p01",
    "1045",  # MySQL: access denied
    "access denied",
    "cloudsql.instances.login",
    "alloydb.users.login",
)


def connect_gap(err: BaseException) -> str | None:
    """`network`, `access_denied`, or None, from a connect error. Never keeps the message."""
    gap = call_gap(err)
    if gap is not None:
        return gap
    text = str(err).lower()
    name = error_name(err).lower()
    if any(h in text for h in _NETWORK_HINTS) or "timeout" in name:
        return "network"
    if any(h in text for h in _DENIED_HINTS):
        return "access_denied"
    return None
