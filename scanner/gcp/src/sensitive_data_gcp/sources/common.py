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
