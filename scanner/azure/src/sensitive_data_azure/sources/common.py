"""What Azure's sampled sources share: plain values, merged findings, and why a call failed."""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import decimal
from collections.abc import Iterable
from typing import Any

from sensitive_data_core.findings import ClassFinding
from sensitive_data_core.safety import error_name
from sensitive_data_core.scan.item import ItemResult, looks_binary

_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
# The data plane's answers when a store's network rules keep the caller out.
NETWORK_ERRORS = frozenset({"AuthorizationFailure", "AuthorizationSourceIPMismatch"})
# Words in a 403's message that say it was the network, not a role. Only looked at here.
_NETWORK_HINTS = (
    "firewall",
    "public internet",
    "private endpoint",
    "virtual network",
    "ip address",
)


def plain(v: Any, depth: int = 0) -> Any:
    """A stored value as the scanner reads it: text, numbers, dates; binary dropped."""
    if depth > 20:
        return None
    inner = getattr(v, "value", v)  # an Azure Tables EntityProperty
    if inner is not v:
        return plain(inner, depth + 1)
    if v is None or isinstance(v, str | bool | int | float | decimal.Decimal | _dt.date):
        return v
    if isinstance(v, dict):
        return {str(k): plain(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [plain(x, depth + 1) for x in v]
    return None  # bytes, GUIDs and anything else that is not text a person typed


def _printable(text: str) -> bool:
    return all(c.isprintable() or c in "\n\r\t" for c in text)


def message_text(content: Any) -> str | None:
    """A queue message's text: as sent, or base64-decoded when that gives printable text
    (how the Storage SDKs encode a message by default). None for binary."""
    if isinstance(content, bytes):
        if looks_binary(content[:4096]):
            return None
        return content.decode("utf-8", errors="replace")
    text = str(content or "")
    try:
        raw = base64.b64decode(text, validate=True) if len(text) >= 8 else b""
    except (binascii.Error, ValueError):
        return text
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return text
    return decoded if decoded and _printable(decoded) else text


def merge_items(items: Iterable[ItemResult]) -> dict[str, ClassFinding]:
    """Several items' findings as one field's (a queue's messages): counts added up."""
    out: dict[str, ClassFinding] = {}
    for item in items:
        for cls, cf in item.findings.items():
            m = out.setdefault(cls, ClassFinding(cls))
            first = m.occurrences == 0
            m.count += cf.count
            m.occurrences += cf.occurrences
            m.via |= cf.via
            for k, n in cf.confidence_counts.items():
                m.confidence_counts[k] = m.confidence_counts.get(k, 0) + n
            if first or _CONF_RANK[cf.confidence] > _CONF_RANK[m.confidence]:
                m.confidence = cf.confidence
    return out


def http_gap(err: BaseException) -> str | None:
    """`network` or `access_denied` for a data-plane 403, else None. Never keeps the message."""
    name = error_name(err)
    if name in NETWORK_ERRORS:
        return "network"
    status = getattr(err, "status_code", None)
    if status == 403 or name in ("Forbidden", "AuthorizationPermissionMismatch"):
        text = str(err).lower()
        return "network" if any(h in text for h in _NETWORK_HINTS) else "access_denied"
    return None
