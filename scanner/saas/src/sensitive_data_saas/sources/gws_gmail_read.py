"""Gmail's attachment read path: a message's attachments fetched and read by the core's
readers, each recorded by its stable id. Message bodies are never rescanned (#67), so their
reading stays with the listing.

This module is `adapter:gws_gmail` (scripts/components.py): a change here rescans the
objects it read. Listing, discovery and configuration stay in `gws_gmail.py`
(`listing:<kind>`), whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

import base64
import binascii
from typing import TYPE_CHECKING, Any

from ..resources import saas_item
from .base import (
    ItemReader,
    bytes_fetch,
)
from .gws import VENDOR

if TYPE_CHECKING:
    from .gws_gmail import GmailSource as _Self

SERVICE = "gmail"
GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"


def _parts(part: dict[str, Any]) -> list[dict[str, Any]]:
    out = [part]
    for p in part.get("parts") or []:
        if isinstance(p, dict):
            out.extend(_parts(p))
    return out


READS = ("gws_gmail",)


def b64(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError):
        return b""


def _files(msg: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    """A message's attachments: its parts with a file name, with their place among its
    parts."""
    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    return [(n, p) for n, p in enumerate(_parts(payload or {})) if p.get("filename")]


def attachment_id(mid: str, n: int, p: dict[str, Any]) -> str:
    """An attachment's stable id: its message's and its part's (Gmail's attachment ids
    change from one read to the next)."""
    return f"{mid}/{p.get('partId') or n}"


def _attachments(src: _Self, mid: str, msg: dict[str, Any], r: ItemReader) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    max_bytes = src.ctx.settings.max_object_bytes
    for n, p in _files(msg):
        if int((p.get("body") or {}).get("size") or 0) > max_bytes:
            r.skip("too_large")
            continue
        out.extend(src._attachment(mid, n, p, r))
    return out


def _attachment(
    src: _Self, mid: str, n: int, p: dict[str, Any], r: ItemReader
) -> list[dict[str, Any]]:
    """One attachment (part `p`, the message's `n`th) read, and recorded in the index by
    its stable id."""
    name = str(p.get("filename") or "")
    body = p.get("body") or {}
    if body.get("attachmentId"):
        got = src.api.get(f"{GMAIL}/messages/{mid}/attachments/{body['attachmentId']}")
        data = b64(str(got.get("data") or ""))
    else:
        data = b64(str(body.get("data") or ""))
    item_id = attachment_id(mid, n, p)

    def resource_for(column: str | None) -> Any:
        return saas_item(
            VENDOR,
            SERVICE,
            src.tenant,
            item_id,
            "attachment",
            owner=src.person.principal_hash,
            name=name,
            column=column,
        )

    found = r.file(
        name, len(data), bytes_fetch(data), resource_for=resource_for, link=None, key=item_id
    )
    r.budget.bytes += len(data)
    return found
