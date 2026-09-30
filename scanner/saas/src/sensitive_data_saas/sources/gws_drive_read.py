"""Drive's read path: one file downloaded by ranged reads (or a Google document exported as
text) and read by the core's reader, or its findings copied from a file with the same bytes.

This module is `adapter:gws_drive`, `adapter:gws_shared_drive` (scripts/components.py): a
change here rescans the objects it read. Listing, discovery and configuration stay in
`gws_drive.py` (`listing:<kind>`), whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

from sensitive_data_core.findings import Link
from sensitive_data_core.index import Stale, md5_fingerprint
from sensitive_data_core.safety import error_name, log_event

from ..resources import saas_item
from .base import ItemReader, bytes_fetch
from .gws import VENDOR

if TYPE_CHECKING:
    from .gws_drive import DriveSource as _Self

READS = ("gws_drive", "gws_shared_drive")


DRIVE = "https://www.googleapis.com/drive/v3"


EXPORTS = {
    "application/vnd.google-apps.document": ("text/plain", ".txt"),
    "application/vnd.google-apps.spreadsheet": ("text/csv", ".csv"),
    "application/vnd.google-apps.presentation": ("text/plain", ".txt"),
}


MAX_EXPORT_BYTES = 10 * 1024 * 1024  # Drive's own limit on an export


def drive_link(file_id: str) -> Link:
    q = urllib.parse.urlencode({"id": file_id})
    return Link(f"https://drive.google.com/open?{q}", (file_id,))


def file_marker(f: dict[str, Any]) -> str:
    """What changes when a Drive file changes: its version (bumped on every change), its
    modified time and size."""
    return f"{f.get('version') or ''}|{f.get('modifiedTime') or ''}|{f.get('size') or 0}"


def _read_file(
    src: _Self, f: dict[str, Any], r: ItemReader, *, why: Stale | None = None, charged: bool = False
) -> None:
    """One file read (a change, or a rescan for `why`; `charged`: its budget is taken)."""
    fid = str(f.get("id") or "")
    name = str(f.get("name") or "file")
    export = EXPORTS.get(str(f.get("mimeType") or ""))
    size = int(f.get("size") or 0)
    link = drive_link(fid)

    def resource_for(column: str | None) -> dict[str, Any]:
        return saas_item(
            VENDOR,
            src.service,
            src.tenant,
            fid,
            "file",
            owner=src.owner,
            container=src.drive.name if src.drive is not None else None,
            name=name,
            column=column,
        )

    if export is None:
        fingerprint = md5_fingerprint(f.get("md5Checksum"))
        prefix = f"{src.id}\n"
        copied = r.duplicate(
            fid, name, fingerprint, file_marker(f), resource_for, link, prefix, why
        )
        if copied is not None:
            r.store.replace_location(f"{src.id}\n{fid}", copied)  # the same bytes
            return
    scope = {"supportsAllDrives": "true"} if src.drive is not None else {}
    try:
        if export is not None:
            mime_out, suffix = export
            resp = src.api.call(f"{DRIVE}/files/{fid}/export", {"mimeType": mime_out, **scope})
            data: bytes = resp.content[:MAX_EXPORT_BYTES]
            if not charged:
                r.budget.take(len(data))
            findings = r.file(
                name + suffix,
                len(data),
                bytes_fetch(data),
                resource_for=resource_for,
                link=link,
                key=fid,
                marker=file_marker(f),
            )
        else:
            if not charged:
                r.budget.take(min(size, src.ctx.settings.max_object_bytes))

            def fetch(start: int, end: int) -> bytes:
                return src.api.download(
                    f"{DRIVE}/files/{fid}", start, end, {"alt": "media", **scope}
                )

            findings = r.file(
                name,
                size,
                fetch,
                resource_for=resource_for,
                link=link,
                key=fid,
                marker=file_marker(f),
                fingerprint=md5_fingerprint(f.get("md5Checksum")),
            )
    except Exception as err:  # one file must not stop the pass
        if r.index is not None:
            r.index.record(fid, marker=file_marker(f), unreadable=True)
        r.cov.unreadable += 1
        log_event("item.unreadable", source=src.target, error=error_name(err))
        return
    if r.index is not None:
        r.index.rescanned(findings, why)
    r.store.replace_location(f"{src.id}\n{fid}", findings)
