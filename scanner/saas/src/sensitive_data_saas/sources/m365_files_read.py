"""SharePoint's and OneDrive's read path: one file downloaded by ranged reads of its content
and read by the core's reader, or its findings copied from a file with the same bytes.

This module is `adapter:m365_sharepoint`, `adapter:m365_onedrive` (scripts/components.py): a
change here rescans the objects it read. Listing, discovery and configuration stay in
`m365_files.py` (`listing:<kind>`), whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sensitive_data_core.index import Stale
from sensitive_data_core.safety import error_name, log_event

from ..resources import saas_item, sharepoint_link
from .base import ItemReader

if TYPE_CHECKING:
    from .m365_files import Drive
    from .m365_files import DriveSource as _Self

READS = ("m365_sharepoint", "m365_onedrive")


def item_marker(item: dict[str, Any]) -> str:
    """What changes when a drive item's content changes: its content tag (`cTag`), modified
    time and size."""
    return (
        f"{item.get('cTag') or ''}|{item.get('lastModifiedDateTime') or ''}|{item.get('size') or 0}"
    )


def item_fingerprint(item: dict[str, Any]) -> str | None:
    """The file's own hash from the listing: SHA-1 where Graph gives it, else QuickXorHash
    (SharePoint and OneDrive for Business), each in its own namespace."""
    f = item.get("file") if isinstance(item.get("file"), dict) else {}
    hashes = (f or {}).get("hashes") if isinstance((f or {}).get("hashes"), dict) else {}
    for name, prefix in (("sha1Hash", "sha1"), ("quickXorHash", "qxh")):
        v = (hashes or {}).get(name)
        if isinstance(v, str) and v.strip():
            return f"{prefix}:{v.strip().lower()}"
    return None


def _read_item(
    src: _Self, drive: Drive, item: dict[str, Any], r: ItemReader, why: Stale | None = None
) -> None:
    """One file read (a change, or a rescan for `why`) and its findings stored."""
    iid = str(item.get("id") or "")
    size = int(item.get("size") or 0)
    location = f"{src.id}\n{iid}"
    name = str(item.get("name") or "file")
    ids = item.get("sharepointIds") if isinstance(item.get("sharepointIds"), dict) else {}
    link = sharepoint_link(drive.host, str((ids or {}).get("listItemUniqueId") or ""))
    path = f"/drives/{drive.drive_id}/items/{iid}/content"

    def fetch(start: int, end: int) -> bytes:
        return src.graph.download(path, start, end)

    def resource_for(column: str | None) -> dict[str, Any]:
        return saas_item(
            "m365",
            src.service,
            src.tenant,
            iid,
            "file",
            owner=src.owner.principal_hash if src.owner else None,
            container=src.container,
            channel=drive.name or None,
            name=name,
            column=column,
        )

    fingerprint = item_fingerprint(item)
    prefix = f"{src.id}\n"
    copied = r.duplicate(iid, name, fingerprint, item_marker(item), resource_for, link, prefix, why)
    if copied is not None:
        r.store.replace_location(location, copied)  # the same bytes as a file read
        return
    try:
        findings = r.file(
            name,
            size,
            fetch,
            resource_for=resource_for,
            link=link,
            key=iid,
            marker=item_marker(item),
            fingerprint=item_fingerprint(item),
        )
    except Exception as err:  # one file must not stop the pass
        if r.index is not None:
            r.index.record(iid, marker=item_marker(item), unreadable=True)
        r.cov.unreadable += 1
        log_event("item.unreadable", source=src.target, error=error_name(err))
        return
    if r.index is not None:
        r.index.rescanned(findings, why)
    r.store.replace_location(location, findings)
