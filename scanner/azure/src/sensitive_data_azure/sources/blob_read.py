"""Blob Storage's read path: one blob (one version) fetched by ranged Get Blob reads and read
by the core's reader, with the encryption it is stored under.

This module is `adapter:azure_blob` (scripts/components.py): a change here rescans the
objects it read. Listing, discovery and configuration stay in `blob.py` (`listing:<kind>`),
whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

import datetime as _dt
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import FindingStore
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.index import Stale, md5_fingerprint
from sensitive_data_core.scan.objects import read_object, record

from ..resources import blob_resource, portal_link

if TYPE_CHECKING:
    from .blob import BlobSource as _Self

READS = ("azure_blob",)


def blob_marker(props: Any) -> str:
    """What changes when a blob changes: its ETag, size and last-modified time."""
    modified = getattr(props, "last_modified", None)
    when = modified.isoformat() if isinstance(modified, _dt.datetime) else str(modified or "")
    return f"{getattr(props, 'etag', '') or ''}|{getattr(props, 'size', 0) or 0}|{when}"


def blob_fingerprint(props: Any) -> str | None:
    settings = getattr(props, "content_settings", None)
    return md5_fingerprint(getattr(settings, "content_md5", None))


def _blob_facts(src: _Self, props: Any) -> dict[str, Any] | None:
    scope = str(getattr(props, "encryption_scope", None) or "")
    if scope and scope in src.t.scopes:
        return dict(src.t.scopes[scope])
    if scope:
        return {"atRestEncryption": "unknown"}  # a scope created after discovery
    return src.facts or src.t.default or None


def _read(
    src: _Self,
    props: Any,
    *,
    cov: Coverage,
    detector: Detector,
    store: FindingStore,
    seen_at: str,
    why: Stale | None = None,
) -> None:
    name = str(props.name)
    size = int(getattr(props, "size", 0) or 0)
    version = getattr(props, "version_id", None) or None

    def fetch(start: int, end: int) -> bytes:
        kwargs: dict[str, Any] = {"offset": start, "length": end - start + 1}
        if version:
            kwargs["version_id"] = version
        data: bytes = src.container.download_blob(name, **kwargs).readall()
        return data

    got = read_object(
        name,
        size,
        fetch,
        detector,
        max_object_bytes=src.max_object_bytes,
        max_inflated_bytes=src.max_inflated_bytes,
        max_rows=src.max_rows,
        columnar=src.columnar,
    )
    fingerprint = blob_fingerprint(props)
    src._op.record(name, marker=blob_marker(props), fingerprint=fingerprint, got=got)
    facts = src._blob_facts(props)
    link = portal_link(src.t.rid, "containersList")
    findings = record(
        got,
        cov,
        resource_for=lambda column: blob_resource(src.t, name, version, column=column),
        link=link,
        seen_at=seen_at,
        facts=facts,
    )
    src._op.rescanned(findings, why)
    if findings is None:
        return
    location = f"{src.id}\n{name}"
    store.replace_location(location, findings)
