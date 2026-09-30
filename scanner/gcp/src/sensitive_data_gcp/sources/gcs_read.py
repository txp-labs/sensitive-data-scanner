"""Cloud Storage's read path: one object generation fetched by ranged media GETs and read by
the core's reader.

This module is `adapter:gcs` (scripts/components.py): a change here rescans the objects it
read. Listing, discovery and configuration stay in `gcs.py` (`listing:<kind>`), whose
changes re-list and never re-read (#67).
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import FindingStore
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.index import Stale, md5_fingerprint
from sensitive_data_core.scan.objects import read_object, record

from ..clients import STORAGE_API
from ..resources import console_link, gcs_object_resource
from .base import kms_facts

if TYPE_CHECKING:
    from .gcs import GcsSource as _Self

READS = ("gcs",)


def object_url(bucket: str, name: str) -> str:
    q = urllib.parse.quote
    return f"{STORAGE_API}/b/{q(bucket, safe='')}/o/{q(name, safe='')}"


def gcs_marker(obj: dict[str, Any]) -> str:
    """What changes when an object changes: its generation (a new one per write), and size."""
    return f"{obj.get('generation') or ''}|{obj.get('size') or 0}|{obj.get('updated') or ''}"


def _read(
    src: _Self,
    obj: dict[str, Any],
    *,
    cov: Coverage,
    detector: Detector,
    store: FindingStore,
    seen_at: str,
    why: Stale | None = None,
) -> None:
    name = str(obj.get("name") or "")
    size = int(obj.get("size") or 0)
    generation = str(obj.get("generation") or "") or None
    url = object_url(src.t.bucket, name)

    def fetch(start: int, end: int) -> bytes:
        params = {"alt": "media", **({"generation": generation} if generation else {})}
        resp = src.rest.call("GET", url, params=params, headers={"Range": f"bytes={start}-{end}"})
        data: bytes = resp.content
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
    fingerprint = md5_fingerprint(obj.get("md5Hash"))
    src._op.record(name, marker=gcs_marker(obj), fingerprint=fingerprint, got=got)
    facts = kms_facts(str(obj.get("kmsKeyName") or "") or None)
    where = src.t.where
    link = console_link(
        f"storage/browser/{urllib.parse.quote(src.t.bucket, safe='')}",
        {"project": where.project},
        src.t.bucket,
    )
    findings = record(
        got,
        cov,
        resource_for=lambda column: gcs_object_resource(
            where, src.t.bucket, name, generation, column=column
        ),
        link=link,
        seen_at=seen_at,
        facts=facts,
    )
    src._op.rescanned(findings, why)
    if findings is None:
        return
    location = f"{src.id}\n{name}"
    store.replace_location(location, findings)
