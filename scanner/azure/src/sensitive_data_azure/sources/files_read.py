"""Azure Files' read path: one file fetched by ranged reads and read by the core's reader.

This module is `adapter:azure_files` (scripts/components.py): a change here rescans the
objects it read. Listing, discovery and configuration stay in `files.py` (`listing:<kind>`),
whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import FindingStore
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.index import Stale
from sensitive_data_core.scan.objects import (
    ObjectResult,
    read_object,
    record,
)

from ..resources import file_resource, portal_link

if TYPE_CHECKING:
    from .files import FilesSource as _Self

READS = ("azure_files",)


def _read(
    src: _Self,
    path: str,
    size: int,
    *,
    cov: Coverage,
    detector: Detector,
    store: FindingStore,
    seen_at: str,
    why: Stale | None = None,
) -> tuple[ObjectResult, list[dict[str, Any]] | None]:
    client = src.share.get_file_client(path)

    def fetch(start: int, end: int) -> bytes:
        data: bytes = client.download_file(offset=start, length=end - start + 1).readall()
        return data

    got = read_object(
        path,
        size,
        fetch,
        detector,
        max_object_bytes=src.max_object_bytes,
        max_inflated_bytes=src.max_inflated_bytes,
        max_rows=src.max_rows,
        columnar=src.columnar,
    )
    facts = src.facts or src.t.facts
    findings = record(
        got,
        cov,
        resource_for=lambda column: file_resource(src.t, path, column=column),
        link=portal_link(src.t.rid, "fileList"),
        seen_at=seen_at,
        facts=facts,
    )
    if findings is not None:
        for f in findings:
            f.update(why.fields() if why is not None else {})
        store.replace_location(f"{src.id}\n{path}", findings)
    return got, findings
