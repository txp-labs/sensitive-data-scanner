"""CodeCommit's read path: one file of a commit fetched with GetFile and read by the core's
reader.

This module is `adapter:codecommit` (scripts/components.py): a change here rescans the
objects it read. Listing, discovery and configuration stay in `code.py` (`listing:<kind>`),
whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sensitive_data_core.adapter import Budget, FindingStore
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.index import ObjectPass, Stale
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.objects import planned_bytes, read_object, record

from .exports import merge

if TYPE_CHECKING:
    from .code import CodeCommitSource as _Self

READS = ("codecommit",)


def _read(
    src: _Self,
    path: str,
    commit: str,
    *,
    cov: Coverage,
    budget: Budget,
    detector: Detector,
    store: FindingStore,
    seen_at: str,
    link: str,
    pass_id: str,
    op: ObjectPass | None = None,
    blob: str | None = None,
    why: Stale | None = None,
) -> None:
    try:
        r = src.client.get_file(
            repositoryName=src.repository, commitSpecifier=commit, filePath=path
        )
    except Exception as err:  # one file must not stop the pass
        if op is not None:
            op.record(path, marker=blob, unreadable=True)
        cov.unreadable += 1
        log_event("item.unreadable", source=src.target, error=error_name(err))
        return
    data = bytes(r.get("fileContent") or b"")
    budget.take(planned_bytes(path, len(data), src.max_bytes))
    got = read_object(
        path,
        len(data),
        lambda start, end: data[start : end + 1],
        detector,
        max_object_bytes=src.max_bytes,
        max_inflated_bytes=src.max_inflated_bytes,
        max_rows=0,
        columnar=False,
    )
    findings = record(
        got,
        cov,
        resource_for=lambda _column: store_field_resource(
            service="codecommit", store=src.repository, field=path, read_by="get_file"
        ),
        link=link,
        seen_at=seen_at,
        facts=src.facts,
        offsets=False,
    )
    if op is not None:
        op.record(path, marker=blob, fingerprint=f"git:{blob}" if blob else None, got=got)
        op.rescanned(findings, why)
    for f in findings or []:
        merge(store, f"{src.id}\n{path}", f, pass_id)
