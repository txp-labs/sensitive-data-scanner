"""Azure Files: every file share, discovered always, read only when opted in.

**Discovery** (`DISCOVER` includes `azure_files`): the storage accounts'
Resource Graph listing that blobs use (a FileStorage account, which has no Blob
service, included), then each account's shares from Resource Manager (Reader),
so a share is in the run summary even when the scanner may not read it. A
store is one share, `account/share`.

**Reading** (`AZURE_FILES_READ=on`, off by default) is the File service's REST
API as the job's identity, with an OAuth token and the **backup intent**
(`x-ms-file-request-intent: backup`), which is how Azure Files takes an Entra
token over REST. The identity needs **Storage File Data Privileged Reader**,
whose data actions are `fileshares/files/read` and
`readFileBackupSemantics/action`: both read. It reads a file whatever its
NTFS ACL says (the backup semantics), which is why it is opt-in, and the
deployment grants it only with `readFileShares`. The files are listed
directory by directory and read the way blobs are (the core's
`scan/objects.py`): ranged reads, table files by column, compressed text
inflated. Nothing is written, leased, closed or snapshotted.

- An NFS share has no REST access: it is `no_read_path`.
- A firewall or private-only account that keeps the job out is `network`; a
  missing role is `access_denied`.
- A pass reads the files modified since the previous complete pass started,
  in path order, and resumes after the last file it read.

**Encryption (1.5):** Azure Files uses the account's key: `Microsoft.Storage`
is `service_managed`; a Key Vault key `customer_managed_key`, hashed.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, apply_rules, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.index import Indexes, ObjectPass, Stale
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.columnar import pyarrow_available
from sensitive_data_core.scan.objects import (
    ObjectResult,
    planned_bytes,
    read_object,
    record,
    sample_point,
)

from ..resources import ResourceId, ShareTarget, azure_fields, file_resource, portal_link
from .base import Context, key_facts
from .blob import STORAGE_ACCOUNTS, STORAGE_API, _account_key_uri, _tags
from .common import http_gap

KIND = "azure_files"
MAX_FILES = 50_000
MAX_DEPTH = 64


class FilesAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        arm = ctx.clients.client("arm")
        for row in ctx.graph(STORAGE_ACCOUNTS):
            endpoint = str(row.get("fileEndpoint") or "")
            if not endpoint:
                continue
            rid = ResourceId.parse(str(row.get("id") or ""))
            account = str(row.get("name") or rid.name)
            facts = key_facts(str(row.get("keySource") or ""), _account_key_uri(row))
            restricted = (
                str(row.get("publicNetworkAccess") or "").lower() == "disabled"
                or str(row.get("defaultAction") or "").lower() == "deny"
            )
            try:
                shares = list(arm.list(f"{rid.value}/fileServices/default/shares", STORAGE_API))
            except Exception as err:  # the account is reported, its shares unknown
                store = Store(KIND, f"{account}/*", tags=_tags(row.get("tags")))
                store.extra.update(azure_fields(rid))
                store.status, store.error = "error", error_name(err)
                store.reason = reason_for(store.error)
                out.stores.append(store)
                continue
            for share in shares:
                name = str(share.get("name") or "")
                if not name:
                    continue
                props = share.get("properties") or {}
                store = Store(KIND, f"{account}/{name}", tags=_tags(row.get("tags")))
                store.extra.update(azure_fields(rid))
                if restricted:
                    store.extra["networkRestricted"] = True
                if props.get("shareUsageBytes") is not None:
                    store.size_bytes = int(props["shareUsageBytes"])
                store.facts = dict(facts)
                store.table = ShareTarget(rid, account, name, endpoint, dict(facts))
                out.stores.append(store)
                if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                    continue
                if str(props.get("enabledProtocols") or "SMB").upper() == "NFS":
                    store.skip("no_read_path")  # an NFS share has no REST access
                elif not ctx.settings.files_read:
                    store.skip("read_not_configured")
                else:
                    pct, _ = ctx.settings.sampling_for(KIND, store.name, store.tags)
                    store.sample_percent = pct if pct is not None else ctx.settings.sample_percent

    def source(self, ctx: Context, store: Store) -> FilesSource | None:
        t = store.table
        if not isinstance(t, ShareTarget):
            return None
        s = ctx.settings
        share = ctx.clients.client("files", t.endpoint).get_share_client(t.share)
        return FilesSource(
            share,
            t,
            sample_percent=store.sample_percent or s.sample_percent,
            max_object_bytes=s.max_object_bytes,
            max_inflated_bytes=s.max_inflated_bytes,
            max_rows=s.columnar_max_rows,
            skew_seconds=s.skew_seconds,
        )


class FilesSource:
    """One share: its files, listed directory by directory, read in path order."""

    kind = KIND
    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(
        self,
        share: Any,
        target: ShareTarget,
        *,
        sample_percent: int = 100,
        max_object_bytes: int = 20 * 1024**2,
        max_inflated_bytes: int = 100 * 1024**2,
        max_rows: int = 10_000,
        skew_seconds: int = 300,
        columnar: bool | None = None,
    ) -> None:
        self.share = share
        self.t = target
        self.sample_percent = sample_percent
        self.max_object_bytes = max_object_bytes
        self.max_inflated_bytes = max_inflated_bytes
        self.max_rows = max_rows
        self.skew = _dt.timedelta(seconds=skew_seconds)
        self.columnar = pyarrow_available() if columnar is None else columnar
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"files:{target.account}/{target.share}"
        self.target = f"{target.account}/{target.share}"

    def __repr__(self) -> str:
        return f"FilesSource({self.t!r})"

    def _files(self) -> list[tuple[str, int, _dt.datetime | None]]:
        """Every file of the share (at most MAX_FILES): its path, size and last change."""
        out: list[tuple[str, int, _dt.datetime | None]] = []
        todo: list[tuple[str, int]] = [("", 0)]
        while todo and len(out) < MAX_FILES:
            directory, depth = todo.pop()
            client = self.share.get_directory_client(directory)
            for item in client.list_directories_and_files(include=["timestamps"]):
                path = f"{directory}/{item.name}" if directory else str(item.name)
                if getattr(item, "is_directory", False):
                    if depth < MAX_DEPTH:
                        todo.append((path, depth + 1))
                    continue
                changed = getattr(item, "last_modified", None) or getattr(
                    item, "last_write_time", None
                )
                out.append((path, int(getattr(item, "size", 0) or 0), changed))
        return sorted(out)

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(KIND, self.target, sample_percent=self.sample_percent)
        watermark = cursor.get("watermark")
        pass_started = cursor.get("passStartedAt") or now.isoformat()
        after = cursor.get("after")
        since = (_dt.datetime.fromisoformat(watermark) - self.skew) if watermark else None
        try:
            files = self._files()
        except Exception as err:  # the share could not be listed
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, kind=KIND, error=cov.error)
            return SourceRun(cov, cursor, note=http_gap(err))
        seen_at = now.isoformat()
        done = True
        generation = int(cursor.get("indexPass") or 0) + (0 if cursor.get("passStartedAt") else 1)
        op = ObjectPass(
            self.indexes,
            self.id,
            self.kind,
            generation=generation,
            columnar=self.columnar,
            budget=budget,
        )
        for path, size, when in files:
            if after is not None and path <= after:
                continue
            cov.listed += 1
            op.seen(path)
            if size == 0:
                after = path
                continue
            marker = f"{size}|{when.isoformat() if when else ''}"
            changed = since is None or when is None or when > since
            decision = op.decide(path, changed=changed, marker=marker)
            if not (decision.read or decision.rescan):
                after = path  # unchanged, and read with what it would be now
                continue
            cov.eligible += int(decision.read)
            if sample_point(path) >= self.sample_percent:
                cov.sampled_out += int(decision.read)
                after = path
                continue
            if decision.rescan:
                op.offer((path, size, marker), decision)  # after this run's changes
                after = path
                continue
            want = planned_bytes(path, size, self.max_object_bytes)
            if not budget.has(want):
                done = False
                break
            budget.take(want)
            self._guarded(path, size, marker, op, cov, detector, store, seen_at)
            after = path
        # Then the rescans this run met, within their capped share (#67).
        for (path, size, marker), why in op.rescans.drain(
            budget, lambda c: planned_bytes(c[0], c[1], self.max_object_bytes)
        ):
            self._guarded(path, size, marker, op, cov, detector, store, seen_at, why)
        op.settle(cov)
        if done:
            cov.pass_complete = True
            op.complete()
            return SourceRun(
                cov, {"watermark": pass_started, "passStartedAt": None, "indexPass": generation}
            )
        cov.backlog = True
        return SourceRun(
            cov,
            {
                "watermark": watermark,
                "passStartedAt": pass_started,
                "after": after,
                "indexPass": generation,
            },
        )

    def _guarded(  # noqa: PLR0917 - one file of the pass
        self,
        path: str,
        size: int,
        marker: str,
        op: ObjectPass,
        cov: Coverage,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        why: Stale | None = None,
    ) -> None:
        """One file read (a change, or a rescan for `why`) and recorded in the index."""
        try:
            got, findings = self._read(
                path, size, cov=cov, detector=detector, store=store, seen_at=seen_at, why=why
            )
            op.record(path, marker=marker, got=got)
            op.rescanned(findings, why)
        except Exception as err:  # one bad file must not stop the pass
            op.record(path, marker=marker, unreadable=True)
            cov.unreadable += 1
            log_event("item.unreadable", source=self.target, error=error_name(err))

    def _read(
        self,
        path: str,
        size: int,
        *,
        cov: Coverage,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        why: Stale | None = None,
    ) -> tuple[ObjectResult, list[dict[str, Any]] | None]:
        client = self.share.get_file_client(path)

        def fetch(start: int, end: int) -> bytes:
            data: bytes = client.download_file(offset=start, length=end - start + 1).readall()
            return data

        got = read_object(
            path,
            size,
            fetch,
            detector,
            max_object_bytes=self.max_object_bytes,
            max_inflated_bytes=self.max_inflated_bytes,
            max_rows=self.max_rows,
            columnar=self.columnar,
        )
        facts = self.facts or self.t.facts
        findings = record(
            got,
            cov,
            resource_for=lambda column: file_resource(self.t, path, column=column),
            link=portal_link(self.t.rid, "fileList"),
            seen_at=seen_at,
            facts=facts,
        )
        if findings is not None:
            for f in findings:
                f.update(why.fields() if why is not None else {})
            store.replace_location(f"{self.id}\n{path}", findings)
        return got, findings

    def prune(self, store: FindingStore, budget: Budget, limit: int = 200) -> int:
        """Drop stored findings whose file is gone."""
        gone = 0
        for location in store.locations(f"{self.id}\n")[:limit]:
            if not budget.time_left():
                break
            path = location.split("\n", 1)[1]
            try:
                self.share.get_file_client(path).get_file_properties()
            except Exception as err:  # unknown: keep the finding
                if error_name(err) in ("ResourceNotFound", "ResourceNotFoundError"):
                    gone += store.remove_location(location)
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        return gone
