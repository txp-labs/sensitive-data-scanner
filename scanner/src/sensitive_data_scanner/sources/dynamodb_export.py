"""DynamoDB Export to S3: a table too large to Scan, read from a point-in-time export.

An export uses no read capacity and reads the table as it was at one moment.
It needs point-in-time recovery (PITR) on the table; discovery reports a
large table without PITR (`pitr_off`) instead of exporting it.

1. Start `ExportTableToPointInTime` (DynamoDB JSON) to the results bucket's
   `exports/dynamodb/` prefix, within `MAX_EXPORTS_PER_RUN` and no sooner than
   `EXPORT_MIN_INTERVAL_DAYS` after the last one.
2. Wait for it (`DescribeExport`).
3. Read its `data/*.json.gz` files, one item per line, attribute by attribute
   like the DynamoDB source (the same `dynamodb_item` findings, keyed by a
   salted hash), across as many runs as the budget needs.
4. Delete the export, and drop findings the new export no longer has.

**Then only what changed** (#67). With `DYNAMODB_INCREMENTAL` (on), each later
export is an incremental one (`ExportType=INCREMENTAL_EXPORT`, `NEW_IMAGE`):
the items written since the last export's point in time, at most 24 hours of
them per export (AWS's limit), one window a run until it catches up. A changed
item's findings are replaced; a deleted item's are dropped. A full export comes
again only when the table's recorded components are stale (a rescan, within
the rescan share: the attribute reader, the adapter or the spec changed), or
when the last export is older than point-in-time recovery keeps (35 days).
"""

from __future__ import annotations

import datetime as _dt
import gzip
import hashlib
import hmac
import json
import secrets
import zlib
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, finding_json
from sensitive_data_core.index import UNINDEXED, Indexes, ObjectPass, Stale
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.attributes import FORMAT, AttributeRules, key_value, scan_attributes

from ..resources import dynamodb_link, dynamodb_resource
from .exports import ExportQuota, delete_prefix, drop_other_passes, due, list_keys


def _time(v: Any) -> _dt.datetime | None:
    try:
        return _dt.datetime.fromisoformat(str(v)) if v else None
    except ValueError:
        return None


if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient
    from mypy_boto3_s3 import S3Client


# AWS: an incremental export covers 15 minutes to 24 hours; its start must be inside the
# point-in-time recovery window (35 days at most).
INCREMENTAL_MIN = _dt.timedelta(minutes=15)
INCREMENTAL_MAX = _dt.timedelta(hours=24)
PITR_WINDOW = _dt.timedelta(days=34)


class DynamoDBExportSource:
    # The table's own encryption (1.5), from discovery (runner.plan): not the export's.
    facts: dict[str, Any] | None = None
    kind = "dynamodb"
    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(
        self,
        client: DynamoDBClient,
        s3: S3Client,
        *,
        table: str,
        table_arn: str,
        region: str,
        results_bucket: str,
        exports_prefix: str,
        quota: ExportQuota,
        kms_key_arn: str | None = None,
        max_object_bytes: int = 20 * 1024**2,
        max_inflated_bytes: int = 100 * 1024**2,
        min_interval_days: int = 7,
        incremental: bool = True,
    ) -> None:
        self.client = client
        self.s3 = s3
        self.table = table
        self.table_arn = table_arn
        self.region = region
        self.bucket = results_bucket
        digest = hashlib.sha256(table_arn.encode()).hexdigest()[:12]
        self.prefix = f"{exports_prefix}dynamodb/{digest}"
        self.quota = quota
        self.kms_key_arn = kms_key_arn
        self.max_object_bytes = max_object_bytes
        self.max_inflated_bytes = max_inflated_bytes
        self.min_interval_days = min_interval_days
        self.incremental = incremental
        self.rules = AttributeRules()
        self.id = f"dynamodb-export:{digest}"
        self.target = f"{table} (export)"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("dynamodb", self.target)
        c = dict(cursor)
        c.setdefault("keySalt", secrets.token_hex(16))
        extra: dict[str, Any] = {"readBy": "export"}
        op = ObjectPass(self.indexes, self.id, self.kind, budget=budget)
        try:
            if not c.get("export"):
                return self._start(c, cov, op, now, extra)
            if c.get("incremental"):
                extra["exportType"] = "incremental"
            if c.get("phase") == "exporting":
                d = self.client.describe_export(ExportArn=c["export"])["ExportDescription"]
                status = str(d.get("ExportStatus", ""))
                if status == "IN_PROGRESS":
                    cov.backlog = True
                    running = {**extra, "exportStatus": "in_progress"}
                    return SourceRun(cov, c, "export_pending", running)
                if status != "COMPLETED":
                    cov.error = "ExportFailed"
                    log_event("source.failed", source=self.target, error=cov.error)
                    base = self._base(d)
                    if base:
                        delete_prefix(self.s3, self.bucket, base)
                    kept = {"keySalt": c["keySalt"], "lastExportAt": now.isoformat()}
                    if c.get("incremental"):
                        # The window is tried again; the last full export still stands.
                        keep = ("keySalt", "lastExportAt", "exportTime", "passId")
                        kept = {k: c[k] for k in keep if c.get(k)}
                    failed = {**extra, "exportStatus": "failed"}
                    return SourceRun(cov, kept, "export_failed", failed)
                base = self._base(d)
                if base is None:
                    raise ValueError("export has no manifest")
                desc = self.client.describe_table(TableName=self.table)["Table"]
                c.update(
                    phase="scanning",
                    base=base,
                    keyNames=[k["AttributeName"] for k in desc["KeySchema"]],
                )
                if not c.get("incremental") and d.get("ExportTime") is not None:
                    at = d["ExportTime"]
                    c["pointInTime"] = at.isoformat() if hasattr(at, "isoformat") else str(at)
            return self._scan(c, cov, op, budget=budget, detector=detector, store=store, now=now)
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if is_kms_denial(err):
                cov.kms_denied += 1
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, cursor, None, extra)

    def _start(
        self,
        c: dict[str, Any],
        cov: Coverage,
        op: ObjectPass,
        now: _dt.datetime,
        extra: dict[str, Any],
    ) -> SourceRun:
        """Start the next export: incremental from the last one's point in time when the
        table's components are current, else full when one is due (or owed as a rescan)."""
        decision = op.decide("table", changed=False)
        why = (
            decision.why if decision.why is not None and decision.why.reason != UNINDEXED else None
        )
        since = _time(c.get("exportTime"))
        current = op.index is None or (decision.why is None and op.index.get("table") is not None)
        if (
            self.incremental
            and since is not None
            and current
            and why is None
            and now - since < PITR_WINDOW
        ):
            if now - since < INCREMENTAL_MIN:
                cov.pass_complete = True  # too soon for a window
                op.settle(cov)
                return SourceRun(cov, c, None, extra)
            return self._export(c, cov, op, now, extra, since=since, why=None)
        if why is not None:
            if not op.rescans.admit():
                op.rescans.miss(why)
                cov.pass_complete = True
                op.settle(cov)
                return SourceRun(cov, c, None, extra)
        elif not due(c.get("lastExportAt"), now, self.min_interval_days):
            cov.pass_complete = True
            op.settle(cov)
            return SourceRun(cov, c, None, extra)
        return self._export(c, cov, op, now, extra, since=None, why=why)

    def _export(
        self,
        c: dict[str, Any],
        cov: Coverage,
        op: ObjectPass,
        now: _dt.datetime,
        extra: dict[str, Any],
        *,
        since: _dt.datetime | None,
        why: Stale | None,
    ) -> SourceRun:
        if not self.quota.take():
            cov.backlog = True
            op.settle(cov)
            return SourceRun(cov, c, "budget", extra)
        args: dict[str, Any] = {
            "TableArn": self.table_arn,
            "S3Bucket": self.bucket,
            "S3Prefix": self.prefix,
            "ExportFormat": "DYNAMODB_JSON",
            "ExportType": "FULL_EXPORT",
            "ClientToken": secrets.token_hex(16),
        }
        until = None
        if since is not None:
            until = min(now, since + INCREMENTAL_MAX)
            args["ExportType"] = "INCREMENTAL_EXPORT"
            args["IncrementalExportSpecification"] = {
                "ExportFromTime": since,
                "ExportToTime": until,
                "ExportViewType": "NEW_IMAGE",
            }
            extra["exportType"] = "incremental"
        if self.kms_key_arn:
            args["S3SseAlgorithm"] = "KMS"
            args["S3SseKmsKeyId"] = self.kms_key_arn
        else:
            args["S3SseAlgorithm"] = "AES256"
        r = self.client.export_table_to_point_in_time(**args)
        c.update(
            export=r["ExportDescription"]["ExportArn"],
            phase="exporting",
            after=None,
        )
        if until is not None:
            c.update(incremental=True, windowEnd=until.isoformat())
            c.setdefault("passId", secrets.token_hex(8))
        else:
            c.pop("incremental", None)
            c["passId"] = secrets.token_hex(8)
            if why is not None:
                c["rescan"] = why.fields()
        cov.backlog = True
        op.settle(cov)
        return SourceRun(cov, c, "export_pending", {**extra, "exportStatus": "in_progress"})

    def _base(self, d: Any) -> str | None:
        """The export's own folder (`…/AWSDynamoDB/<export-id>/`), from its manifest key."""
        manifest = str(d.get("ExportManifest") or "")
        if "/AWSDynamoDB/" not in f"/{manifest}":
            return None
        return manifest.rsplit("/", 1)[0] + "/"

    def _scan(
        self,
        c: dict[str, Any],
        cov: Coverage,
        op: ObjectPass,
        *,
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        seen_at = now.isoformat()
        link = dynamodb_link(self.region, self.table)
        salt = str(c["keySalt"])
        done = True
        for obj in list_keys(self.s3, self.bucket, f"{c['base']}data/", c.get("after")):
            key = obj["Key"]
            cov.listed += 1
            if not key.endswith(".json.gz"):
                c["after"] = key
                continue
            size = min(int(obj.get("Size", 0)), self.max_object_bytes)
            if not budget.has(size):
                done = False
                break
            budget.take(size)
            try:
                args: dict[str, Any] = {"Bucket": self.bucket, "Key": key}
                if int(obj.get("Size", 0)) > self.max_object_bytes:
                    args["Range"] = f"bytes=0-{self.max_object_bytes - 1}"
                    cov.partial += 1
                data = self.s3.get_object(**args)["Body"].read()
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                text = d.decompress(data, self.max_inflated_bytes).decode("utf-8", "replace")
            except (zlib.error, OSError, EOFError, gzip.BadGzipFile) as err:
                cov.unreadable += 1
                log_event("item.unreadable", source=self.target, error=error_name(err))
                c["after"] = key
                continue
            cov.bytes_scanned += len(data)
            for line in text.splitlines():
                self._item(
                    line,
                    c=c,
                    cov=cov,
                    detector=detector,
                    store=store,
                    salt=salt,
                    link=link,
                    seen_at=seen_at,
                )
            c["after"] = key
        extra: dict[str, Any] = {"readBy": "export", "exportStatus": "completed"}
        if c.get("incremental"):
            extra["exportType"] = "incremental"
        if not done:
            cov.backlog = True
            op.settle(cov)
            return SourceRun(cov, c, None, extra)
        if not c.get("incremental"):
            # A full export: findings of items it no longer has are gone.
            gone = drop_other_passes(store, self.id, c["passId"])
            if gone:
                log_event("finding.gone", source=self.target, count=gone)
        delete_prefix(self.s3, self.bucket, c["base"])
        cov.pass_complete = True
        why = c.get("rescan")
        if isinstance(why, dict) and why.get("rescanReason"):
            op.rescanned(
                None, Stale(str(why["rescanReason"]), tuple(why.get("rescanClasses") or ()))
            )
        op.record("table", readers=("attributes",), text=True)
        op.settle(cov)
        finished = {
            "keySalt": salt,
            "lastExportAt": c.get("lastExportAt") if c.get("incremental") else now.isoformat(),
            "exportTime": c.get("windowEnd") if c.get("incremental") else c.get("pointInTime"),
            "passId": c["passId"],
        }
        return SourceRun(cov, {k: v for k, v in finished.items() if v}, None, extra)

    def _item(
        self,
        line: str,
        *,
        c: dict[str, Any],
        cov: Coverage,
        detector: Detector,
        store: FindingStore,
        salt: str,
        link: str,
        seen_at: str,
    ) -> None:
        try:
            doc = json.loads(line)
        except ValueError:
            return
        if not isinstance(doc, dict):
            return
        if "Keys" in doc:
            # An incremental export's line: the item's keys and its new image, or no image
            # for an item deleted in the window.
            keys = doc.get("Keys") if isinstance(doc.get("Keys"), dict) else {}
            item = doc.get("NewImage")
            if not isinstance(item, dict):
                canonical = json.dumps(
                    {n: key_value(v) for n, v in sorted((keys or {}).items())},
                    separators=(",", ":"),
                )
                gone = hmac.new(salt.encode(), canonical.encode(), hashlib.sha256).hexdigest()
                store.remove_location(f"{self.id}\n{gone}")
                return
        else:
            item = doc.get("Item")
        if not isinstance(item, dict):
            return
        cov.eligible += 1
        key = {n: item[n] for n in c.get("keyNames") or [] if n in item}
        canonical = json.dumps(
            {n: key_value(v) for n, v in sorted(key.items())}, separators=(",", ":")
        )
        key_hash = hmac.new(salt.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        try:
            result = scan_attributes(item, detector, self.rules)
        except Exception as err:  # one bad item must not stop the pass
            cov.unreadable += 1
            log_event("item.unreadable", source=self.target, error=error_name(err))
            return
        cov.scanned += 1
        cov.formats[FORMAT] = cov.formats.get(FORMAT, 0) + 1
        cov.redaction_markers += result.redaction_markers
        cov.test_values += result.test_values
        cov.suppressed += result.suppressed
        shown = {n: key_value(v) for n, v in key.items()}
        findings = []
        for path, found in sorted(result.by_path.items()):
            resource = dynamodb_resource(self.table, shown, key_hash, path)
            for cf in found.findings.values():
                f = finding_json(resource, link, FORMAT, cf, seen_at, facts=self.facts)
                f["_pass"] = c["passId"]
                f.update(c.get("rescan") or {})
                findings.append(f)
        store.replace_location(f"{self.id}\n{key_hash}", findings)
