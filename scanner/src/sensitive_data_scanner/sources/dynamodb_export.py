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

from ..detect.analyzer import Detector
from ..findings import Coverage, dynamodb_link, dynamodb_resource, finding_json
from ..safety import error_name, is_kms_denial, log_event
from ..scan.attributes import FORMAT, AttributeRules, key_value, scan_attributes
from .base import Budget, FindingStore, SourceRun
from .exports import ExportQuota, delete_prefix, drop_other_passes, due, list_keys

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient
    from mypy_boto3_s3 import S3Client


class DynamoDBExportSource:
    kind = "dynamodb"

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
        extra = {"readBy": "export"}
        try:
            if not c.get("export"):
                if not due(c.get("lastExportAt"), now, self.min_interval_days):
                    cov.pass_complete = True
                    return SourceRun(cov, c, None, extra)
                if not self.quota.take():
                    cov.backlog = True
                    return SourceRun(cov, c, "budget", extra)
                args: dict[str, Any] = {
                    "TableArn": self.table_arn,
                    "S3Bucket": self.bucket,
                    "S3Prefix": self.prefix,
                    "ExportFormat": "DYNAMODB_JSON",
                    "ExportType": "FULL_EXPORT",
                    "ClientToken": secrets.token_hex(16),
                }
                if self.kms_key_arn:
                    args["S3SseAlgorithm"] = "KMS"
                    args["S3SseKmsKeyId"] = self.kms_key_arn
                else:
                    args["S3SseAlgorithm"] = "AES256"
                r = self.client.export_table_to_point_in_time(**args)
                c.update(
                    export=r["ExportDescription"]["ExportArn"],
                    phase="exporting",
                    passId=secrets.token_hex(8),
                    after=None,
                )
                cov.backlog = True
                return SourceRun(cov, c, "export_pending", {**extra, "exportStatus": "in_progress"})
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
            return self._scan(c, cov, budget=budget, detector=detector, store=store, now=now)
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if is_kms_denial(err):
                cov.kms_denied += 1
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, cursor, None, extra)

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
        if not done:
            cov.backlog = True
            return SourceRun(cov, c, None, {"readBy": "export", "exportStatus": "completed"})
        gone = drop_other_passes(store, self.id, c["passId"])
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        delete_prefix(self.s3, self.bucket, c["base"])
        cov.pass_complete = True
        finished = {"keySalt": salt, "lastExportAt": now.isoformat()}
        return SourceRun(cov, finished, None, {"readBy": "export", "exportStatus": "completed"})

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
            item = json.loads(line).get("Item")
        except (ValueError, AttributeError):
            return
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
                f = finding_json(resource, link, FORMAT, cf, seen_at)
                f["_pass"] = c["passId"]
                findings.append(f)
        store.replace_location(f"{self.id}\n{key_hash}", findings)
