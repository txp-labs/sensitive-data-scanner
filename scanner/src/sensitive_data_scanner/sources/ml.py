"""Machine learning and graph stores: SageMaker and Neptune Analytics, both opt-in (#35).

**SageMaker** (`DISCOVER` includes `sagemaker`; reading needs `SAGEMAKER_READ`):

- **Feature Store.** `ListFeatureGroups`, `DescribeFeatureGroup`. A feature
  group's offline store is S3 (Parquet under its resolved S3 URI): it is read
  there by the S3 source, which the S3 bucket's own source then leaves to it,
  so each object is read once. The online store has no API that lists its
  records (`GetRecord` needs each record's identifier), so an online-only
  group is `no_read_path`; its offline store, when it has one, holds the same
  records' history.
- **Notebook instances.** `ListNotebookInstances`: each is reported
  `no_read_path`. Its ML storage volume lives in SageMaker's own account, not
  the customer's, so no snapshot and no EBS direct read reaches it.

**Neptune Analytics** (`neptune_analytics`; reading needs
`NEPTUNE_ANALYTICS_EXPORT_ROLE_ARN` and `NEPTUNE_ANALYTICS_EXPORT_KMS_KEY_ARN`):
`ListGraphs`, `GetGraph`. A graph is exported (`StartExportTask`, CSV,
encrypted with the customer's key, written by the export role) to the results
bucket's `exports/neptune-graph/` prefix, at most `MAX_EXPORTS_PER_RUN` a run
(shared with the RDS and DynamoDB exports) and no sooner than
`EXPORT_MIN_INTERVAL_DAYS`. Later runs wait for it (`GetExportTask`), read its
CSV files by column (nodes and edges, each property a column), and delete the
export. A finding names the graph, `nodes` or `edges`, and the property.
"""

from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import io
import secrets
import urllib.parse
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.columnar import scan_rows

from ..discovery import decide, glue_location, needs_tags
from ..resources import console_link
from .base import Context
from .encryption import classifier
from .exports import ExportQuota, delete_prefix, drop_other_passes, due, list_keys, merge
from .s3 import S3Source

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("sagemaker", "neptune-graph", "s3")

GRAPH_RUNNING = frozenset({"INITIALIZING", "EXPORTING", "CANCELLING"})
# Neptune Analytics' task states, as the run summary's `exportStatus` names them for RDS.
EXPORT_STATUS = {
    "INITIALIZING": "starting",
    "EXPORTING": "in_progress",
    "CANCELLING": "canceling",
    "SUCCEEDED": "complete",
    "FAILED": "failed",
    "CANCELLED": "canceled",
}
MAX_CSV_ROWS = 10_000


# ------------------------------------------------------------------ SageMaker


class SageMakerAdapter:
    kind = "sagemaker"

    def discover(self, ctx: Context, out: Discovery) -> None:
        sm = ctx.clients.client("sagemaker")
        keys = classifier(ctx.clients)
        for page in sm.get_paginator("list_feature_groups").paginate():
            for g in page.get("FeatureGroupSummaries", []):
                name = str(g["FeatureGroupName"])
                store = Store(self.kind, f"feature-group/{name}")
                store.extra["resource"] = "feature_group"
                out.stores.append(store)
                try:
                    d = sm.describe_feature_group(FeatureGroupName=name)
                except Exception as err:
                    store.status, store.error = "error", error_name(err)
                    store.reason = reason_for(store.error)
                    continue
                offline = (d.get("OfflineStoreConfig") or {}).get("S3StorageConfig") or {}
                online = d.get("OnlineStoreConfig") or {}
                key = offline.get("KmsKeyId") or (online.get("SecurityConfig") or {}).get(
                    "KmsKeyId"
                )
                store.facts = keys.facts(key=key, aws_owned=not key)
                if needs_tags(ctx.config, self.kind):
                    try:
                        t = sm.list_tags(ResourceArn=str(d.get("FeatureGroupArn")))
                        store.tags = {str(x["Key"]): str(x.get("Value", "")) for x in t["Tags"]}
                        decide(store, ctx.config)
                    except Exception as err:
                        decide(store, ctx.config, error_name(err))
                else:
                    decide(store, ctx.config)
                if store.status != "pending":
                    continue
                if not ctx.config.sagemaker_read:
                    store.skip("read_not_configured")
                    continue
                where = glue_location(
                    str(offline.get("ResolvedOutputS3Uri") or offline.get("S3Uri") or "")
                )
                if where is None:
                    store.skip("no_read_path")  # online only: no API lists its records
                    continue
                store.extra["s3Locations"] = [f"{where[0]}/{where[1]}"]
        for page in sm.get_paginator("list_notebook_instances").paginate():
            for nb in page.get("NotebookInstances", []):
                store = Store(self.kind, f"notebook-instance/{nb['NotebookInstanceName']}")
                store.extra["resource"] = "notebook_instance"
                out.stores.append(store)
                decide(store, ctx.config)
                if store.status == "pending":
                    store.skip("no_read_path")  # its volume is in SageMaker's own account

    def source(self, ctx: Context, store: Store) -> list[S3Source]:
        c = ctx.config
        out = []
        for loc in store.extra.get("s3Locations") or []:
            bucket, _, prefix = str(loc).partition("/")
            out.append(
                S3Source(
                    ctx.clients.s3,
                    bucket=bucket,
                    prefix=prefix,
                    region=ctx.region,
                    sample_percent=store.sample_percent or c.sample_percent,
                    max_object_bytes=c.max_object_bytes,
                    max_inflated_bytes=c.max_inflated_bytes,
                    skew_seconds=c.s3_skew_seconds,
                    max_per_prefix=store.max_per_prefix
                    if store.max_per_prefix is not None
                    else c.s3_max_objects_per_prefix,
                    max_rows=c.columnar_max_rows,
                    keys=classifier(ctx.clients),
                )
            )
        return out


# ------------------------------------------------------------------ Neptune Analytics


class NeptuneAnalyticsAdapter:
    kind = "neptune_analytics"

    def discover(self, ctx: Context, out: Discovery) -> None:
        ng = ctx.clients.client("neptune-graph")
        keys = classifier(ctx.clients)
        graphs: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            r = ng.list_graphs(**({"nextToken": token} if token else {}))
            graphs.extend(r.get("graphs", []))
            token = r.get("nextToken")
            if not token:
                break
        for g in graphs:
            store = Store(self.kind, str(g.get("name")))
            out.stores.append(store)
            key = g.get("kmsKeyIdentifier")
            store.facts = keys.facts(key=key, aws_owned=key in (None, "", "AWS_OWNED_KEY"))
            state = str(g.get("status") or "")
            if state != "AVAILABLE":
                store.skip("unsupported")
                store.extra["state"] = state[:60]
                continue
            tag_error: str | None = None
            if needs_tags(ctx.config, self.kind):
                try:
                    t = ng.list_tags_for_resource(resourceArn=str(g.get("arn")))
                    store.tags = {str(k): str(v) for k, v in (t.get("tags") or {}).items()}
                except Exception as err:
                    tag_error = error_name(err)
            decide(store, ctx.config, tag_error)
            if store.status != "pending":
                continue
            c = ctx.config
            if not (c.neptune_analytics_export_role_arn and c.neptune_analytics_export_kms_key_arn):
                store.skip("export_not_configured")
                continue
            store.extra["arn"] = str(g.get("id"))

    def source(self, ctx: Context, store: Store) -> NeptuneGraphExportSource | None:
        graph_id = store.extra.get("arn")
        c = ctx.config
        if not graph_id or ctx.quota is None:
            return None
        return NeptuneGraphExportSource(
            ctx.clients.client("neptune-graph"),
            ctx.clients.s3,
            name=store.name,
            graph_id=str(graph_id),
            region=ctx.region,
            results_bucket=c.results_bucket,
            exports_prefix=c.exports_prefix,
            role_arn=str(c.neptune_analytics_export_role_arn),
            kms_key_arn=str(c.neptune_analytics_export_kms_key_arn),
            quota=ctx.quota,
            max_bytes=c.max_object_bytes,
            min_interval_days=c.export_min_interval_days,
        )


class NeptuneGraphExportSource:
    """One graph, by an export to CSV in the results bucket: started, waited for, read by
    column, deleted."""

    kind = "neptune_analytics"
    facts: dict[str, Any] | None = None

    def __init__(
        self,
        client: Any,
        s3: Any,
        *,
        name: str,
        graph_id: str,
        region: str,
        results_bucket: str,
        exports_prefix: str,
        role_arn: str,
        kms_key_arn: str,
        quota: ExportQuota,
        max_bytes: int = 20 * 1024**2,
        min_interval_days: int = 7,
    ) -> None:
        self.client = client
        self.s3 = s3
        self.name = name
        self.graph_id = graph_id
        self.region = region
        self.bucket = results_bucket
        self.prefix = f"{exports_prefix}neptune-graph/"
        self.role_arn = role_arn
        self.kms_key_arn = kms_key_arn
        self.quota = quota
        self.max_bytes = max_bytes
        self.min_interval_days = min_interval_days
        self.id = f"neptunegraph:{hashlib.sha256(graph_id.encode()).hexdigest()[:16]}"
        self.target = name

    def link(self) -> str:
        q = urllib.parse.quote(self.graph_id, safe="")
        return console_link(self.region, f"neptune-graph/home?region={self.region}#/graphs/{q}")

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        c = dict(cursor)
        try:
            if not c.get("task"):
                return self._start(c, cov, now)
            if c.get("phase") == "exporting":
                t = self.client.get_export_task(taskIdentifier=c["task"])
                status = str(t.get("status") or "").upper()
                if status in GRAPH_RUNNING:
                    cov.backlog = True
                    extra = {"exportStatus": EXPORT_STATUS.get(status, "in_progress")}
                    return SourceRun(cov, c, "export_pending", extra)
                if status != "SUCCEEDED":
                    cov.error = "ExportFailed"
                    delete_prefix(self.s3, self.bucket, f"{self.prefix}{c['task']}/")
                    log_event("source.failed", source=self.target, error=cov.error)
                    kept = {"lastExportAt": c.get("lastExportAt")}
                    extra = {"exportStatus": EXPORT_STATUS.get(status, "failed")}
                    return SourceRun(cov, kept, "export_failed", extra)
                c["phase"] = "scanning"
            return self._scan(c, cov, budget, detector, store, now)
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if is_kms_denial(err):
                cov.kms_denied += 1
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, cursor, None, {})

    def _start(self, c: dict[str, Any], cov: Coverage, now: _dt.datetime) -> SourceRun:
        if not due(c.get("lastExportAt"), now, self.min_interval_days):
            cov.pass_complete = True
            return SourceRun(cov, c, None, {})
        if not self.quota.take():
            cov.backlog = True
            return SourceRun(cov, c, "budget", {})
        r = self.client.start_export_task(
            graphIdentifier=self.graph_id,
            roleArn=self.role_arn,
            format="CSV",
            destination=f"s3://{self.bucket}/{self.prefix}",
            kmsKeyIdentifier=self.kms_key_arn,
        )
        started = {
            "lastExportAt": c.get("lastExportAt"),
            "task": str(r["taskId"]),
            "phase": "exporting",
            "passId": secrets.token_hex(8),
            "after": None,
        }
        cov.backlog = True
        return SourceRun(cov, started, "export_pending", {"exportStatus": "starting"})

    def _scan(  # noqa: PLR0917 - the scanning phase of one export
        self,
        c: dict[str, Any],
        cov: Coverage,
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        base = f"{self.prefix}{c['task']}/"
        seen_at, link = now.isoformat(), self.link()
        done = True
        for obj in list_keys(self.s3, self.bucket, base, c.get("after")):
            key = str(obj["Key"])
            cov.listed += 1
            if not key.lower().endswith(".csv"):
                c["after"] = key
                continue
            cov.eligible += 1
            size = min(int(obj.get("Size", 0)), self.max_bytes)
            if not budget.has(size):
                done = False
                break
            budget.take(size)
            args: dict[str, Any] = {"Bucket": self.bucket, "Key": key}
            if int(obj.get("Size", 0)) > self.max_bytes:
                args["Range"] = f"bytes=0-{self.max_bytes - 1}"
                cov.partial += 1
            data = self.s3.get_object(**args)["Body"].read()
            text = data.decode("utf-8", "replace")
            rows = list(csv.reader(io.StringIO(text)))
            if not rows:
                c["after"] = key
                continue
            # openCypher CSV headers: `~id`, `~label`, `name:String`, ...
            header = [h.split(":", 1)[0] for h in rows[0]]
            records = [dict(zip(header, r, strict=False)) for r in rows[1:MAX_CSV_ROWS]]
            part = "edges" if "edge" in key.lower() else "nodes"
            table = scan_rows("csv", header, records, detector, MAX_CSV_ROWS)
            cov.scanned += 1
            cov.bytes_scanned += len(data)
            cov.formats["csv"] = cov.formats.get("csv", 0) + 1
            cov.test_values += table.test_values
            cov.suppressed += table.suppressed

            def resource(column: str, part: str = part) -> dict[str, Any]:
                return store_field_resource(
                    service="neptune_analytics",
                    store=self.name,
                    table=part,
                    field=column,
                    read_by="export",
                )

            for f in column_findings(table, resource, link, seen_at, facts=self.facts):
                merge(store, f"{self.id}\n{part}", f, str(c["passId"]))
            c["after"] = key
        if not done:
            cov.backlog = True
            return SourceRun(cov, c, None, {"exportStatus": "complete"})
        gone = drop_other_passes(store, self.id, str(c["passId"]))
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        delete_prefix(self.s3, self.bucket, base)
        cov.pass_complete = True
        return SourceRun(cov, {"lastExportAt": now.isoformat()}, None, {"exportStatus": "complete"})
