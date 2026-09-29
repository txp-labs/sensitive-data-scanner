"""RDS and Aurora: by snapshot export to Parquet (the default), or read-only SQL (opt-in).

**Snapshot export.** No database credentials and no load on the database:

1. Find the cluster's (or instance's) latest automated snapshot.
2. Start one export task (`StartExportTask`) of that snapshot to the results
   bucket's `exports/rds/` prefix, encrypted with the customer's KMS key,
   written by the export role. At most `MAX_EXPORTS_PER_RUN` exports start in a
   run, and a store is exported again no sooner than `EXPORT_MIN_INTERVAL_DAYS`.
3. On later runs, wait for it (`DescribeExportTasks`); then read its Parquet
   files by column, across as many runs as the budget needs.
4. When every file is read, delete the export, and drop findings the new
   snapshot no longer has.

A finding names the engine, the cluster or instance, the database, and the
table and column (`schema.table.column`). Rows are not addressable once the
export is deleted, so a finding carries counts, not offsets.

**Data API (opt-in, `RDS_DATA_API`).** For a small Aurora database: the
generic sampled SQL of the core's scan/sql.py (list the tables from
`information_schema`, then `SELECT * ... LIMIT n` from each), inside a
transaction that is always rolled back (and `SET TRANSACTION READ ONLY` on
PostgreSQL). Identifiers are quoted; the only statements are the scanner's
own SELECTs. The secret should belong to a read-only database user.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import io
import json
import secrets
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, finding_json
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.columnar import TableResult, scan_parquet
from sensitive_data_core.scan.sql import (
    MYSQL,
    POSTGRESQL,
    Dialect,
    Params,
    sample_sql,
    sample_tables,
)
from sensitive_data_core.scan.sql import tables_sql as generic_tables_sql

from ..config import DataApiTarget
from ..resources import rds_link, rds_resource
from .exports import ExportQuota, delete_prefix, drop_other_passes, due, list_keys, merge
from .s3 import S3RangeFile

if TYPE_CHECKING:
    from mypy_boto3_rds import RDSClient
    from mypy_boto3_rds_data import RDSDataServiceClient
    from mypy_boto3_s3 import S3Client

# Engines whose snapshots RDS can export to S3.
EXPORTABLE_ENGINES = frozenset(
    {"aurora", "aurora-mysql", "aurora-postgresql", "mysql", "mariadb", "postgres"}
)
RUNNING = frozenset({"STARTING", "IN_PROGRESS", "CANCELING"})


def _findings(
    table: TableResult,
    *,
    engine: str,
    identifier: str,
    db_type: str,
    database: str,
    name: str,
    read_by: str,
    snapshot_time: str | None,
    link: str,
    seen_at: str,
) -> list[dict[str, Any]]:
    out = []
    for column, item in sorted(table.by_column.items()):
        resource = rds_resource(
            engine=engine,
            identifier=identifier,
            db_type=db_type,
            database=database,
            table=name,
            column=column,
            read_by=read_by,
            snapshot_time=snapshot_time,
        )
        for cf in item.findings.values():
            cf.offsets = []  # the rows are gone with the export: counts only
            out.append(finding_json(resource, link, table.format, cf, seen_at))
    return out


def export_table_of(relative: str) -> tuple[str, str] | None:
    """`<db>/<schema.table>/<partition>/part-….parquet` to (db, schema.table)."""
    parts = relative.split("/")
    if len(parts) < 3 or not parts[-1].endswith(".parquet"):
        return None
    return parts[0], parts[1]


class RdsExportSource:
    kind = "rds"

    def __init__(
        self,
        rds: RDSClient,
        s3: S3Client,
        *,
        identifier: str,
        db_type: str,  # cluster | instance
        engine: str,
        region: str,
        results_bucket: str,
        exports_prefix: str,
        role_arn: str,
        kms_key_arn: str,
        quota: ExportQuota,
        max_rows: int = 10_000,
        max_object_bytes: int = 20 * 1024**2,
        min_interval_days: int = 7,
    ) -> None:
        self.rds = rds
        self.s3 = s3
        self.identifier = identifier
        self.db_type = db_type
        self.engine = engine
        self.region = region
        self.bucket = results_bucket
        self.prefix = f"{exports_prefix}rds/"
        self.role_arn = role_arn
        self.kms_key_arn = kms_key_arn
        self.quota = quota
        self.max_rows = max_rows
        self.max_object_bytes = max_object_bytes
        self.min_interval_days = min_interval_days
        self.id = f"rds:{db_type}:{identifier}"
        self.target = f"{db_type}:{identifier}"

    def latest_snapshot(self) -> dict[str, str] | None:
        """The latest available automated snapshot: its ARN, id and time."""
        best: dict[str, str] | None = None
        if self.db_type == "cluster":
            pages = self.rds.get_paginator("describe_db_cluster_snapshots").paginate(
                DBClusterIdentifier=self.identifier, SnapshotType="automated"
            )
            for page in pages:
                for s in page.get("DBClusterSnapshots", []):
                    if s.get("Status") != "available" or "SnapshotCreateTime" not in s:
                        continue
                    at = s["SnapshotCreateTime"].isoformat()
                    if best is None or at > best["at"]:
                        best = {
                            "arn": s["DBClusterSnapshotArn"],
                            "id": s["DBClusterSnapshotIdentifier"],
                            "at": at,
                        }
        else:
            ipages = self.rds.get_paginator("describe_db_snapshots").paginate(
                DBInstanceIdentifier=self.identifier, SnapshotType="automated"
            )
            for ipage in ipages:
                for snap in ipage.get("DBSnapshots", []):
                    if snap.get("Status") != "available" or "SnapshotCreateTime" not in snap:
                        continue
                    at = snap["SnapshotCreateTime"].isoformat()
                    if best is None or at > best["at"]:
                        best = {
                            "arn": snap["DBSnapshotArn"],
                            "id": snap["DBSnapshotIdentifier"],
                            "at": at,
                        }
        return best

    def _task_id(self, snapshot_at: str) -> str:
        digest = hashlib.sha256(self.id.encode()).hexdigest()[:10]
        stamp = "".join(c for c in snapshot_at if c.isdigit())[:12]
        return f"sds-{digest}-{stamp}-{secrets.token_hex(3)}"

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("rds", self.target)
        c = dict(cursor)
        try:
            if not c.get("task"):
                return self._start(c, cov, now)
            if c.get("phase") == "exporting":
                task = self.rds.describe_export_tasks(ExportTaskIdentifier=c["task"])
                status = str((task.get("ExportTasks") or [{}])[0].get("Status", "")).upper()
                if status in RUNNING:
                    cov.backlog = True
                    return SourceRun(cov, c, "export_pending", self._extra(c, status))
                if status != "COMPLETE":
                    cov.error = "ExportCanceled" if status == "CANCELED" else "ExportFailed"
                    delete_prefix(self.s3, self.bucket, f"{self.prefix}{c['task']}/")
                    log_event("source.failed", source=self.target, error=cov.error)
                    kept = {k: c.get(k) for k in ("lastSnapshot", "lastSnapshotAt", "lastExportAt")}
                    kept["failedSnapshot"] = c.get("snapshot")
                    return SourceRun(cov, kept, "export_failed", self._extra(c, status))
                c["phase"] = "scanning"
            return self._scan(c, cov, budget=budget, detector=detector, store=store, now=now)
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if is_kms_denial(err):
                cov.kms_denied += 1
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, cursor, None, self._extra(c, None))

    def _extra(self, c: dict[str, Any], status: str | None) -> dict[str, Any]:
        out: dict[str, Any] = {"engine": self.engine, "dbType": self.db_type}
        if c.get("snapshotAt"):
            out["snapshotTime"] = c["snapshotAt"]
        if status:
            out["exportStatus"] = status.lower()
        return out

    def _start(self, c: dict[str, Any], cov: Coverage, now: _dt.datetime) -> SourceRun:
        snap = self.latest_snapshot()
        if snap is None:
            return SourceRun(cov, c, "no_snapshot", self._extra(c, None))
        if snap["arn"] in (c.get("lastSnapshot"), c.get("failedSnapshot")):
            cov.pass_complete = snap["arn"] == c.get("lastSnapshot")
            note = None if cov.pass_complete else "export_failed"
            return SourceRun(cov, c, note, self._extra({"snapshotAt": snap["at"]}, None))
        if not due(c.get("lastExportAt"), now, self.min_interval_days):
            cov.pass_complete = True
            return SourceRun(
                cov, c, None, self._extra({"snapshotAt": c.get("lastSnapshotAt")}, None)
            )
        if not self.quota.take():
            cov.backlog = True
            return SourceRun(cov, c, "budget", self._extra({}, None))
        task_id = self._task_id(snap["at"])
        self.rds.start_export_task(
            ExportTaskIdentifier=task_id,
            SourceArn=snap["arn"],
            S3BucketName=self.bucket,
            S3Prefix=self.prefix.rstrip("/"),
            IamRoleArn=self.role_arn,
            KmsKeyId=self.kms_key_arn,
        )
        started = {
            **{k: c.get(k) for k in ("lastSnapshot", "lastSnapshotAt", "lastExportAt")},
            "task": task_id,
            "phase": "exporting",
            "snapshot": snap["arn"],
            "snapshotAt": snap["at"],
            "passId": secrets.token_hex(8),
            "after": None,
        }
        cov.backlog = True
        return SourceRun(cov, started, "export_pending", self._extra(started, "STARTING"))

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
        base = f"{self.prefix}{c['task']}/"
        seen_at = now.isoformat()
        link = rds_link(self.region, self.identifier, self.db_type)
        done = True
        for obj in list_keys(self.s3, self.bucket, base, c.get("after")):
            key = obj["Key"]
            cov.listed += 1
            where = export_table_of(key[len(base) :])
            if where is None:  # export_info_*.json and the like
                c["after"] = key
                continue
            cov.eligible += 1
            size = int(obj.get("Size", 0))
            if not budget.has(min(size, self.max_object_bytes)):
                done = False
                break
            budget.take(min(size, self.max_object_bytes))
            raw = S3RangeFile(self.s3, self.bucket, key, size=size, max_bytes=self.max_object_bytes)
            try:
                table = scan_parquet(io.BufferedReader(raw, 256 * 1024), detector, self.max_rows)
            except Exception as err:  # one bad file must not stop the pass
                cov.unreadable += 1
                if is_kms_denial(err):
                    cov.kms_denied += 1
                log_event("item.unreadable", source=self.target, error=error_name(err))
                c["after"] = key
                continue
            cov.scanned += 1
            cov.bytes_scanned += raw.bytes_read
            cov.formats["parquet"] = cov.formats.get("parquet", 0) + 1
            cov.partial += int(table.partial or raw.cut)
            cov.test_values += table.test_values
            cov.suppressed += table.suppressed
            cov.redaction_markers += table.redaction_markers
            database, name = where
            for f in _findings(
                table,
                engine=self.engine,
                identifier=self.identifier,
                db_type=self.db_type,
                database=database,
                name=name,
                read_by="snapshot_export",
                snapshot_time=c.get("snapshotAt"),
                link=link,
                seen_at=seen_at,
            ):
                merge(store, f"{self.id}\n{database}/{name}", f, c["passId"])
            c["after"] = key
        if not done:
            cov.backlog = True
            return SourceRun(cov, c, None, self._extra(c, "COMPLETE"))
        gone = drop_other_passes(store, self.id, c["passId"])
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        delete_prefix(self.s3, self.bucket, base)
        cov.pass_complete = True
        finished = {
            "lastSnapshot": c.get("snapshot"),
            "lastSnapshotAt": c.get("snapshotAt"),
            "lastExportAt": now.isoformat(),
        }
        return SourceRun(cov, finished, None, self._extra(c, "COMPLETE"))


def _dialect(engine: str) -> Dialect:
    return MYSQL if engine == "mysql" else POSTGRESQL


def quote_identifier(name: str, engine: str) -> str:
    """A SQL identifier, quoted so that nothing in it is SQL (the core's scan/sql.py)."""
    return _dialect(engine).ident(name)


def tables_sql(engine: str, schemas: tuple[str, ...]) -> tuple[str, list[dict[str, Any]]]:
    """The statement that lists base tables, and its Data API parameters (never inlined)."""
    sql, params = generic_tables_sql(_dialect(engine), schemas)
    return sql, [{"name": n, "value": {"stringValue": v}} for n, v in params]


def select_sql(engine: str, schema: str, table: str, limit: int) -> str:
    return sample_sql(_dialect(engine), schema, table, limit)


class RdsDataApiSource:
    """An Aurora database read with read-only SQL through the Data API (opt-in)."""

    kind = "rds"

    def __init__(self, client: RDSDataServiceClient, *, target: DataApiTarget, region: str) -> None:
        self.client = client
        self.t = target
        self.region = region
        self.identifier = target.cluster_arn.rsplit(":", 1)[-1]
        digest = hashlib.sha256(f"{target.cluster_arn}|{target.database}".encode()).hexdigest()
        self.id = f"rdsdata:{digest[:16]}"
        self.target = f"data_api:{self.identifier}/{target.database}"

    def _exec(self, sql: str, tx: str | None, params: list[dict[str, Any]] | None = None) -> Any:
        args: dict[str, Any] = {
            "resourceArn": self.t.cluster_arn,
            "secretArn": self.t.secret_arn,
            "database": self.t.database,
            "sql": sql,
            "formatRecordsAs": "JSON",
        }
        if tx:
            args["transactionId"] = tx
        if params:
            args["parameters"] = params
        return self.client.execute_statement(**args)

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("rds", self.target)
        pass_id = cursor.get("passId") or secrets.token_hex(8)
        after = cursor.get("after")
        seen_at = now.isoformat()
        engine = "aurora-postgresql" if self.t.engine == "postgresql" else "aurora-mysql"
        link = rds_link(self.region, self.identifier, "cluster")
        extra = {"engine": engine, "dbType": "cluster", "readBy": "data_api"}
        tx: str | None = None
        done = False

        def execute(sql: str, params: Params) -> list[dict[str, Any]]:
            data_api = [{"name": n, "value": {"stringValue": v}} for n, v in params]
            r = self._exec(sql, tx, data_api)
            rows: list[dict[str, Any]] = json.loads(r.get("formattedRecords") or "[]")
            return rows

        def on_table(schema: str, name: str, table: TableResult) -> None:
            findings = _findings(
                table,
                engine=engine,
                identifier=self.identifier,
                db_type="cluster",
                database=self.t.database,
                name=f"{schema}.{name}",
                read_by="data_api",
                snapshot_time=None,
                link=link,
                seen_at=seen_at,
            )
            for f in findings:
                f["_pass"] = pass_id
            store.replace_location(f"{self.id}\n{schema}.{name}", findings)

        try:
            tx = self.client.begin_transaction(
                resourceArn=self.t.cluster_arn,
                secretArn=self.t.secret_arn,
                database=self.t.database,
            )["transactionId"]
            if self.t.engine == "postgresql":
                self._exec("SET TRANSACTION READ ONLY", tx)
            res = sample_tables(
                execute,
                _dialect(self.t.engine),
                detector=detector,
                has_room=lambda: budget.has(0),
                take=budget.take,
                on_table=on_table,
                after=after,
                schemas=self.t.schemas,
                max_rows=self.t.max_rows_per_table,
                max_tables=self.t.max_tables,
                source=self.target,
            )
            cov.listed, cov.eligible, cov.scanned = res.listed, res.eligible, res.scanned
            cov.unreadable, cov.partial, cov.bytes_scanned = res.unreadable, res.partial, res.bytes
            cov.test_values, cov.suppressed = res.test_values, res.suppressed
            cov.redaction_markers = res.redaction_markers
            if res.scanned:
                cov.formats["sql"] = res.scanned
            after, done = res.after, res.done
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            done = False
            log_event("source.failed", source=self.target, error=cov.error)
        finally:
            if tx:
                try:
                    self.client.rollback_transaction(
                        resourceArn=self.t.cluster_arn,
                        secretArn=self.t.secret_arn,
                        transactionId=tx,
                    )
                except Exception as err:  # the transaction times out by itself
                    log_event("source.failed", source=self.target, error=error_name(err))
        if done:
            cov.pass_complete = True
            drop_other_passes(store, self.id, pass_id)
            return SourceRun(cov, {"passId": None, "after": None}, None, extra)
        if cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"passId": pass_id, "after": after}, None, extra)
