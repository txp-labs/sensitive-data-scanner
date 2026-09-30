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
own SELECTs. **The user is checked first**, as the databases runner checks its
own (`sensitive_data_core.grants`): a user that can write (superuser, CREATE on
the database or a schema, INSERT, UPDATE, DELETE or TRUNCATE anywhere; for
MySQL, any privilege beyond reads, roles included) is refused as
`db_user_can_write` with `writeGrants`, and one whose privileges cannot be read
as `grants_unverifiable`: nothing is read.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import secrets
from typing import TYPE_CHECKING, Any

from sensitive_data_core import grants
from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import (
    UNKNOWN_ENCRYPTION,
    Coverage,
    encryption_facts,
)
from sensitive_data_core.index import Indexes, ObjectPass
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.columnar import TableResult
from sensitive_data_core.scan.sql import (
    Params,
    sample_tables,
)
from sensitive_data_core.scan.sql import tables_sql as generic_tables_sql

from ..config import DataApiTarget
from ..resources import rds_link
from . import rds_read as _read_path
from .encryption import rds_facts
from .exports import ExportQuota, delete_prefix, drop_other_passes, due
from .rds_read import _dialect, _findings

if TYPE_CHECKING:
    from mypy_boto3_rds import RDSClient
    from mypy_boto3_rds_data import RDSDataServiceClient
    from mypy_boto3_s3 import S3Client

MAX_WRITE_GRANTS = 30
# Engines whose snapshots RDS can export to S3.
EXPORTABLE_ENGINES = frozenset(
    {"aurora", "aurora-mysql", "aurora-postgresql", "mysql", "mariadb", "postgres"}
)
RUNNING = frozenset({"STARTING", "IN_PROGRESS", "CANCELING"})


class RdsExportSource:
    kind = "rds"
    # The cluster's or instance's own encryption (1.5), from discovery (runner.plan): the
    # finding is about the database, not the export read in its place.
    facts: dict[str, Any] | None = None

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

    # The read path (`rds_read.py`, the `adapter:<kind>` component, #67).
    _scan = _read_path._scan


def tables_sql(engine: str, schemas: tuple[str, ...]) -> tuple[str, list[dict[str, Any]]]:
    """The statement that lists base tables, and its Data API parameters (never inlined)."""
    sql, params = generic_tables_sql(_dialect(engine), schemas)
    return sql, [{"name": n, "value": {"stringValue": v}} for n, v in params]


class RdsDataApiSource:
    """An Aurora database read with read-only SQL through the Data API (opt-in)."""

    kind = "rds"
    # The cluster's encryption (1.5): from discovery, or from `describe_db_clusters` with `rds`.
    facts: dict[str, Any] | None = None
    rds: Any = None
    keys: Any = None
    # A change to how this kind is listed (`listing:<kind>`) drops these cursor keys: the next
    # pass lists the store again from the start and reads only what changed (#67).
    relist_keys: tuple[str, ...] = ("after",)
    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(self, client: RDSDataServiceClient, *, target: DataApiTarget, region: str) -> None:
        self.client = client
        self.t = target
        self.region = region
        self.identifier = target.cluster_arn.rsplit(":", 1)[-1]
        digest = hashlib.sha256(f"{target.cluster_arn}|{target.database}".encode()).hexdigest()
        self.id = f"rdsdata:{digest[:16]}"
        self.target = f"data_api:{self.identifier}/{target.database}"

    def _cluster_facts(self) -> dict[str, Any]:
        """The cluster's `StorageEncrypted` and key; `unknown` when it cannot be described."""
        if self.rds is None or self.keys is None:
            return encryption_facts(UNKNOWN_ENCRYPTION)
        try:
            got = self.rds.describe_db_clusters(DBClusterIdentifier=self.t.cluster_arn)
        except Exception:  # the findings then say `unknown`; the read goes on
            return encryption_facts(UNKNOWN_ENCRYPTION)
        clusters = got.get("DBClusters") or []
        if not clusters:
            return encryption_facts(UNKNOWN_ENCRYPTION)
        return rds_facts(self.keys, dict(clusters[0]))

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
        today = (now.date() - _dt.date(1970, 1, 1)).days
        op = ObjectPass(self.indexes, self.id, self.kind, generation=today, budget=budget)
        engine = "aurora-postgresql" if self.t.engine == "postgresql" else "aurora-mysql"
        link = rds_link(self.region, self.identifier, "cluster")
        extra: dict[str, Any] = {"engine": engine, "dbType": "cluster", "readBy": "data_api"}
        tx: str | None = None
        done = False
        if self.facts is None:
            self.facts = self._cluster_facts()

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
                facts=self.facts,
            )
            for f in findings:
                f["_pass"] = pass_id
                f.update(table.rescan)
            store.replace_location(f"{self.id}\n{schema}.{name}", findings)

        try:
            tx = self.client.begin_transaction(
                resourceArn=self.t.cluster_arn,
                secretArn=self.t.secret_arn,
                database=self.t.database,
            )["transactionId"]
            if self.t.engine == "postgresql":
                self._exec("SET TRANSACTION READ ONLY", tx)
            check = grants.postgresql if self.t.engine == "postgresql" else grants.mysql
            try:
                held = check(execute)
            except Exception as err:  # the catalog is hidden from the user
                held = grants.Grants(verified=False, error=error_name(err))
            if not held.verified or held.write:
                refused = "grants_unverifiable" if not held.verified else "db_user_can_write"
                log_event("source.refused", source=self.target, kind="rds", reason=refused)
                if held.write:
                    extra["writeGrants"] = sorted(held.write)[:MAX_WRITE_GRANTS]
                # Named on the coverage too, for a run without DISCOVER (no run summary).
                cov.error = "DbUserCanWrite" if held.write else "GrantsUnverifiable"
                return SourceRun(cov, dict(cursor), refused, extra)
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
                index=op,
                # A table skipped as unchanged keeps its findings in this pass.
                on_skip=lambda sch, n: op.carry(store, f"{self.id}\n{sch}.{n}", pass_id),
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
        op.settle(cov)
        if done:
            cov.pass_complete = True
            drop_other_passes(store, self.id, pass_id)
            return SourceRun(cov, {"passId": None, "after": None}, None, extra)
        if cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"passId": pass_id, "after": after}, None, extra)
