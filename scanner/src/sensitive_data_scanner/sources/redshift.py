"""Redshift and Redshift Serverless: discovered, then read with sampled SELECTs (opt-in).

**Discovery** (`DISCOVER` includes `redshift`): `DescribeClusters` for
provisioned clusters, `ListWorkgroups` and `ListNamespaces` for Serverless.
A cluster that is paused or not `available` is reported, not read.

**Reading** (`REDSHIFT_READ`, off by default) goes through the Redshift Data
API with no stored password:

- `iam`: the scanner's own IAM identity (`GetClusterCredentialsWithIAM`, or
  Serverless `GetCredentials`). Redshift maps the role to the database user
  `IAMR:<role name>`, creating it on first use with no privileges beyond
  PUBLIC, so the scanner sees only what an administrator grants that user.
- `db_user`: temporary credentials for an existing read-only database user
  (`GetClusterCredentials` for `REDSHIFT_DB_USER`, never auto-created) on
  provisioned clusters. Serverless has no such mode and uses `iam`.

For each database (`ListDatabases`), the pass lists local base tables from
`svv_tables` and runs `SELECT * FROM "schema"."table" LIMIT n` on each: the
generic sampled SQL of scan/sql.py. Those are the only statements. A finding
names the column: `store_field` with the database, `schema.table` and column.
A store whose user can see no table is reported as `no_grant`.

UNLOAD to S3 was the other way to read. It needs a role attached to the
cluster that can write to the scanner's bucket, and the same database
credentials to run the UNLOAD, so it asks for more (a write path out of the
cluster, and a change to the cluster's roles) for no gain at sample sizes.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import secrets
import time
import urllib.parse
from collections.abc import Callable
from typing import Any

from ..detect.analyzer import Detector
from ..discovery import Discovery, Store, decide, needs_tags
from ..findings import Coverage, console_link, store_field_resource
from ..safety import error_name, log_event
from ..scan.columnar import TableResult
from ..scan.sql import REDSHIFT, Params, sample_tables
from .base import Budget, Context, FindingStore, SourceRun, column_findings
from .exports import drop_other_passes

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("redshift", "redshift-serverless", "redshift-data")

# Databases every cluster has that hold no user data.
INTERNAL_DATABASES = frozenset({"padb_harvest", "sys:internal", "awsdatacatalog"})
DONE = frozenset({"FINISHED"})
FAILED = frozenset({"FAILED", "ABORTED"})


class StatementFailed(Exception):
    """A Data API statement ended FAILED or ABORTED (its message is never kept)."""


class StatementTimeout(Exception):
    """A Data API statement did not finish within its time."""


def _tags(
    raw: list[dict[str, Any]] | None, key: str = "Key", value: str = "Value"
) -> dict[str, str]:
    return {str(t.get(key)): str(t.get(value, "")) for t in raw or [] if t.get(key)}


def _cell(v: dict[str, Any]) -> Any:
    if v.get("isNull"):
        return None
    for k in ("stringValue", "longValue", "doubleValue", "booleanValue", "blobValue"):
        if k in v:
            return v[k]
    return None


class RedshiftAdapter:
    kind = "redshift"

    def discover(self, ctx: Context, out: Discovery) -> None:
        failures: list[BaseException] = []
        for step in (self._clusters, self._workgroups):
            try:
                step(ctx, out)
            except Exception as err:  # the other deployment type is still listed
                failures.append(err)
        if failures:
            raise failures[0]

    def _decide(self, ctx: Context, store: Store, tag_error: str | None = None) -> None:
        decide(store, ctx.config, tag_error)
        if store.status == "pending" and ctx.config.redshift_read == "off":
            store.skip("read_not_configured")

    def _clusters(self, ctx: Context, out: Discovery) -> None:
        rs = ctx.clients.client("redshift")
        for page in rs.get_paginator("describe_clusters").paginate():
            for c in page.get("Clusters", []):
                store = Store("redshift", str(c["ClusterIdentifier"]))
                store.extra.update(deployment="provisioned", database=str(c.get("DBName") or "dev"))
                store.tags = _tags(c.get("Tags"))
                out.stores.append(store)
                state = str(c.get("ClusterStatus") or "")
                if state == "paused":
                    store.skip("paused")  # a query would not resume it; reported instead
                    continue
                if state != "available":
                    store.skip("unsupported")
                    store.extra["state"] = state[:60]
                    continue
                self._decide(ctx, store)

    def _workgroups(self, ctx: Context, out: Discovery) -> None:
        sl = ctx.clients.client("redshift-serverless")
        dbs: dict[str, str] = {}
        for page in sl.get_paginator("list_namespaces").paginate():
            for n in page.get("namespaces", []):
                dbs[str(n.get("namespaceName"))] = str(n.get("dbName") or "dev")
        for page in sl.get_paginator("list_workgroups").paginate():
            for w in page.get("workgroups", []):
                store = Store("redshift", str(w["workgroupName"]))
                store.extra.update(
                    deployment="serverless",
                    database=dbs.get(str(w.get("namespaceName")), "dev"),
                )
                out.stores.append(store)
                state = str(w.get("status") or "")
                if state != "AVAILABLE":
                    store.skip("unsupported")
                    store.extra["state"] = state[:60]
                    continue
                tag_error: str | None = None
                if needs_tags(ctx.config, "redshift"):
                    try:
                        r = sl.list_tags_for_resource(resourceArn=str(w.get("workgroupArn")))
                        store.tags = _tags(r.get("tags"), "key", "value")
                    except Exception as err:
                        tag_error = error_name(err)
                self._decide(ctx, store, tag_error)

    def source(self, ctx: Context, store: Store) -> RedshiftSource | None:
        c = ctx.config
        serverless = store.extra.get("deployment") == "serverless"
        return RedshiftSource(
            ctx.clients.client("redshift-data"),
            identifier=store.name,
            serverless=serverless,
            database=str(store.extra.get("database") or "dev"),
            db_user=c.redshift_db_user if c.redshift_read == "db_user" and not serverless else None,
            region=ctx.region,
            max_rows=c.redshift_max_rows,
            max_tables=c.redshift_max_tables,
            statement_seconds=c.redshift_statement_seconds,
        )


class RedshiftSource:
    """One cluster or workgroup: each database's tables, sampled, over the Data API."""

    kind = "redshift"

    def __init__(
        self,
        client: Any,
        *,
        identifier: str,
        serverless: bool,
        database: str,
        region: str,
        db_user: str | None = None,
        max_rows: int = 1000,
        max_tables: int = 500,
        statement_seconds: int = 60,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.client = client
        self.identifier = identifier
        self.serverless = serverless
        self.database = database
        self.region = region
        self.db_user = db_user
        self.max_rows = max_rows
        self.max_tables = max_tables
        self.statement_seconds = statement_seconds
        self.sleep = sleep
        what = "workgroup" if serverless else "cluster"
        digest = hashlib.sha256(f"{what}|{identifier}".encode()).hexdigest()[:16]
        self.id = f"redshift:{digest}"
        self.target = f"{what}:{identifier}"
        self.service = "redshift_serverless" if serverless else "redshift"

    def _auth(self) -> dict[str, Any]:
        if self.serverless:
            return {"WorkgroupName": self.identifier}
        auth: dict[str, Any] = {"ClusterIdentifier": self.identifier}
        if self.db_user:
            auth["DbUser"] = self.db_user
        return auth

    def link(self) -> str:
        q = urllib.parse.quote(self.identifier, safe="")
        page = (
            f"serverless-workgroup?workgroup={q}"
            if self.serverless
            else f"cluster-details?cluster={q}"
        )
        return console_link(self.region, f"redshiftv2/home?region={self.region}#{page}")

    def databases(self) -> list[str]:
        names: set[str] = set()
        pages = self.client.get_paginator("list_databases").paginate(
            Database=self.database, **self._auth()
        )
        for page in pages:
            names.update(str(d) for d in page.get("Databases", []))
        return sorted(n for n in names if n not in INTERNAL_DATABASES)

    def _execute(
        self, database: str, budget: Budget
    ) -> Callable[[str, Params], list[dict[str, Any]]]:
        def execute(sql: str, params: Params) -> list[dict[str, Any]]:
            args: dict[str, Any] = {"Sql": sql, "Database": database, **self._auth()}
            if params:
                args["Parameters"] = [{"name": n, "value": v} for n, v in params]
            sid = self.client.execute_statement(**args)["Id"]
            until = min(budget.deadline, budget.clock() + self.statement_seconds)
            wait = 0.2
            while True:
                d = self.client.describe_statement(Id=sid)
                status = str(d.get("Status") or "")
                if status in DONE:
                    break
                if status in FAILED:
                    raise StatementFailed
                if budget.clock() >= until:
                    raise StatementTimeout
                (self.sleep or time.sleep)(wait)
                wait = min(2.0, wait * 2)
            if not d.get("HasResultSet"):
                return []
            rows: list[dict[str, Any]] = []
            token: str | None = None
            while True:
                r = self.client.get_statement_result(
                    Id=sid, **({"NextToken": token} if token else {})
                )
                names = [
                    str(c.get("name") or c.get("label") or i)
                    for i, c in enumerate(r.get("ColumnMetadata") or [])
                ]
                for rec in r.get("Records") or []:
                    rows.append({names[i]: _cell(v) for i, v in enumerate(rec) if i < len(names)})
                token = r.get("NextToken")
                if not token:
                    return rows

        return execute

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("redshift", self.target)
        pass_id = cursor.get("passId") or secrets.token_hex(8)
        after: list[str] | None = cursor.get("after")
        seen_at = now.isoformat()
        link = self.link()
        extra: dict[str, Any] = {"deployment": "serverless" if self.serverless else "provisioned"}
        done = False
        try:
            for db in self.databases():
                if after is not None and db < after[0]:
                    continue
                within = after[1:] if after is not None and db == after[0] else None

                def on_table(schema: str, name: str, table: TableResult, db: str = db) -> None:
                    findings = column_findings(
                        table,
                        lambda col: store_field_resource(
                            service=self.service,
                            store=self.identifier,
                            database=db,
                            table=f"{schema}.{name}",
                            field=col,
                            read_by="data_api",
                        ),
                        link,
                        seen_at,
                    )
                    for f in findings:
                        f["_pass"] = pass_id
                    store.replace_location(f"{self.id}\n{db}/{schema}.{name}", findings)

                res = sample_tables(
                    self._execute(db, budget),
                    REDSHIFT,
                    detector=detector,
                    has_room=lambda: budget.has(0),
                    take=budget.take,
                    on_table=on_table,
                    after=within,
                    max_rows=self.max_rows,
                    max_tables=self.max_tables,
                    source=self.target,
                )
                cov.listed += res.listed
                cov.eligible += res.eligible
                cov.scanned += res.scanned
                cov.unreadable += res.unreadable
                cov.partial += res.partial
                cov.bytes_scanned += res.bytes
                cov.test_values += res.test_values
                cov.suppressed += res.suppressed
                cov.redaction_markers += res.redaction_markers
                if res.scanned:
                    cov.formats["sql"] = cov.formats.get("sql", 0) + res.scanned
                if not res.done:
                    after = [db, *(res.after or [])]
                    break
                after = [db, "￿"]  # every table of this database is read
            else:
                done = True
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
        if done:
            cov.pass_complete = True
            gone = drop_other_passes(store, self.id, pass_id)
            if gone:
                log_event("finding.gone", source=self.target, count=gone)
            note = "no_grant" if cov.listed == 0 else None
            return SourceRun(cov, {"passId": None, "after": None}, note, extra)
        if cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"passId": pass_id, "after": after}, None, extra)
