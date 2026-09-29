"""Stores discovered and reported, with the reason they are not read: never a silent pass.

- **DocumentDB** (instance-based and elastic clusters) and **Neptune**: their
  snapshots cannot be exported to S3 (RDS `StartExportTask` takes Aurora
  MySQL and PostgreSQL, and RDS MySQL, MariaDB and PostgreSQL, only), and the
  scanner holds no database credentials: `no_snapshot_export`.
- **EFS** and **FSx**: a file system is read by mounting it inside its VPC.
  The scanner's Lambda is not in the VPC and mounts nothing, so each is
  reported as `needs_task`: the opt-in file-system task
  (docs/ARCHITECTURE.md) is the way to read it.

Each is listed with the kind's own describe call, decided by the allow and
deny rules like every store, and then reported.
"""

from __future__ import annotations

from typing import Any

from ..discovery import Discovery, Store, decide, needs_tags
from ..safety import error_name
from .base import Context

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("docdb", "neptune", "docdb-elastic", "efs", "fsx")


def _tags(raw: list[dict[str, Any]] | None) -> dict[str, str]:
    return {str(t.get("Key")): str(t.get("Value", "")) for t in raw or [] if t.get("Key")}


class ClusterAdapter:
    """DocumentDB or Neptune clusters (the RDS API, filtered by engine)."""

    def __init__(self, kind: str, service: str, engine: str) -> None:
        self.kind = kind
        self.service = service
        self.engine = engine

    def discover(self, ctx: Context, out: Discovery) -> None:
        pages = (
            ctx.clients.client(self.service)
            .get_paginator("describe_db_clusters")
            .paginate(Filters=[{"Name": "engine", "Values": [self.engine]}])
        )
        for page in pages:
            for c in page.get("DBClusters", []):
                if str(c.get("Engine")) != self.engine:
                    continue
                store = Store(self.kind, str(c["DBClusterIdentifier"]))
                store.extra.update(engine=self.engine, deployment="instance_based")
                store.tags = _tags(c.get("TagList"))
                out.stores.append(store)
                decide(store, ctx.config)
                if store.status == "pending":
                    store.skip("no_snapshot_export")
        if self.kind == "documentdb":
            self._elastic(ctx, out)

    def _elastic(self, ctx: Context, out: Discovery) -> None:
        elastic = ctx.clients.client("docdb-elastic")
        for page in elastic.get_paginator("list_clusters").paginate():
            for c in page.get("clusters", []):
                store = Store(self.kind, str(c.get("clusterName")))
                store.extra.update(engine=self.engine, deployment="elastic")
                out.stores.append(store)
                tag_error: str | None = None
                if needs_tags(ctx.config, self.kind):
                    try:
                        r = elastic.list_tags_for_resource(resourceArn=str(c.get("clusterArn")))
                        store.tags = {str(k): str(v) for k, v in (r.get("tags") or {}).items()}
                    except Exception as err:
                        tag_error = error_name(err)
                decide(store, ctx.config, tag_error)
                if store.status == "pending":
                    store.skip("no_snapshot_export")

    def source(self, ctx: Context, store: Store) -> None:
        return None


class EfsAdapter:
    kind = "efs"

    def discover(self, ctx: Context, out: Discovery) -> None:
        efs = ctx.clients.client("efs")
        for page in efs.get_paginator("describe_file_systems").paginate():
            for fs in page.get("FileSystems", []):
                store = Store("efs", str(fs["FileSystemId"]))
                size = (fs.get("SizeInBytes") or {}).get("Value")
                store.size_bytes = int(size) if size is not None else None
                store.tags = _tags(fs.get("Tags"))
                out.stores.append(store)
                state = str(fs.get("LifeCycleState") or "")
                if state != "available":
                    store.skip("unsupported")
                    store.extra["state"] = state[:60]
                    continue
                decide(store, ctx.config)
                if store.status == "pending":
                    store.skip("needs_task")

    def source(self, ctx: Context, store: Store) -> None:
        return None


class FsxAdapter:
    kind = "fsx"

    def discover(self, ctx: Context, out: Discovery) -> None:
        fsx = ctx.clients.client("fsx")
        for page in fsx.get_paginator("describe_file_systems").paginate():
            for fs in page.get("FileSystems", []):
                store = Store("fsx", str(fs["FileSystemId"]))
                gib = fs.get("StorageCapacity")
                store.size_bytes = int(gib) * 1024**3 if gib is not None else None
                store.extra["fileSystemType"] = str(fs.get("FileSystemType") or "")[:40]
                store.tags = _tags(fs.get("Tags"))
                out.stores.append(store)
                state = str(fs.get("Lifecycle") or "")
                if state not in ("AVAILABLE", "UPDATING"):
                    store.skip("unsupported")
                    store.extra["state"] = state[:60]
                    continue
                decide(store, ctx.config)
                if store.status == "pending":
                    store.skip("needs_task")

    def source(self, ctx: Context, store: Store) -> None:
        return None
