"""The AWS adapters that plug into discovery and the run through the core's `Adapter`
(`sensitive_data_core.adapter`), each given an AWS `Context` (`sources/base.py`).

S3, CloudWatch Logs, DynamoDB, Glue and RDS predate the interface and are
wired in discovery.py and runner.py; every store kind added since is an
adapter here, keyed by its kind (the name `DISCOVER` and the run summary use).
"""

from __future__ import annotations

from sensitive_data_core.adapter import Adapter

from .base import Context
from .config_stores import SecretsAdapter, SsmAdapter
from .coverage_only import ClusterAdapter, EfsAdapter, FsxAdapter
from .ebs import BackupAdapter, EbsAdapter
from .opensearch import OpenSearchAdapter
from .other_stores import (
    ElastiCacheAdapter,
    KeyspacesAdapter,
    MemoryDbAdapter,
    TimestreamAdapter,
)
from .redshift import RedshiftAdapter
from .streams import FirehoseAdapter, KinesisAdapter, SqsAdapter

_ALL: list[Adapter[Context]] = [
    RedshiftAdapter(),
    OpenSearchAdapter(),
    ClusterAdapter("documentdb", "docdb", "docdb"),
    ClusterAdapter("neptune", "neptune", "neptune"),
    EbsAdapter(),
    BackupAdapter(),
    EfsAdapter(),
    FsxAdapter(),
    KinesisAdapter(),
    FirehoseAdapter(),
    SqsAdapter(),
    SsmAdapter(),
    SecretsAdapter(),
    ElastiCacheAdapter(),
    MemoryDbAdapter(),
    TimestreamAdapter(),
    KeyspacesAdapter(),
]
ADAPTERS: dict[str, Adapter[Context]] = {a.kind: a for a in _ALL}
