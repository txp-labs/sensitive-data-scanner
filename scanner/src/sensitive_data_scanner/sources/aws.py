"""The AWS adapters that plug into discovery and the run through `sources.base.Adapter`.

S3, CloudWatch Logs, DynamoDB, Glue and RDS predate the interface and are
wired in discovery.py and runner.py; every store kind added since is an
adapter here, keyed by its kind (the name `DISCOVER` and the run summary use).
"""

from __future__ import annotations

from .base import Adapter
from .coverage_only import ClusterAdapter, EfsAdapter, FsxAdapter
from .ebs import BackupAdapter, EbsAdapter
from .opensearch import OpenSearchAdapter
from .redshift import RedshiftAdapter
from .streams import FirehoseAdapter, KinesisAdapter, SqsAdapter

_ALL: list[Adapter] = [
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
]
ADAPTERS: dict[str, Adapter] = {a.kind: a for a in _ALL}
