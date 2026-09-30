"""The Google Cloud adapters, keyed by their kind (the name `DISCOVER` and the run summary use).

Each is the core's `Adapter` (`sensitive_data_core.adapter`), given a Google
Cloud `Context` (`sources/base.py`).
"""

from __future__ import annotations

from sensitive_data_core.adapter import Adapter

from .base import Context
from .bigquery import BigQueryAdapter
from .bigtable import BigtableAdapter
from .databases import DatabaseAdapter
from .documents import DocumentAdapter
from .gcs import GcsAdapter
from .logging import LoggingAdapter
from .pubsub import PubSubAdapter
from .secrets import SecretManagerAdapter
from .snapshots import SnapshotAdapter
from .spanner import SpannerAdapter

_ALL: list[Adapter[Context]] = [
    GcsAdapter(),
    BigQueryAdapter(),
    DocumentAdapter("firestore"),
    DocumentAdapter("datastore"),
    SpannerAdapter(),
    BigtableAdapter(),
    LoggingAdapter(),
    PubSubAdapter(),
    SnapshotAdapter(),
    SecretManagerAdapter(),
    DatabaseAdapter("cloudsql_postgresql"),
    DatabaseAdapter("cloudsql_mysql"),
    DatabaseAdapter("cloudsql_sqlserver"),
    DatabaseAdapter("alloydb"),
]
ADAPTERS: dict[str, Adapter[Context]] = {a.kind: a for a in _ALL}
