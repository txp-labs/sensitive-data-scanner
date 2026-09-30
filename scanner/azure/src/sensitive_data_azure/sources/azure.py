"""The Azure adapters, keyed by their kind (the name `DISCOVER` and the run summary use).

Each is the core's `Adapter` (`sensitive_data_core.adapter`), given an Azure
`Context` (`sources/base.py`).
"""

from __future__ import annotations

from sensitive_data_core.adapter import Adapter

from .base import Context
from .blob import BlobAdapter
from .cosmos import CosmosAdapter, MongoClusterAdapter
from .databases import DatabaseAdapter
from .keyvault import KeyVaultAdapter
from .logs import LogAnalyticsAdapter
from .snapshots import DiskSnapshotAdapter
from .storage_services import QueueAdapter, TableAdapter

_ALL: list[Adapter[Context]] = [
    BlobAdapter(),
    TableAdapter(),
    QueueAdapter(),
    CosmosAdapter(),
    MongoClusterAdapter(),
    LogAnalyticsAdapter(),
    DiskSnapshotAdapter(),
    KeyVaultAdapter(),
    DatabaseAdapter("azure_sql"),
    DatabaseAdapter("azure_sql_mi"),
    DatabaseAdapter("azure_postgresql"),
    DatabaseAdapter("azure_mysql"),
    DatabaseAdapter("synapse_sql"),
]
ADAPTERS: dict[str, Adapter[Context]] = {a.kind: a for a in _ALL}
