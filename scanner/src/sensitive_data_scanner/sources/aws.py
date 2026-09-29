"""The AWS adapters that plug into discovery and the run through `sources.base.Adapter`.

S3, CloudWatch Logs, DynamoDB, Glue and RDS predate the interface and are
wired in discovery.py and runner.py; every store kind added since is an
adapter here, keyed by its kind (the name `DISCOVER` and the run summary use).
"""

from __future__ import annotations

from .base import Adapter
from .opensearch import OpenSearchAdapter
from .redshift import RedshiftAdapter

_ALL: list[Adapter] = [
    RedshiftAdapter(),
    OpenSearchAdapter(),
]
ADAPTERS: dict[str, Adapter] = {a.kind: a for a in _ALL}
