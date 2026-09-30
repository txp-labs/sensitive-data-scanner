"""The Azure adapters, keyed by their kind (the name `DISCOVER` and the run summary use).

Each is the core's `Adapter` (`sensitive_data_core.adapter`), given an Azure
`Context` (`sources/base.py`).
"""

from __future__ import annotations

from sensitive_data_core.adapter import Adapter

from .base import Context
from .blob import BlobAdapter

_ALL: list[Adapter[Context]] = [
    BlobAdapter(),
]
ADAPTERS: dict[str, Adapter[Context]] = {a.kind: a for a in _ALL}
