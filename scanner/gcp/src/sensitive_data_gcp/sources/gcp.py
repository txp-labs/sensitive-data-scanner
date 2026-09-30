"""The Google Cloud adapters, keyed by their kind (the name `DISCOVER` and the run summary use).

Each is the core's `Adapter` (`sensitive_data_core.adapter`), given a Google
Cloud `Context` (`sources/base.py`).
"""

from __future__ import annotations

from sensitive_data_core.adapter import Adapter

from .base import Context
from .gcs import GcsAdapter

_ALL: list[Adapter[Context]] = [
    GcsAdapter(),
]
ADAPTERS: dict[str, Adapter[Context]] = {a.kind: a for a in _ALL}
