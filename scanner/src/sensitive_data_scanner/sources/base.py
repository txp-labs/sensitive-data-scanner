"""What an AWS adapter is given: the configuration, a client per service, where it runs.

The adapter interface itself, the budget and the finding store are the
core's (`sensitive_data_core.adapter`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..config import Config
    from .exports import ExportQuota


@dataclass
class Context:
    """What an adapter is given: the configuration, a client per service, where it runs."""

    config: Config
    clients: Any  # runner.Clients: `clients.client("<service>")`
    region: str
    account: str
    quota: ExportQuota | None = None
