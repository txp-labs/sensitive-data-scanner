"""What every source shares: the run budget, the store findings go into, and the adapter
interface a kind of store plugs into discovery and the run with.

Nothing here names a cloud. An adapter (sources/aws.py lists AWS's) lists its
stores, decides with the shared allow, deny and sampling rules, and gives the
runner a source per store; the budget, the findings and the run summary stay
the core's.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from ..findings import ClassFinding, Coverage, finding_json

if TYPE_CHECKING:
    from ..config import Config
    from ..discovery import Discovery, Store
    from ..scan.columnar import TableResult
    from .exports import ExportQuota


class Budget:
    """Items, bytes and wall-clock time a run (or one source's share of it) may use."""

    def __init__(
        self,
        max_items: int,
        max_bytes: int,
        deadline: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_items = max_items
        self.max_bytes = max_bytes
        self.deadline = deadline
        self.clock = clock
        self.items = 0
        self.bytes = 0

    def has(self, size: int = 0) -> bool:
        """Room for one more item of `size`. The first item always fits, so one large
        item cannot stall a pass."""
        if self.clock() >= self.deadline:
            return False
        if self.items == 0:
            return True
        return self.items < self.max_items and self.bytes + size <= self.max_bytes

    def take(self, size: int) -> None:
        self.items += 1
        self.bytes += size

    def exhausted(self) -> bool:
        """Nothing more fits: items, bytes or time are spent."""
        return self.items >= self.max_items or self.bytes >= self.max_bytes or not self.time_left()

    def time_left(self) -> bool:
        return self.clock() < self.deadline

    def share(self, ways: int) -> Budget:
        """An even share of what is left, for one of `ways` sources still to run."""
        n = max(1, ways)
        now = self.clock()
        left = max(0.0, self.deadline - now)
        return Budget(
            max(1, (self.max_items - self.items) // n),
            max(1, (self.max_bytes - self.bytes) // n),
            now + left / n,
            self.clock,
        )

    def absorb(self, child: Budget) -> None:
        self.items += child.items
        self.bytes += child.bytes


@dataclass
class SourceRun:
    coverage: Coverage
    cursor: dict[str, Any]
    # For the run summary: why a store was not read this run (an export that is
    # still running, no snapshot yet), and facts about it (the snapshot read).
    note: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class FindingStore:
    """Findings by id, carried between runs in the scanner's own state (never values)."""

    now: str
    items: dict[str, dict[str, Any]] = field(default_factory=dict)
    max_items: int = 20_000
    dropped: int = 0

    def replace_location(self, location: str, findings: list[dict[str, Any]]) -> None:
        """An S3 object was read again: its findings replace what was stored for it."""
        old = {k: v for k, v in self.items.items() if v.get("_location") == location}
        for k in old:
            del self.items[k]
        for f in findings:
            prev = old.get(f["id"])
            if prev:
                f["firstSeenAt"] = prev.get("firstSeenAt", f["firstSeenAt"])
            self.put(location, f)

    def put(self, location: str, finding: dict[str, Any]) -> None:
        if finding["id"] not in self.items and len(self.items) >= self.max_items:
            self.dropped += 1
            return
        self.items[finding["id"]] = {**finding, "_location": location}

    def remove_location(self, location: str) -> int:
        gone = [k for k, v in self.items.items() if v.get("_location") == location]
        for k in gone:
            del self.items[k]
        return len(gone)

    def locations(self, prefix: str) -> list[str]:
        return sorted(
            {v["_location"] for v in self.items.values() if v["_location"].startswith(prefix)}
        )

    def public(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in f.items() if not k.startswith("_")} for f in self.items.values()]


def column_findings(
    table: TableResult,
    resource_for: Callable[[str], dict[str, Any]],
    link: str | None,
    seen_at: str,
) -> list[dict[str, Any]]:
    """Per-column findings with counts only: the rows of a sample are not addressable later."""
    out = []
    for column, item in sorted(table.by_column.items()):
        resource = resource_for(column)
        for cf in item.findings.values():
            cf.offsets = []
            out.append(finding_json(resource, link, table.format, cf, seen_at))
    return out


def class_findings(
    findings: dict[str, ClassFinding],
    resource: dict[str, Any],
    link: str | None,
    fmt: str,
    seen_at: str,
) -> list[dict[str, Any]]:
    """Findings for one field with counts only (a record, message or value read once)."""
    out = []
    for cf in findings.values():
        cf.offsets = []
        out.append(finding_json(resource, link, fmt, cf, seen_at))
    return out


@dataclass
class Context:
    """What an adapter is given: the configuration, a client per service, where it runs."""

    config: Config
    clients: Any  # runner.Clients: `clients.client("<service>")`
    region: str
    account: str
    quota: ExportQuota | None = None


class Adapter(Protocol):
    """One kind of store: how to list it, and the source that reads one of them."""

    kind: str

    def discover(self, ctx: Context, out: Discovery) -> None:
        """Append a Store per store of this kind, decided (read, or skipped with a reason)."""

    def source(self, ctx: Context, store: Store) -> Any | None:
        """The source that reads a pending store, or None (the store is then reported)."""
