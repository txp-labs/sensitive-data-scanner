"""What every source shares: the run budget, and the store findings go into."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..findings import Coverage


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
