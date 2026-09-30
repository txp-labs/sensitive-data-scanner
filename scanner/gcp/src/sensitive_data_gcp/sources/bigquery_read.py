"""BigQuery's read path: a table's rows, as tabledata.list gives them, turned into records the
core's columnar reader reads.

This module is `adapter:bigquery` (scripts/components.py): a change here rescans the objects
it read. Listing, discovery and configuration stay in `bigquery.py` (`listing:<kind>`),
whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

import json
from typing import Any

READS = ("bigquery",)


def _fields(schema: Any) -> list[dict[str, Any]]:
    got = schema.get("fields") if isinstance(schema, dict) else None
    return [f for f in got or [] if isinstance(f, dict)]


def _protected(f: dict[str, Any]) -> bool:
    """A field under a policy tag (column-level security), or holding one."""
    tags = (f.get("policyTags") or {}).get("names") if isinstance(f, dict) else None
    return bool(tags) or any(_protected(x) for x in _fields(f))


def cell(f: dict[str, Any], v: Any, depth: int = 0) -> Any:
    """One `tabledata.list` cell as a plain value, by its schema field. Bytes are dropped."""
    if depth > 15 or v is None:
        return None
    if str(f.get("mode") or "").upper() == "REPEATED":
        inner = {**f, "mode": "NULLABLE"}
        return [cell(inner, x.get("v") if isinstance(x, dict) else x, depth + 1) for x in v]
    kind = str(f.get("type") or "").upper()
    if kind in ("RECORD", "STRUCT"):
        values = v.get("f") if isinstance(v, dict) else None
        return row_of(_fields(f), values or [], depth + 1)
    if kind == "BYTES":
        return None
    return v if isinstance(v, str | int | float | bool) else json.dumps(v)


def row_of(fields: list[dict[str, Any]], cells: list[Any], depth: int = 0) -> dict[str, Any]:
    return {
        str(f.get("name") or ""): cell(f, c.get("v") if isinstance(c, dict) else None, depth)
        for f, c in zip(fields, cells, strict=False)
    }
