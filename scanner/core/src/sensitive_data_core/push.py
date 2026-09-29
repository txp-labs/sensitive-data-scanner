"""The findings push: how a run's findings document leaves the environment it scans.

A sink takes the findings document and delivers it; the runner does not know
where. Every platform uses the same document and the same split into parts:
EventBridge on AWS (`sensitive_data_scanner.events`), an HTTPS endpoint with
an HMAC signature from anywhere (`sensitive_data_db.sinks`). A part stays
under EventBridge's 256 KB event limit, which also keeps an HTTPS body small;
a larger run sends several, numbered by `part` and `parts`, and the union of
the parts is the document. Only findings leave: never a value.
"""

from __future__ import annotations

import json
from typing import Any, Protocol


class FindingsSink(Protocol):
    """Somewhere a run's findings document goes."""

    def push(self, document: dict[str, Any]) -> int:
        """Deliver the document (in parts). Returns how many parts were accepted."""
        ...


MAX_DETAIL_BYTES = 200_000  # below the 256 KB event limit, with room for the envelope


def event_details(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The document split into event details, each under the size limit.

    `findings`, `coverage` and the discovery summary's `stores` are the lists
    that grow with the estate; each is split across the parts, and the union
    of the parts is the document. Everything else is repeated in every part.
    """
    discovery = document.get("discovery")
    base = {k: v for k, v in document.items() if k not in ("findings", "coverage", "discovery")}
    head = dict(discovery, stores=[]) if isinstance(discovery, dict) else None
    fixed = len(json.dumps(base)) + (len(json.dumps(head)) if head is not None else 0) + 64
    entries: list[tuple[str, Any]] = [("findings", f) for f in document.get("findings", [])]
    entries += [("coverage", c) for c in document.get("coverage", [])]
    if isinstance(discovery, dict):
        entries += [("stores", s) for s in discovery.get("stores", [])]
    chunks: list[list[tuple[str, Any]]] = [[]]
    size = fixed
    for entry in entries:
        n = len(json.dumps(entry[1])) + 1
        if chunks[-1] and size + n > MAX_DETAIL_BYTES:
            chunks.append([])
            size = fixed
        chunks[-1].append(entry)
        size += n
    parts = len(chunks)
    out = []
    for i, chunk in enumerate(chunks):
        detail: dict[str, Any] = {
            **base,
            "part": i + 1,
            "parts": parts,
            "findings": [v for k, v in chunk if k == "findings"],
            "coverage": [v for k, v in chunk if k == "coverage"],
        }
        if head is not None:
            detail["discovery"] = dict(head, stores=[v for k, v in chunk if k == "stores"])
        out.append(detail)
    return out
