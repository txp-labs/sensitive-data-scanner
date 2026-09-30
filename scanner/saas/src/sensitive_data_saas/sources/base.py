"""What a SaaS adapter is given, and what every SaaS source shares.

- `Context`: the settings, the clients, and what adapters share within one
  run (the users a list of principals and groups resolves to).
- `ItemReader`: reads one item's text or one file with the core's readers and
  turns what it found into findings; every source's reads go through it, so
  text, attachments and files are read the same way everywhere.
- `call_gap`: a refused call as a store's gap.
"""

from __future__ import annotations

import datetime as _dt
import html
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore
from sensitive_data_core.coverage import ACCESS_DENIED
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import (
    CUSTOMER_MANAGED_KEY,
    SERVICE_MANAGED,
    Coverage,
    encryption_facts,
    finding_json,
)
from sensitive_data_core.index import ObjectPass
from sensitive_data_core.safety import error_name
from sensitive_data_core.scan.columnar import pyarrow_available
from sensitive_data_core.scan.item import ItemResult, scan_item_text
from sensitive_data_core.scan.objects import ObjectResult, read_object, record

from ..clients import Clients
from ..config import Settings


@dataclass
class Context:
    settings: Settings
    clients: Clients
    memo: dict[str, Any] = field(default_factory=dict)


def vendor_facts(customer_key_id: str | None) -> dict[str, str]:
    """A tenant's at-rest encryption: the vendor's own keys (`service_managed`), or the
    customer's (`customer_managed_key`, named by the hash of the id the customer gave)."""
    if customer_key_id:
        return encryption_facts(CUSTOMER_MANAGED_KEY, customer_key_id)
    return encryption_facts(SERVICE_MANAGED)


# Vendor codes for a call the scanner may not make, beyond the core's ACCESS_DENIED.
DENIED = frozenset(
    {
        *ACCESS_DENIED,
        "Http401",
        "Http403",
        "InvalidAuthenticationToken",
        # Google: the delegation does not cover the scope or the user; a user or drive the
        # caller may not see.
        "unauthorized_client",
        "UNAUTHENTICATED",
    }
)
PROTECTED = frozenset({"ProtectedApiNotApproved"})
NOT_PROVISIONED = frozenset(
    {
        "MailboxNotEnabledForRESTAPI",
        "MailboxNotFound",
        "ResourceNotFound",
        "Request_ResourceNotFound",
        "itemNotFound",
    }
)


def call_gap(err: BaseException) -> str | None:
    """`protected_api`, `not_provisioned`, `throttled` or `access_denied`, else None."""
    name = error_name(err)
    if name in PROTECTED:
        return "protected_api"
    if name in NOT_PROVISIONED:
        return "not_provisioned"
    if name == "Throttled":
        return "throttled"
    if name in DENIED:
        return "access_denied"
    return None


class _Text(HTMLParser):
    """HTML's text: tags dropped, a line break for each block, entities decoded."""

    BLOCK = frozenset({"p", "div", "br", "li", "tr", "td", "th", "h1", "h2", "h3", "table"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_text(markup: str) -> str:
    """The text of an HTML body (a Teams message, an HTML mail body)."""
    parser = _Text()
    try:
        parser.feed(markup)
        parser.close()
    except Exception:  # malformed markup: the tags stripped by pattern instead
        return html.unescape(re.sub(r"<[^>]{0,2000}>", " ", markup))
    return "".join(parser.parts)


def parse_time(v: Any) -> _dt.datetime | None:
    try:
        return _dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        return None


@dataclass
class ItemReader:
    """One source's pass: reads text and files with the core's readers, makes their findings,
    and holds the pass's coverage, the finding store and the budget share."""

    detector: Detector
    settings: Settings
    cov: Coverage
    seen_at: str
    facts: dict[str, Any]
    store: FindingStore
    budget: Budget
    columnar: bool = field(default_factory=pyarrow_available)
    # The pass's object index (#67): a drive's files are recorded by their item id.
    index: ObjectPass | None = None

    def __repr__(self) -> str:
        return f"ItemReader({self.cov.kind!r})"

    def room(self) -> bool:
        return self.budget.has(0) and self.budget.time_left()

    def text(self, text: str, resource: dict[str, Any], link: str | None) -> list[dict[str, Any]]:
        """One message's (or page's) text, as findings on `resource`."""
        item = scan_item_text("message.txt", text, self.detector)
        self.cov.scanned += 1
        self.cov.bytes_scanned += len(text.encode("utf-8", "replace"))
        return self._item(item, resource, link)

    def _item(
        self, item: ItemResult, resource: dict[str, Any], link: str | None
    ) -> list[dict[str, Any]]:
        self.cov.formats[item.format] = self.cov.formats.get(item.format, 0) + 1
        self.cov.redaction_markers += item.redaction_markers
        self.cov.test_values += item.test_values
        self.cov.suppressed += item.suppressed
        return [
            finding_json(resource, link, item.format, cf, self.seen_at, facts=self.facts)
            for cf in item.findings.values()
            if cf.count or cf.occurrences
        ]

    def skip(self, kind: str) -> None:
        self.cov.skipped[kind] = self.cov.skipped.get(kind, 0) + 1

    def file(
        self,
        name: str,
        size: int,
        fetch: Callable[[int, int], bytes],
        *,
        resource_for: Callable[[str | None], dict[str, Any]],
        link: str | None,
        key: str | None = None,
        marker: str | None = None,
        fingerprint: str | None = None,
    ) -> list[dict[str, Any]]:
        """One file or attachment of `size` bytes, read with ranged `fetch`es. What it cannot
        read is counted (`skipped` by kind, `too_large`); a failed fetch is raised. With a
        `key` (a drive item's id), the read is recorded in the pass's object index."""
        if size <= 0:
            return []
        s = self.settings
        got: ObjectResult = read_object(
            name,
            size,
            fetch,
            self.detector,
            max_object_bytes=s.max_object_bytes,
            max_inflated_bytes=s.max_inflated_bytes,
            max_rows=s.columnar_max_rows,
            columnar=self.columnar,
        )
        if self.index is not None and key is not None:
            self.index.record(key, marker=marker, fingerprint=fingerprint, got=got, name=name)
        findings = record(
            got,
            self.cov,
            resource_for=resource_for,
            link=link,
            seen_at=self.seen_at,
            facts=self.facts,
            table_offsets=False,
        )
        return findings or []

    def duplicate(  # noqa: PLR0917 - one file of the pass
        self,
        key: str,
        name: str,
        fingerprint: str | None,
        marker: str | None,
        resource_for: Callable[[str | None], dict[str, Any]],
        link: str | None,
        prefix: str,
        why: Any = None,
    ) -> list[dict[str, Any]] | None:
        """A file whose hash (from the listing) is a file already read under a name of the
        same kind, with components still current (#67 part 5): not downloaded; its findings
        are the original's, as its own (`duplicateOf`). None when it must be read."""
        if self.index is None:
            return None
        original = self.index.duplicate(key, fingerprint, name=name)
        if original is None:
            return None
        findings = self.index.copy_findings(
            original,
            self.store,
            prefix,
            resource_for=resource_for,
            link=link,
            seen_at=self.seen_at,
            facts=self.facts,
        )
        self.index.rescanned(findings, why)
        self.index.record_duplicate(key, original, marker=marker, fingerprint=fingerprint)
        return findings


def bytes_fetch(data: bytes) -> Callable[[int, int], bytes]:
    """A ranged fetch over bytes already downloaded (an attachment's content)."""

    def fetch(start: int, end: int) -> bytes:
        return data[start : end + 1]

    return fetch
