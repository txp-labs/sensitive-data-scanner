"""Exchange Online mail's attachment read path: a message's file attachments downloaded and
read by the core's readers, each recorded by its stable id. Message bodies are never
rescanned (#67), so their reading stays with the listing.

This module is `adapter:m365_mail` (scripts/components.py): a change here rescans the
objects it read. Listing, discovery and configuration stay in `m365_mail.py`
(`listing:<kind>`), whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sensitive_data_core.safety import error_name, log_event

from ..resources import outlook_link, saas_item
from .base import (
    ItemReader,
    bytes_fetch,
)

if TYPE_CHECKING:
    from .m365_mail import MailSource as _Self

SERVICE = "exchange"
FILE_ATTACHMENT = "#microsoft.graph.fileAttachment"
ATTACHMENT_FIELDS = "id,name,size,isInline"
READS = ("m365_mail",)


def _attachments(src: _Self, mid: str, reader: ItemReader) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    max_bytes = src.ctx.settings.max_object_bytes
    for page, _, _ in src.graph.pages(
        f"/users/{src.user_id}/messages/{mid}/attachments", {"$select": ATTACHMENT_FIELDS}
    ):
        for att in page:
            if att.get("@odata.type") != FILE_ATTACHMENT:
                reader.skip("linked_item")
                continue
            if int(att.get("size") or 0) > max_bytes:
                reader.skip("too_large")
                continue
            try:
                out.extend(src._attachment(mid, att, reader))
            except Exception as err:  # one attachment must not stop the message
                reader.cov.unreadable += 1
                log_event("item.unreadable", source=src.target, error=error_name(err))
    return out


def _attachment(
    src: _Self, mid: str, att: dict[str, Any], reader: ItemReader
) -> list[dict[str, Any]]:
    """One file attachment downloaded and read, recorded in the index by its stable id."""
    aid = str(att.get("id") or "")
    name = str(att.get("name") or "attachment")
    data: bytes = src.graph.call(
        f"/users/{src.user_id}/messages/{mid}/attachments/{aid}/$value"
    ).content
    item_id = f"{mid}/{aid}"

    def resource_for(column: str | None) -> Any:
        return saas_item(
            "m365",
            SERVICE,
            src.tenant,
            item_id,
            "attachment",
            owner=src.person.principal_hash,
            name=name,
            column=column,
        )

    found = reader.file(
        name,
        len(data),
        bytes_fetch(data),
        resource_for=resource_for,
        link=outlook_link(mid),
        key=item_id,
    )
    reader.budget.bytes += len(data)
    return found
