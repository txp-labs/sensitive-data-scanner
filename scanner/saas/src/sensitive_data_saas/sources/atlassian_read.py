"""Jira's and Confluence's attachment read path: an issue's or page's attachments read with
ranged GETs by the core's readers, each recorded by its stable id. Issue and page text is
never rescanned (#67), so its reading stays with the listing.

This module is `adapter:jira_project`, `adapter:confluence_space` (scripts/components.py): a
change here rescans the objects it read. Listing, discovery and configuration stay in
`atlassian.py` (`listing:<kind>`), whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from sensitive_data_core.safety import error_name, log_event

from ..resources import saas_item
from .base import (
    ItemReader,
)

if TYPE_CHECKING:
    from .atlassian import _Atlassian as _Self

VENDOR = "atlassian"
READS = ("jira_project", "confluence_space")


def download_url(base: str, pid: str, aid: str) -> str:
    """A Confluence attachment's content, by its page and its id."""
    return f"{base}/rest/api/content/{pid}/child/attachment/{aid}/download"


def attachments(
    src: _Self,
    items: list[dict[str, Any]],
    r: ItemReader,
    *,
    url_of: Callable[[str], str],
    container_item: str,
    link: str | None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for att in items:
        if not att.get("id"):
            continue
        try:
            out.extend(
                src.attachment(att, r, url_of=url_of, container_item=container_item, link=link)
            )
        except Exception as err:  # one attachment must not stop the item
            r.cov.unreadable += 1
            log_event("item.unreadable", source=src.target, error=error_name(err))
    return out


def attachment(
    src: _Self,
    att: dict[str, Any],
    r: ItemReader,
    *,
    url_of: Callable[[str], str],
    container_item: str,
    link: str | None,
) -> list[dict[str, Any]]:
    """One attachment read with ranged GETs, recorded in the index by its stable id."""
    aid = str(att.get("id") or "")
    name = str(att.get("filename") or att.get("title") or "attachment")
    size = int(att.get("size") or att.get("fileSize") or 0)
    url = url_of(aid)
    item_id = f"{container_item}/{aid}"

    def fetch(start: int, end: int) -> bytes:
        return src.api.download(url, start, end)

    def resource_for(column: str | None) -> Any:
        return saas_item(
            VENDOR,
            src.service,
            src.tenant,
            item_id,
            "attachment",
            container=src.c.key,
            name=name,
            column=column,
        )

    return r.file(name, size, fetch, resource_for=resource_for, link=link, key=item_id)
