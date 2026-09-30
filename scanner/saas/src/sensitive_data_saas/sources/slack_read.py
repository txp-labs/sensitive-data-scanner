"""Slack's file read path: a shared file downloaded from files.slack.com and read by the core's
readers, recorded by its file id. Messages are never rescanned (#67), so their reading stays
with the listing.

This module is `adapter:slack_channel`, `adapter:slack_dm` (scripts/components.py): a change
here rescans the objects it read. Listing, discovery and configuration stay in `slack.py`
(`listing:<kind>`), whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

from sensitive_data_core.safety import error_name, log_event

from ..resources import saas_item
from .base import (
    ItemReader,
)

if TYPE_CHECKING:
    from .slack import _Messages as _Self

VENDOR = "slack"
READS = ("slack_channel", "slack_dm")


def file(
    src: _Self, f: dict[str, Any], r: ItemReader, *, channel: str, container: str, link: str | None
) -> list[dict[str, Any]]:
    fid = str(f.get("id") or "")
    url = str(f.get("url_private_download") or f.get("url_private") or "")
    if f.get("mode") in ("tombstone", "hidden_by_limit") or not fid:
        return []
    if f.get("is_external") or urllib.parse.urlsplit(url).hostname != "files.slack.com":
        r.skip("linked_item")
        return []
    name = str(f.get("name") or "file")
    size = int(f.get("size") or 0)

    def fetch(start: int, end: int) -> bytes:
        return src.api.download(url, start, end)

    def resource_for(column: str | None) -> dict[str, Any]:
        return saas_item(
            VENDOR,
            src.service,
            src.tenant,
            fid,
            "attachment",
            container=container,
            channel=channel,
            name=name,
            column=column,
        )

    try:
        return r.file(name, size, fetch, resource_for=resource_for, link=link, key=fid)
    except Exception as err:  # one file must not stop the message
        r.cov.unreadable += 1
        log_event("item.unreadable", source=src.target, error=error_name(err))
        return []
