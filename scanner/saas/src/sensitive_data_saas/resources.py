"""SaaS items in findings: named by vendor, the tenant's hash, masked names and hashed people.

A SaaS item's names hold what people typed: a site's or a team's name, a
channel's, a file's or an attachment's. Its owner is a person, named by an
address, which is PII. So a finding's `saas_item` resource carries:

- `vendor` and `service` (`m365`, `exchange`), fixed words;
- `tenantHash`: the SHA-256 of the tenant's id (for Microsoft 365, the Entra
  tenant id, lower-case);
- `ownerHash`: the SHA-256 of the mailbox's or drive's owner, by principal name
  or address, lower-case; the address is never written, masked or not;
- `container`, `channel` and `name`: masked like keys (the core's
  `redact_digits`);
- `itemId`, the vendor's id, masked like a key, and `itemHash`, its SHA-256, so
  two items whose ids mask alike stay two findings.

A run summary's store is named the same way: a person's store (a mailbox, a
OneDrive) is `user-<first 16 hex of ownerHash>`.

A `link` goes to the item in the vendor's own web app, built from ids only
(an Outlook on the web message by its id, a SharePoint document by its unique
id, a Teams channel by its ids), and is dropped when any of them had to be
masked (the core's `Link`).
"""

from __future__ import annotations

import hashlib
import urllib.parse
from typing import Any

from sensitive_data_core.findings import Link
from sensitive_data_core.safety import redact_digits


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def tenant_hash(tenant: str) -> str:
    return sha(tenant.strip().lower())


def owner_hash(principal: str) -> str:
    """How a person is named: the SHA-256 of their principal name or address, lower-case."""
    return sha(principal.strip().lower())


def user_store_name(principal_hash: str) -> str:
    return f"user-{principal_hash[:16]}"


def store_fields(vendor: str, tenant: str, owner: str | None = None) -> dict[str, Any]:
    """A run summary store's `vendor`, `tenantHash` and (a person's store) `ownerHash`."""
    out: dict[str, Any] = {"vendor": vendor, "tenantHash": tenant}
    if owner is not None:
        out["ownerHash"] = owner
    return out


def saas_item(
    vendor: str,
    service: str,
    tenant: str,
    item_id: str,
    part: str,
    *,
    owner: str | None = None,
    container: str | None = None,
    channel: str | None = None,
    name: str | None = None,
    column: str | None = None,
) -> dict[str, Any]:
    """One item (or a part of one; for a table file, one column of it): `tenant` and
    `owner` are hashes already."""
    names = {
        k: v
        for k, v in (
            ("container", container),
            ("channel", channel),
            ("itemId", item_id),
            ("name", name),
            ("column", column),
        )
        if v is not None
    }
    masked = {k: redact_digits(v)[:1024] for k, v in names.items()}
    out: dict[str, Any] = {
        "type": "saas_item",
        "vendor": vendor,
        "service": service,
        "tenantHash": tenant,
        "itemHash": sha(item_id),
        "part": part,
        **masked,
    }
    if owner is not None:
        out["ownerHash"] = owner
    if masked != {k: v[:1024] for k, v in names.items()}:
        out["keyMasked"] = True
    return out


def outlook_link(message_id: str) -> Link:
    """The message in Outlook on the web, by its id (its owner, or a delegate, opens it)."""
    q = urllib.parse.urlencode(
        {"ItemID": message_id, "exvsurl": "1", "viewmodel": "ReadMessageItem"}
    )
    return Link(f"https://outlook.office365.com/owa/?{q}", (message_id,))


def sharepoint_link(host: str, unique_id: str) -> Link | None:
    """A SharePoint or OneDrive file by its unique id, on its own host."""
    if not host.endswith(".sharepoint.com") or not unique_id:
        return None
    q = urllib.parse.urlencode({"sourcedoc": "{" + unique_id + "}", "action": "default"})
    return Link(f"https://{host}/_layouts/15/Doc.aspx?{q}", (host, unique_id))


def teams_channel_link(channel_id: str, team_id: str) -> Link:
    """A Teams channel by its ids (no name, and no tenant id: findings name the tenant only
    by its hash)."""
    q = urllib.parse.urlencode({"groupId": team_id})
    path = urllib.parse.quote(channel_id, safe="")
    return Link(f"https://teams.microsoft.com/l/channel/{path}/?{q}", (channel_id, team_id))
