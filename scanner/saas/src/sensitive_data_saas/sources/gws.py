"""What Google Workspace's adapters share: the people in scope, the tenant, the facts.

**People.** `GWS_USERS` (addresses), `GWS_GROUPS` (group addresses, expanded
to their members, nested groups included) and `GWS_ORG_UNITS`
(organizational unit paths) are whose Gmail and My Drive are read. Groups and
units are listed with the Directory API as `GWS_ADMIN_USER`, with the
read-only directory scopes (`admin.directory.user.readonly`,
`admin.directory.group.member.readonly`). Suspended users are left out. A person
is named only by the hash of their address; their address is used only as the
delegation's subject (inside a signed JWT), never in a URL, a cursor or a log.

**Encryption.** Google encrypts Workspace data at rest with its own keys
(`service_managed`). Workspace has no customer-managed key for Gmail or Drive;
a file under client-side encryption is ciphertext to the API and is not read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sensitive_data_core.findings import SERVICE_MANAGED, encryption_facts
from sensitive_data_core.safety import error_name, log_event

from ..config import GwsSettings
from ..google import GoogleApi
from ..resources import owner_hash, store_fields, tenant_hash, user_store_name
from ..scopes import GWS_DIRECTORY
from .base import Context, call_gap

VENDOR = "google_workspace"
DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
_PEOPLE = "gws.people"


@dataclass
class GwsPerson:
    principal_hash: str
    email: str | None = None
    gap: str | None = None
    error: str | None = None

    @property
    def store_name(self) -> str:
        return user_store_name(self.principal_hash)

    def __repr__(self) -> str:
        return f"GwsPerson({self.store_name!r})"


def settings_of(ctx: Context) -> GwsSettings:
    g = ctx.settings.gws
    if g is None:  # pragma: no cover - the adapters run only when it is configured
        raise RuntimeError("google workspace is not configured")
    return g


def tenant_of(ctx: Context) -> str:
    return tenant_hash(settings_of(ctx).customer_id)


def facts_of(ctx: Context) -> dict[str, str]:
    return encryption_facts(SERVICE_MANAGED)


def fields_of(ctx: Context, owner: str | None = None) -> dict[str, Any]:
    return store_fields(VENDOR, tenant_of(ctx), owner)


def directory(ctx: Context) -> GoogleApi:
    return ctx.clients.google(settings_of(ctx).admin_user, GWS_DIRECTORY)


def people(ctx: Context) -> list[GwsPerson]:
    """Everyone in scope, once per run, in a stable order."""
    if _PEOPLE in ctx.memo:
        found: list[GwsPerson] = ctx.memo[_PEOPLE]
        return found
    g = settings_of(ctx)
    api = directory(ctx)
    by_hash: dict[str, GwsPerson] = {}

    def add(email: str) -> None:
        h = owner_hash(email)
        by_hash.setdefault(h, GwsPerson(h, email.lower()))

    fields = "users(primaryEmail,suspended),nextPageToken"
    if g.users or g.groups or g.org_units:
        # Signing in, and the delegation to the administrator, fail the listing as a whole.
        api.get(f"{DIRECTORY}/users", {"customer": "my_customer", "maxResults": "1"})
    for email in g.users:
        try:
            u = api.get(f"{DIRECTORY}/users/{email}", {"fields": "primaryEmail,suspended"})
        except Exception as err:
            h = owner_hash(email)
            by_hash.setdefault(h, GwsPerson(h, None, call_gap(err) or "error", error_name(err)))
            continue
        if not u.get("suspended"):
            add(str(u.get("primaryEmail") or email))
    for group in g.groups:
        try:
            for page, _, _ in api.pages(
                f"{DIRECTORY}/groups/{group}/members",
                "members",
                {"includeDerivedMembership": "true", "maxResults": "200"},
            ):
                for m in page:
                    if (
                        m.get("type") == "USER"
                        and m.get("email")
                        and m.get("status") != "SUSPENDED"
                    ):
                        add(str(m["email"]))
        except Exception as err:  # the group is its own store, with its gap
            h = owner_hash(group)
            by_hash.setdefault(h, GwsPerson(h, None, call_gap(err) or "error", error_name(err)))
            log_event("discovery.failed", kind="gws_group", error=error_name(err))
    for unit in g.org_units:
        try:
            for page, _, _ in api.pages(
                f"{DIRECTORY}/users",
                "users",
                {
                    "customer": "my_customer",
                    "query": f"orgUnitPath='{unit}'",
                    "maxResults": "500",
                    "fields": fields,
                },
            ):
                for u in page:
                    if u.get("primaryEmail") and not u.get("suspended"):
                        add(str(u["primaryEmail"]))
        except Exception as err:
            h = owner_hash(unit)
            by_hash.setdefault(h, GwsPerson(h, None, call_gap(err) or "error", error_name(err)))
            log_event("discovery.failed", kind="gws_org_unit", error=error_name(err))
    out = sorted(by_hash.values(), key=lambda p: p.principal_hash)
    ctx.memo[_PEOPLE] = out
    return out
