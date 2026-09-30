"""What Microsoft 365's adapters share: the people in scope, the mail scope check, the facts.

**People.** `M365_USERS` (principal names or object ids) and `M365_GROUPS`
(group object ids, expanded to their transitive members that are users) are
whose mailboxes, OneDrives and chats are read. Each is resolved once per run
with `User.Read.All` (`GET /users/{id}`) and `GroupMember.Read.All`
(`GET /groups/{id}/transitiveMembers/microsoft.graph.user`), keeping the object
id (what every later URL uses, so no address is ever in a URL or a cursor) and
the hash of the principal name. A principal that cannot be resolved is still a
store, named by the hash of what was configured, with its gap.

**The mail scope check.** `Mail.Read` as an application reads every mailbox in
the tenant unless Exchange limits it: RBAC for Applications (a management scope
on a role assignment) or, the older way, an application access policy. The
scanner cannot see that limit, so it tests it: before any mail is read, it asks
for one message of `M365_MAIL_SCOPE_CHECK`, a mailbox outside the scope. Only
Exchange refusing (`ErrorAccessDenied`) lets mail be read. If that mailbox can
be read, every mailbox is `unscoped_grant` and none is read; without the
setting, or when the answer says nothing (the mailbox does not exist), every
mailbox is `scope_unverified`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sensitive_data_core.safety import error_name, log_event

from ..config import M365Settings
from ..graph import Graph
from ..resources import owner_hash, store_fields, tenant_hash, user_store_name
from .base import Context, call_gap, vendor_facts

VENDOR = "m365"
_PEOPLE = "m365.people"
_SCOPE = "m365.scope"


@dataclass
class Person:
    """A user in scope: the object id URLs use, and the hash that names them."""

    principal_hash: str
    user_id: str | None = None
    gap: str | None = None
    error: str | None = None

    @property
    def store_name(self) -> str:
        return user_store_name(self.principal_hash)

    def __repr__(self) -> str:
        return f"Person({self.store_name!r})"


def settings_of(ctx: Context) -> M365Settings:
    m = ctx.settings.m365
    if m is None:  # pragma: no cover - the adapters run only when it is configured
        raise RuntimeError("m365 is not configured")
    return m


def tenant_of(ctx: Context) -> str:
    return tenant_hash(settings_of(ctx).tenant)


def facts_of(ctx: Context) -> dict[str, str]:
    return vendor_facts(settings_of(ctx).customer_key_id)


def fields_of(ctx: Context, owner: str | None = None) -> dict[str, Any]:
    return store_fields(VENDOR, tenant_of(ctx), owner)


def _resolve(graph: Graph, principal: str) -> Person:
    try:
        user = graph.get(f"/users/{principal}", {"$select": "id,userPrincipalName"})
    except Exception as err:
        return Person(owner_hash(principal), None, call_gap(err) or "error", error_name(err))
    upn = str(user.get("userPrincipalName") or principal)
    return Person(owner_hash(upn), str(user.get("id") or "") or None)


def people(ctx: Context) -> list[Person]:
    """Everyone in scope, resolved once per run, in a stable order."""
    if _PEOPLE in ctx.memo:
        found: list[Person] = ctx.memo[_PEOPLE]
        return found
    m = settings_of(ctx)
    graph = ctx.clients.graph
    # Signing in fails the listing as a whole (every kind names it), not person by person.
    graph.app.token()
    by_hash: dict[str, Person] = {}
    for principal in m.users:
        p = _resolve(graph, principal)
        by_hash.setdefault(p.principal_hash, p)
    for group in m.groups:
        try:
            for page, _, _ in graph.pages(
                f"/groups/{group}/transitiveMembers/microsoft.graph.user",
                {"$select": "id,userPrincipalName", "$top": "999"},
            ):
                for u in page:
                    upn = str(u.get("userPrincipalName") or u.get("id") or "")
                    if upn:
                        h = owner_hash(upn)
                        by_hash.setdefault(h, Person(h, str(u.get("id") or "") or None))
        except Exception as err:  # the group is its own store, with its gap
            h = owner_hash(group)
            by_hash.setdefault(h, Person(h, None, call_gap(err) or "error", error_name(err)))
            log_event("discovery.failed", kind="m365_group", error=error_name(err))
    out = sorted(by_hash.values(), key=lambda p: p.principal_hash)
    ctx.memo[_PEOPLE] = out
    return out


def mail_scope(ctx: Context) -> str | None:
    """None when the mail grant is proved scoped; else the reason no mailbox is read."""
    if _SCOPE in ctx.memo:
        got: str | None = ctx.memo[_SCOPE]
        return got
    m = settings_of(ctx)
    result: str | None
    if m.mail_scope_check is None:
        result = "scope_unverified"
    else:
        try:
            ctx.clients.graph.get(
                f"/users/{m.mail_scope_check}/messages", {"$top": "1", "$select": "id"}
            )
            result = "unscoped_grant"
        except Exception as err:
            name = error_name(err)
            result = None if name in ("ErrorAccessDenied", "Http403") else "scope_unverified"
    if result is not None:
        log_event("source.refused", source="m365_mail", kind="m365_mail", reason=result)
    ctx.memo[_SCOPE] = result
    return result
