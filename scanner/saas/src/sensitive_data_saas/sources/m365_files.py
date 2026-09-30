"""SharePoint and OneDrive files: each drive read incrementally with a delta query.

**Grant.** `Sites.Selected` (preferred): the app reads only the sites an admin
granted it one by one (`read`), and those are named in `M365_SITES`.
`Files.Read.All` reads every OneDrive and site, and is needed for the
OneDrives of the people in scope; `Sites.Read.All` only lists sites for
`M365_SITES=all`.

**Stores.** One per site (`m365_sharepoint`, the site's name masked), whose
document libraries are its sources; one per person's OneDrive
(`m365_onedrive`, `user-<hash>`).

**Reading.** Each drive's items come from `/drives/{id}/root/delta`: the
first pass lists every item, later ones only what changed. A file is read with
ranged GETs of `/drives/{id}/items/{item}/content` (Graph redirects to a
pre-authenticated download; the token is not sent there) by the core's
readers: Word, Excel and PowerPoint files, CSV, JSON, text, and table files by
column. Media, PDFs, archives and older Office files are counted by kind; a
rights-managed (encrypted) Office file is `encrypted`.

- At most `FILES_MAX_PER_DRIVE` files a run; the pass resumes at the page and
  item it stopped at. A deleted file drops its findings.
- Sampling is stable, by the item's id (`SAMPLE_PERCENT`).
- Nothing is checked out, shared, versioned or changed: every call is a GET.

**Gaps.** A site the app was not granted is `access_denied`; a person with no
OneDrive is `not_provisioned`.
"""

from __future__ import annotations

import datetime as _dt
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.objects import sample_point

from ..graph import Graph
from ..resources import saas_item, sharepoint_link
from .base import Context, ItemReader, call_gap
from .m365 import Person, facts_of, fields_of, people, settings_of, tenant_of

ITEM_FIELDS = "id,name,size,file,folder,deleted,lastModifiedDateTime,sharepointIds"


@dataclass
class Drive:
    """One document library or OneDrive: its id, its name, and the host its files are on."""

    drive_id: str
    name: str = ""
    host: str = ""

    def __repr__(self) -> str:
        return f"Drive({redact_digits(self.name)!r})"


@dataclass
class SiteTarget:
    site_id: str
    name: str
    drives: list[Drive] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"SiteTarget({redact_digits(self.name)!r})"


@dataclass
class OneDriveTarget:
    person: Person

    def __repr__(self) -> str:
        return f"OneDriveTarget({self.person!r})"


def _host(web_url: Any) -> str:
    """Only the host of a web URL: its path names the site or the person."""
    return (urllib.parse.urlsplit(str(web_url or "")).hostname or "").lower()


def _drives(graph: Graph, path: str) -> list[Drive]:
    out: list[Drive] = []
    for page, _, _ in graph.pages(path, {"$select": "id,name,webUrl,driveType"}):
        for d in page:
            if d.get("id"):
                out.append(Drive(str(d["id"]), str(d.get("name") or ""), _host(d.get("webUrl"))))
    return out


class SharePointAdapter:
    kind = "m365_sharepoint"

    def discover(self, ctx: Context, out: Discovery) -> None:
        m = settings_of(ctx)
        graph = ctx.clients.graph
        sites: list[tuple[str, str]] = []
        failed: list[tuple[str, BaseException]] = []
        if m.all_sites:
            for page, _, _ in graph.pages("/sites", {"search": "*", "$select": "id,displayName"}):
                sites.extend((str(x["id"]), str(x.get("displayName") or "")) for x in page)
        for ref in m.sites:
            try:
                # `host:/sites/x` (a path) or `host,<site guid>,<web guid>` (an id).
                got = graph.get(f"/sites/{ref}", {"$select": "id,displayName"})
                sites.append((str(got["id"]), str(got.get("displayName") or ref)))
            except Exception as err:  # still a store, with its gap
                failed.append((ref, err))
        for ref, failure in failed:
            store = Store(self.kind, ref.split(":", 1)[-1] or ref)
            store.extra.update(fields_of(ctx))
            gap = call_gap(failure) or "error"
            if gap in ("not_provisioned", "protected_api"):
                store.skip(gap)
            else:
                store.status, store.reason, store.error = "error", gap, error_name(failure)
            out.stores.append(store)
        for site_id, name in sorted(set(sites), key=lambda x: x[1]):
            store = Store(self.kind, name or site_id)
            store.extra.update(fields_of(ctx))
            store.facts = facts_of(ctx)
            out.stores.append(store)
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            try:
                drives = _drives(graph, f"/sites/{site_id}/drives")
            except Exception as err:
                gap = call_gap(err) or "error"
                store.status, store.reason, store.error = "error", gap, error_name(err)
                continue
            store.table = SiteTarget(site_id, name, drives)
            pct, _ = ctx.settings.sampling_for(self.kind, store.name, None)
            store.sample_percent = pct if pct is not None else ctx.settings.sample_percent

    def source(self, ctx: Context, store: Store) -> list[DriveSource] | None:
        t = store.table
        if not isinstance(t, SiteTarget):
            return None
        return [
            DriveSource(
                ctx,
                self.kind,
                "sharepoint",
                d,
                store.name,
                sample_percent=store.sample_percent or 100,
                container=t.name,
            )
            for d in t.drives
        ]


class OneDriveAdapter:
    kind = "m365_onedrive"

    def discover(self, ctx: Context, out: Discovery) -> None:
        for p in people(ctx):
            store = Store(self.kind, p.store_name)
            store.extra.update(fields_of(ctx, p.principal_hash))
            store.facts = facts_of(ctx)
            store.table = OneDriveTarget(p)
            out.stores.append(store)
            if p.gap is not None:
                if p.gap in ("access_denied", "error"):
                    store.status, store.reason, store.error = "error", p.gap, p.error
                else:
                    store.skip(p.gap)
                continue
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            pct, _ = ctx.settings.sampling_for(self.kind, store.name, None)
            store.sample_percent = pct if pct is not None else ctx.settings.sample_percent

    def source(self, ctx: Context, store: Store) -> DriveSource | None:
        t = store.table
        if not isinstance(t, OneDriveTarget) or t.person.user_id is None:
            return None
        return DriveSource(
            ctx,
            self.kind,
            "onedrive",
            None,
            store.name,
            sample_percent=store.sample_percent or 100,
            owner=t.person,
        )


class DriveSource:
    """One drive: a site's document library, or a person's OneDrive (found when it runs)."""

    def __init__(
        self,
        ctx: Context,
        kind: str,
        service: str,
        drive: Drive | None,
        store_name: str,
        *,
        sample_percent: int,
        container: str | None = None,
        owner: Person | None = None,
    ) -> None:
        self.ctx = ctx
        self.graph: Graph = ctx.clients.graph
        self.kind = kind
        self.service = service
        self.drive = drive
        self.owner = owner
        self.container = container
        self.sample_percent = sample_percent
        self.facts: dict[str, Any] | None = None
        self.tenant = tenant_of(ctx)
        key = drive.drive_id if drive is not None else (owner.principal_hash if owner else "")
        self.id = f"{kind}:{key}"
        self.target = store_name if drive is None else f"{store_name}/{drive.name}"

    def __repr__(self) -> str:
        return f"DriveSource({redact_digits(self.target)!r})"

    def _own_drive(self) -> Drive:
        user = self.owner.user_id if self.owner is not None else None
        d = self.graph.get(f"/users/{user}/drive", {"$select": "id,webUrl"})
        return Drive(str(d["id"]), "", _host(d.get("webUrl")))

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        s = self.ctx.settings
        cov = Coverage(self.kind, self.target, sample_percent=self.sample_percent)
        r = ItemReader(detector, s, cov, now.isoformat(), dict(self.facts or {}), store, budget)
        st: dict[str, Any] = dict(cursor)
        note: str | None = None
        done = False
        try:
            drive = self.drive or self._own_drive()
            done = self._drive(drive, st, r, cap=s.files_max)
        except Exception as err:  # recorded by name on the source
            gap = call_gap(err)
            cov.error = None if gap == "throttled" else error_name(err)
            if cov.scanned == 0 and gap is not None:
                note = gap
            log_event("source.failed", source=self.target, error=error_name(err))
        cov.pass_complete = done and cov.error is None
        if not done and cov.error is None:
            cov.backlog = True
        return SourceRun(cov, st, note=note)

    def _drive(self, drive: Drive, st: dict[str, Any], r: ItemReader, *, cap: int) -> bool:
        url = st.get("page") or st.get("delta")
        if url is None:
            query = urllib.parse.urlencode({"$select": ITEM_FIELDS, "$top": "200"})
            url = f"/drives/{drive.drive_id}/root/delta?{query}"
        skip = int(st.get("skip") or 0)
        read = 0
        while True:
            page = self.graph.get(url)
            items = [i for i in page.get("value") or [] if isinstance(i, dict)]
            for i, item in enumerate(items):
                if i < skip:
                    continue
                if read >= cap or not r.room():
                    st.clear()
                    st.update(page=url, skip=i)
                    return False
                read += self._item(drive, item, r)
            skip = 0
            nxt = page.get("@odata.nextLink")
            if nxt:
                url = str(nxt)
                st.clear()
                st.update(page=url, skip=0)
                continue
            delta = page.get("@odata.deltaLink")
            st.clear()
            if delta:
                st["delta"] = str(delta)
            return True

    def _item(self, drive: Drive, item: dict[str, Any], r: ItemReader) -> int:
        iid = str(item.get("id") or "")
        if not iid:
            return 0
        location = f"{self.id}\n{iid}"
        if item.get("deleted") is not None or "@removed" in item:
            r.store.remove_location(location)
            return 0
        if "file" not in item:
            return 0  # a folder, or the root
        r.cov.listed += 1
        size = int(item.get("size") or 0)
        if size == 0:
            return 0
        r.cov.eligible += 1
        if sample_point(iid) >= self.sample_percent:
            r.cov.sampled_out += 1
            return 0
        name = str(item.get("name") or "file")
        r.budget.take(min(size, self.ctx.settings.max_object_bytes))
        ids = item.get("sharepointIds") if isinstance(item.get("sharepointIds"), dict) else {}
        link = sharepoint_link(drive.host, str((ids or {}).get("listItemUniqueId") or ""))
        path = f"/drives/{drive.drive_id}/items/{iid}/content"

        def fetch(start: int, end: int) -> bytes:
            return self.graph.download(path, start, end)

        def resource_for(column: str | None) -> dict[str, Any]:
            return saas_item(
                "m365",
                self.service,
                self.tenant,
                iid,
                "file",
                owner=self.owner.principal_hash if self.owner else None,
                container=self.container,
                channel=drive.name or None,
                name=name,
                column=column,
            )

        try:
            findings = r.file(name, size, fetch, resource_for=resource_for, link=link)
        except Exception as err:  # one file must not stop the pass
            r.cov.unreadable += 1
            log_event("item.unreadable", source=self.target, error=error_name(err))
            return 1
        r.store.replace_location(location, findings)
        return 1
