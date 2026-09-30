"""Google Drive: each person's My Drive, and shared drives, with `drive.readonly` only.

**Grant.** Domain-wide delegation of `https://www.googleapis.com/auth/drive.readonly`.
My Drive is read as its owner (the files they own, not what others share with
them: each file is read once, in its owner's store). A shared drive is read as
`GWS_ADMIN_USER`, who must be a member of it (a Viewer is enough); with
`GWS_SHARED_DRIVES=all`, the administrator's domain access lists every shared
drive (`drives.list`, `useDomainAdminAccess`).

**Stores.** `gws_drive` per person (`user-<hash>`); `gws_shared_drive` per
shared drive (its name, masked).

**Reading.** The first pass lists the drive's files (`files.list`), after
taking the drive's change token (`changes.getStartPageToken`); later runs read
only what changed since (`changes.list`), and a removed or trashed file drops
its findings. A file is read with ranged `alt=media` GETs by the core's
readers (Word, Excel and PowerPoint files, CSV, JSON, text, table files by
column); a Google Docs, Sheets or Slides file is exported (`files.export`) as
text or CSV and read the same way. Media, PDFs, archives and other Google
types (Forms, Drawings) are counted by kind; a shortcut is `linked_item`.

- At most `FILES_MAX_PER_DRIVE` files a run; the pass resumes at its page and
  file. Sampling is stable, by file id.
- Nothing is changed: no permission, no revision, no view mark.

**Gaps.** A shared drive the administrator is not a member of is
`access_denied`; a person without Drive is `not_provisioned`.
"""

from __future__ import annotations

import datetime as _dt
import urllib.parse
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, Link
from sensitive_data_core.index import Indexes, ObjectPass, md5_fingerprint
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.objects import sample_point

from ..google import GoogleApi
from ..resources import saas_item
from ..scopes import GWS_DRIVE
from .base import Context, ItemReader, bytes_fetch
from .gws import VENDOR, GwsPerson, facts_of, fields_of, settings_of, tenant_of
from .gws_gmail import gap_of, person_stores

DRIVE = "https://www.googleapis.com/drive/v3"
FILE_FIELDS = "id,name,mimeType,size,trashed,ownedByMe,md5Checksum,version,modifiedTime"
EXPORTS = {
    "application/vnd.google-apps.document": ("text/plain", ".txt"),
    "application/vnd.google-apps.spreadsheet": ("text/csv", ".csv"),
    "application/vnd.google-apps.presentation": ("text/plain", ".txt"),
}
FOLDER = "application/vnd.google-apps.folder"
SHORTCUT = "application/vnd.google-apps.shortcut"
GOOGLE_TYPE = "application/vnd.google-apps."
MAX_EXPORT_BYTES = 10 * 1024 * 1024  # Drive's own limit on an export


def drive_link(file_id: str) -> Link:
    q = urllib.parse.urlencode({"id": file_id})
    return Link(f"https://drive.google.com/open?{q}", (file_id,))


@dataclass
class MyDrive:
    person: GwsPerson

    def __repr__(self) -> str:
        return f"MyDrive({self.person!r})"


@dataclass
class SharedDrive:
    drive_id: str
    name: str

    def __repr__(self) -> str:
        return f"SharedDrive({redact_digits(self.name)!r})"


class DriveAdapter:
    kind = "gws_drive"

    def discover(self, ctx: Context, out: Discovery) -> None:
        person_stores(ctx, out, self.kind, MyDrive)

    def source(self, ctx: Context, store: Store) -> DriveSource | None:
        t = store.table
        if not isinstance(t, MyDrive) or t.person.email is None:
            return None
        api = ctx.clients.google(t.person.email, GWS_DRIVE)
        return DriveSource(
            ctx,
            api,
            self.kind,
            "drive",
            store.name,
            sample_percent=store.sample_percent or 100,
            owner=t.person.principal_hash,
        )


class SharedDriveAdapter:
    kind = "gws_shared_drive"

    def discover(self, ctx: Context, out: Discovery) -> None:
        g = settings_of(ctx)
        api = ctx.clients.google(g.admin_user, GWS_DRIVE)
        drives: list[tuple[str, str]] = []
        if g.all_shared_drives:
            for page, _, _ in api.pages(
                f"{DRIVE}/drives",
                "drives",
                {
                    "useDomainAdminAccess": "true",
                    "pageSize": "100",
                    "fields": "nextPageToken,drives(id,name)",
                },
            ):
                drives.extend((str(d["id"]), str(d.get("name") or "")) for d in page if d.get("id"))
        for drive_id in g.shared_drives:
            try:
                d = api.get(
                    f"{DRIVE}/drives/{drive_id}",
                    {"useDomainAdminAccess": "true", "fields": "id,name"},
                )
                drives.append((drive_id, str(d.get("name") or drive_id)))
            except Exception as err:  # still a store, with its gap
                store = Store(self.kind, drive_id)
                store.extra.update(fields_of(ctx))
                gap = gap_of(err, frozenset({"NOT_FOUND"})) or "error"
                if gap == "not_provisioned":
                    store.skip(gap)
                else:
                    store.status, store.reason, store.error = "error", gap, error_name(err)
                out.stores.append(store)
        for drive_id, name in sorted(set(drives), key=lambda x: (x[1], x[0])):
            store = Store(self.kind, name or drive_id)
            store.extra.update(fields_of(ctx))
            store.facts = facts_of(ctx)
            store.table = SharedDrive(drive_id, name)
            out.stores.append(store)
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            pct, _ = ctx.settings.sampling_for(self.kind, store.name, None)
            store.sample_percent = pct if pct is not None else ctx.settings.sample_percent

    def source(self, ctx: Context, store: Store) -> DriveSource | None:
        t = store.table
        if not isinstance(t, SharedDrive):
            return None
        api = ctx.clients.google(settings_of(ctx).admin_user, GWS_DRIVE)
        return DriveSource(
            ctx,
            api,
            self.kind,
            "shared_drive",
            store.name,
            sample_percent=store.sample_percent or 100,
            drive=t,
        )


def file_marker(f: dict[str, Any]) -> str:
    """What changes when a Drive file changes: its version (bumped on every change), its
    modified time and size."""
    return f"{f.get('version') or ''}|{f.get('modifiedTime') or ''}|{f.get('size') or 0}"


class DriveSource:
    """One drive: a person's My Drive, or a shared drive."""

    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(
        self,
        ctx: Context,
        api: GoogleApi,
        kind: str,
        service: str,
        store_name: str,
        *,
        sample_percent: int,
        owner: str | None = None,
        drive: SharedDrive | None = None,
    ) -> None:
        self.ctx = ctx
        self.api = api
        self.kind = kind
        self.service = service
        self.owner = owner
        self.drive = drive
        self.sample_percent = sample_percent
        self.facts: dict[str, Any] | None = None
        self.tenant = tenant_of(ctx)
        self.id = f"{kind}:{drive.drive_id if drive is not None else owner}"
        self.target = store_name
        self.read = 0

    def __repr__(self) -> str:
        return f"DriveSource({redact_digits(self.target)!r})"

    def _scope(self) -> dict[str, str]:
        """The query parameters that point a call at this drive."""
        if self.drive is None:
            return {}
        return {
            "driveId": self.drive.drive_id,
            "supportsAllDrives": "true",
            "includeItemsFromAllDrives": "true",
        }

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        self.read = 0
        cov = Coverage(self.kind, self.target, sample_percent=self.sample_percent)
        r = ItemReader(
            detector, self.ctx.settings, cov, now.isoformat(), dict(self.facts or {}), store, budget
        )
        r.index = ObjectPass(self.indexes, self.id, self.kind)
        st: dict[str, Any] = dict(cursor)
        note: str | None = None
        done = False
        try:
            done = self._changes(st, r) if st.get("mode") == "changes" else self._list(st, r)
        except Exception as err:  # recorded by name on the source
            gap = gap_of(err)
            if self.drive is not None and error_name(err) == "NOT_FOUND":
                gap = "access_denied"  # Drive answers 404 to one who is not a member
            cov.error = None if gap == "throttled" else error_name(err)
            if cov.scanned == 0 and gap is not None:
                note = gap
            log_event("source.failed", source=self.target, error=error_name(err))
        cov.pass_complete = done and cov.error is None
        if not done and cov.error is None:
            cov.backlog = True
        return SourceRun(cov, st, note=note)

    def _room(self, r: ItemReader) -> bool:
        return self.read < self.ctx.settings.files_max and r.room()

    def _list(self, st: dict[str, Any], r: ItemReader) -> bool:
        if st.get("mode") != "list":
            got = self.api.get(f"{DRIVE}/changes/startPageToken", self._scope() or None)
            st.clear()
            st.update(mode="list", start=str(got.get("startPageToken") or ""), page=None, skip=0)
        params: dict[str, Any] = {
            "pageSize": "200",
            "fields": f"nextPageToken,files({FILE_FIELDS})",
            "q": "trashed=false" if self.drive is not None else "'me' in owners and trashed=false",
            **self._scope(),
        }
        if self.drive is not None:
            params["corpora"] = "drive"
        token = st.get("page")
        skip = int(st.get("skip") or 0)
        for page, nxt, _ in self.api.pages(f"{DRIVE}/files", "files", params, token=token):
            for i, f in enumerate(page):
                if i < skip:
                    continue
                if not self._room(r):
                    st.update(page=token, skip=i)
                    return False
                self._file(f, r)
            skip = 0
            token = nxt
            st.update(page=token, skip=0)
        start = str(st.get("start") or "")
        st.clear()
        st.update(mode="changes", changes=start)
        return True

    def _changes(self, st: dict[str, Any], r: ItemReader) -> bool:
        params: dict[str, Any] = {
            "pageSize": "200",
            "fields": (
                f"nextPageToken,newStartPageToken,changes(fileId,removed,file({FILE_FIELDS}))"
            ),
            **self._scope(),
        }
        token = str(st.get("page") or st.get("changes") or "")
        skip = int(st.get("skip") or 0)
        while token:
            page = self.api.get(f"{DRIVE}/changes", {**params, "pageToken": token})
            changes = [c for c in page.get("changes") or [] if isinstance(c, dict)]
            for i, c in enumerate(changes):
                if i < skip:
                    continue
                fid = str(c.get("fileId") or "")
                f = c.get("file") if isinstance(c.get("file"), dict) else None
                if c.get("removed") or f is None or f.get("trashed"):
                    r.store.remove_location(f"{self.id}\n{fid}")
                    if r.index is not None:
                        r.index.forget(fid)
                    continue
                if self.drive is None and f.get("ownedByMe") is False:
                    continue  # another person's file: read in its owner's store
                if not self._room(r):
                    st.clear()
                    st.update(mode="changes", page=token, skip=i)
                    return False
                self._file(f, r)
            skip = 0
            if page.get("nextPageToken"):
                token = str(page["nextPageToken"])
                st.clear()
                st.update(mode="changes", page=token, skip=0)
                continue
            st.clear()
            st.update(mode="changes", changes=str(page.get("newStartPageToken") or token))
            return True
        return True

    def _file(self, f: dict[str, Any], r: ItemReader) -> None:
        fid = str(f.get("id") or "")
        mime = str(f.get("mimeType") or "")
        if not fid or mime == FOLDER:
            return
        r.cov.listed += 1
        if mime == SHORTCUT:
            r.skip("linked_item")
            return
        name = str(f.get("name") or "file")
        export = EXPORTS.get(mime)
        if mime.startswith(GOOGLE_TYPE) and export is None:
            r.skip("document")  # Forms, Drawings, Sites, Maps: no text export read
            return
        size = int(f.get("size") or 0)
        if export is None and size == 0:
            return
        r.cov.eligible += 1
        if sample_point(fid) >= self.sample_percent:
            r.cov.sampled_out += 1
            return
        self.read += 1
        link = drive_link(fid)

        def resource_for(column: str | None) -> dict[str, Any]:
            return saas_item(
                VENDOR,
                self.service,
                self.tenant,
                fid,
                "file",
                owner=self.owner,
                container=self.drive.name if self.drive is not None else None,
                name=name,
                column=column,
            )

        scope = {"supportsAllDrives": "true"} if self.drive is not None else {}
        try:
            if export is not None:
                mime_out, suffix = export
                resp = self.api.call(f"{DRIVE}/files/{fid}/export", {"mimeType": mime_out, **scope})
                data: bytes = resp.content[:MAX_EXPORT_BYTES]
                r.budget.take(len(data))
                findings = r.file(
                    name + suffix,
                    len(data),
                    bytes_fetch(data),
                    resource_for=resource_for,
                    link=link,
                    key=fid,
                    marker=file_marker(f),
                )
            else:
                r.budget.take(min(size, self.ctx.settings.max_object_bytes))

                def fetch(start: int, end: int) -> bytes:
                    return self.api.download(
                        f"{DRIVE}/files/{fid}", start, end, {"alt": "media", **scope}
                    )

                findings = r.file(
                    name,
                    size,
                    fetch,
                    resource_for=resource_for,
                    link=link,
                    key=fid,
                    marker=file_marker(f),
                    fingerprint=md5_fingerprint(f.get("md5Checksum")),
                )
        except Exception as err:  # one file must not stop the pass
            if r.index is not None:
                r.index.record(fid, marker=file_marker(f), unreadable=True)
            r.cov.unreadable += 1
            log_event("item.unreadable", source=self.target, error=error_name(err))
            return
        r.store.replace_location(f"{self.id}\n{fid}", findings)
