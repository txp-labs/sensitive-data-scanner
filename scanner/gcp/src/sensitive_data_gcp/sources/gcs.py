"""Cloud Storage: every bucket under the organization or folder, read by object.

**Discovery** (`DISCOVER` includes `gcs`): Cloud Asset Inventory lists every
bucket in scope (`storage.googleapis.com/Bucket`) with its labels and default
Cloud KMS key, so a bucket is in the run summary even when a service perimeter
keeps the job from its objects. A store is one bucket. The job's own state
bucket is `self`.

**Reading** is the JSON API with `storage.objects.list` and
`storage.objects.get` (Storage Object Viewer, or the custom read-only role):
objects listed in name order, then ranged media GETs, read the way the AWS
scanner reads an S3 object (the core's `scan/objects.py`): Parquet, ORC and
Avro by column, gzip and zstd inflated, JSON, CSV, transcripts and text.
Nothing is written, copied, rewritten or composed.

- Incremental: a pass reads only objects updated since the previous complete
  pass started (less the clock skew), and resumes after the budget at the
  listing page it stopped in.
- Sampling: `samplePercent` (a stable hash of the name) and at most n objects
  per directory (`maxObjectsPerPrefix`), stated in the coverage, never silent.
- An object under a customer-supplied key (CSEK) cannot be read without that
  key, which the scanner never has: it is counted in `kmsDenied`.
- A bucket inside a VPC Service Controls perimeter the job is outside of is the
  store's `network` gap; a missing permission is `access_denied`; a
  requester-pays bucket (reading would bill the job's project) is
  `requester_pays`.

**Encryption (1.5).** Every object is encrypted at rest. A finding says under
which key: the object's own `kmsKeyName` (a CMEK, `customer_managed_key`, named
only by the SHA-256 of the key's versionless resource name), else Google's own
keys (`service_managed`). The run summary gives the bucket's default key.
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
from sensitive_data_core.index import UNINDEXED, Indexes, ObjectPass, Stale, md5_fingerprint
from sensitive_data_core.safety import error_name, log_event, redact_digits
from sensitive_data_core.scan.columnar import pyarrow_available
from sensitive_data_core.scan.objects import planned_bytes, read_object, record, sample_point

from ..clients import STORAGE_API, Rest
from ..resources import Located, console_link, gcs_object_resource
from .base import Context, kms_facts, labels
from .common import call_gap

KIND = "gcs"
ASSET_TYPE = "storage.googleapis.com/Bucket"
LIST_FIELDS = (
    "items(name,size,updated,generation,kmsKeyName,customerEncryption,storageClass,md5Hash),"
    "nextPageToken"
)


@dataclass
class BucketTarget:
    """One bucket: where it is, and its default key."""

    where: Located
    bucket: str
    default: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"BucketTarget({redact_digits(self.bucket)!r})"


def _bucket_name(row: dict[str, Any]) -> str:
    name = str(row.get("name") or "")
    return str(row.get("displayName") or name.rsplit("/", 1)[-1])


def object_url(bucket: str, name: str) -> str:
    q = urllib.parse.quote
    return f"{STORAGE_API}/b/{q(bucket, safe='')}/o/{q(name, safe='')}"


class GcsAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        own = ctx.settings.state_bucket
        for row in ctx.search(ASSET_TYPE):
            bucket = _bucket_name(row)
            if not bucket:
                continue
            where = Located(ctx.project_of(row), str(row.get("name") or ""))
            store = Store(KIND, bucket, tags=labels(row))
            store.extra.update(where.fields())
            keys = [str(k) for k in row.get("kmsKeys") or [] if k] or (
                [str(row["kmsKey"])] if row.get("kmsKey") else []
            )
            store.facts = kms_facts(keys[0] if keys else None)
            store.table = BucketTarget(where, bucket, dict(store.facts))
            out.stores.append(store)
            if own is not None and bucket == own:
                store.skip("self")
                continue
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            pct, per = ctx.settings.sampling_for(KIND, bucket, store.tags)
            store.sample_percent = pct if pct is not None else ctx.settings.sample_percent
            store.max_per_prefix = (
                per if per is not None else ctx.settings.gcs_max_objects_per_prefix
            )

    def source(self, ctx: Context, store: Store) -> GcsSource | None:
        t = store.table
        if not isinstance(t, BucketTarget):
            return None
        s = ctx.settings
        return GcsSource(
            ctx.rest,
            t,
            sample_percent=store.sample_percent or s.sample_percent,
            max_per_prefix=store.max_per_prefix or 0,
            max_object_bytes=s.max_object_bytes,
            max_inflated_bytes=s.max_inflated_bytes,
            max_rows=s.columnar_max_rows,
            skew_seconds=s.skew_seconds,
        )


def _time(v: Any) -> _dt.datetime | None:
    try:
        return _dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        return None


def gcs_marker(obj: dict[str, Any]) -> str:
    """What changes when an object changes: its generation (a new one per write), and size."""
    return f"{obj.get('generation') or ''}|{obj.get('size') or 0}|{obj.get('updated') or ''}"


class GcsSource:
    """One bucket (or a prefix of it): its objects, listed in name order and read."""

    kind = KIND
    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

    def __init__(
        self,
        rest: Rest,
        target: BucketTarget,
        *,
        prefix: str = "",
        sample_percent: int = 100,
        max_per_prefix: int = 0,
        max_object_bytes: int = 20 * 1024**2,
        max_inflated_bytes: int = 100 * 1024**2,
        max_rows: int = 10_000,
        skew_seconds: int = 300,
        columnar: bool | None = None,
        page_size: int = 1000,
    ) -> None:
        self.rest = rest
        self.t = target
        self.prefix = prefix
        self.sample_percent = sample_percent
        self.max_per_prefix = max_per_prefix
        self.max_object_bytes = max_object_bytes
        self.max_inflated_bytes = max_inflated_bytes
        self.max_rows = max_rows
        self.skew = _dt.timedelta(seconds=skew_seconds)
        self.columnar = pyarrow_available() if columnar is None else columnar
        self.page_size = page_size
        self.facts: dict[str, Any] | None = None  # the store's (runner)
        self.id = f"gcs:{target.bucket}/{prefix}"
        self.target = f"{target.bucket}/{prefix}"
        self._op = ObjectPass(None, self.id, self.kind)

    def __repr__(self) -> str:
        return f"GcsSource({self.t!r})"

    def _page(self, token: str | None) -> tuple[list[dict[str, Any]], str | None]:
        params: list[tuple[str, str]] = [
            ("maxResults", str(self.page_size)),
            ("fields", LIST_FIELDS),
        ]
        if self.prefix:
            params.append(("prefix", self.prefix))
        if token:
            params.append(("pageToken", token))
        page = self.rest.get(
            f"{STORAGE_API}/b/{urllib.parse.quote(self.t.bucket, safe='')}/o", params
        )
        items = [i for i in page.get("items") or [] if isinstance(i, dict)]
        return items, str(page.get("nextPageToken") or "") or None

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target, sample_percent=self.sample_percent)
        watermark = cursor.get("watermark")
        pass_started = cursor.get("passStartedAt") or now.isoformat()
        token: str | None = cursor.get("token")
        skip = int(cursor.get("skip") or 0)
        since = (_dt.datetime.fromisoformat(watermark) - self.skew) if watermark else None
        seen_at = now.isoformat()
        cur_dir: str | None = cursor.get("prefixDir")
        cur_n = int(cursor.get("prefixCount") or 0)
        done = False
        first_error: str | None = None
        note: str | None = None
        generation = int(cursor.get("indexPass") or 0) + (0 if cursor.get("passStartedAt") else 1)
        self._op = ObjectPass(
            self.indexes,
            self.id,
            self.kind,
            generation=generation,
            columnar=self.columnar,
            budget=budget,
        )
        try:
            while budget.time_left():
                items, next_token = self._page(token)
                stop = False
                read_in_page = 0
                for i, obj in enumerate(items):
                    if i < skip:
                        continue
                    read_in_page = i + 1
                    got = self._one(
                        obj,
                        cov=cov,
                        since=since,
                        detector=detector,
                        store=store,
                        seen_at=seen_at,
                        budget=budget,
                        cur_dir=cur_dir,
                        cur_n=cur_n,
                    )
                    if got is None:
                        cov.backlog = True
                        stop = True
                        read_in_page = i
                        break
                    cur_dir, cur_n, err = got
                    first_error = first_error or err
                if stop:
                    skip = read_in_page
                    break
                skip = 0
                token = next_token
                if token is None:
                    done = True
                    break
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if cov.scanned == 0:
                note = call_gap(err)
                if note == "access_denied":
                    note = None  # an error the run summary names by the error itself
            log_event("source.failed", source=self.target, error=cov.error)
        if cov.error is None:
            # Then the rescans this run met, within their capped share (#67).
            for obj, why in self._op.rescans.drain(budget, self._planned):
                err_name = self._guarded(obj, cov, detector, store, seen_at, why)
                first_error = first_error or err_name
        if done and cov.error is None:
            cov.pass_complete = True
            self._op.complete()
            new_cursor: dict[str, Any] = {"watermark": pass_started, "passStartedAt": None}
            cur_dir, cur_n = None, 0
        else:
            if cov.error is None:
                cov.backlog = True
            new_cursor = {
                "watermark": watermark,
                "passStartedAt": pass_started,
                "token": token,
                "skip": skip,
            }
        if self.max_per_prefix:
            new_cursor["prefixDir"] = cur_dir
            new_cursor["prefixCount"] = cur_n
        new_cursor["indexPass"] = generation
        self._op.settle(cov)
        if cov.error is None and cov.scanned == 0 and cov.unreadable > 0:
            cov.error = first_error
        return SourceRun(cov, new_cursor, note=note)

    def _one(
        self,
        obj: dict[str, Any],
        *,
        cov: Coverage,
        since: _dt.datetime | None,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        budget: Budget,
        cur_dir: str | None,
        cur_n: int,
    ) -> tuple[str | None, int, str | None] | None:
        """One listed object: read, skipped or counted. None when the budget has no room."""
        name = str(obj.get("name") or "")
        size = int(obj.get("size") or 0)
        cov.listed += 1
        self._op.seen(name)
        if name.endswith("/") or size == 0:
            return cur_dir, cur_n, None  # a folder placeholder or an empty object
        updated = _time(obj.get("updated"))
        changed = since is None or updated is None or updated > since
        decision = self._op.decide(name, changed=changed, marker=gcs_marker(obj))
        if not (decision.read or decision.rescan):
            return cur_dir, cur_n, None  # unchanged, and read with what it would be now
        cov.eligible += int(decision.read)
        if sample_point(name) >= self.sample_percent:
            cov.sampled_out += int(decision.read)
            return cur_dir, cur_n, None
        directory = name.rsplit("/", 1)[0] if "/" in name else ""
        counted = decision.read or (decision.why is not None and decision.why.reason == UNINDEXED)
        if self.max_per_prefix and counted:
            if directory != cur_dir:
                cur_dir, cur_n = directory, 0
            if cur_n >= self.max_per_prefix:
                cov.sampled_out += int(decision.read)
                return cur_dir, cur_n, None
        if decision.rescan:
            self._op.offer(obj, decision)  # read after this run's changes, if it fits
            return cur_dir, cur_n + int(counted), None
        want = planned_bytes(name, size, self.max_object_bytes)
        if not budget.has(want):
            return None
        budget.take(want)
        cur_n += 1
        return cur_dir, cur_n, self._guarded(obj, cov, detector, store, seen_at)

    def _planned(self, obj: dict[str, Any]) -> int:
        size = int(obj.get("size") or 0)
        return planned_bytes(str(obj.get("name") or ""), size, self.max_object_bytes)

    def _guarded(  # noqa: PLR0917 - one object of the pass
        self,
        obj: dict[str, Any],
        cov: Coverage,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        why: Stale | None = None,
    ) -> str | None:
        """One object read (a change, or a rescan for `why`); the error's name when it could
        not be."""
        name = str(obj.get("name") or "")
        fingerprint = md5_fingerprint(obj.get("md5Hash"))
        original = self._op.duplicate(name, fingerprint)
        if original is not None:
            # The same bytes as an object read with what it would be read with now (#67).
            generation = str(obj.get("generation") or "") or None
            where = self.t.where
            findings = self._op.copy_findings(
                original,
                store,
                f"{self.id}\n",
                resource_for=lambda column: gcs_object_resource(
                    where, self.t.bucket, name, generation, column=column
                ),
                link=console_link(
                    f"storage/browser/{urllib.parse.quote(self.t.bucket, safe='')}",
                    {"project": where.project},
                    self.t.bucket,
                ),
                seen_at=seen_at,
                facts=kms_facts(str(obj.get("kmsKeyName") or "") or None),
            )
            self._op.rescanned(findings, why)
            store.replace_location(f"{self.id}\n{name}", findings)
            self._op.record_duplicate(
                name, original, marker=gcs_marker(obj), fingerprint=fingerprint
            )
            return None
        if obj.get("customerEncryption"):
            self._op.record(name, marker=gcs_marker(obj), unreadable=True)
            cov.unreadable += 1
            cov.kms_denied += 1  # a customer-supplied key: unreadable without it
            return "CUSTOMER_SUPPLIED_KEY"
        try:
            self._read(obj, cov=cov, detector=detector, store=store, seen_at=seen_at, why=why)
        except Exception as err:  # one bad object must not stop the pass
            self._op.record(name, marker=gcs_marker(obj), unreadable=True)
            cov.unreadable += 1
            e = error_name(err)
            log_event("item.unreadable", source=self.target, error=e)
            return e
        return None

    def _read(
        self,
        obj: dict[str, Any],
        *,
        cov: Coverage,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        why: Stale | None = None,
    ) -> None:
        name = str(obj.get("name") or "")
        size = int(obj.get("size") or 0)
        generation = str(obj.get("generation") or "") or None
        url = object_url(self.t.bucket, name)

        def fetch(start: int, end: int) -> bytes:
            params = {"alt": "media", **({"generation": generation} if generation else {})}
            resp = self.rest.call(
                "GET", url, params=params, headers={"Range": f"bytes={start}-{end}"}
            )
            data: bytes = resp.content
            return data

        got = read_object(
            name,
            size,
            fetch,
            detector,
            max_object_bytes=self.max_object_bytes,
            max_inflated_bytes=self.max_inflated_bytes,
            max_rows=self.max_rows,
            columnar=self.columnar,
        )
        fingerprint = md5_fingerprint(obj.get("md5Hash"))
        self._op.record(name, marker=gcs_marker(obj), fingerprint=fingerprint, got=got)
        facts = kms_facts(str(obj.get("kmsKeyName") or "") or None)
        where = self.t.where
        link = console_link(
            f"storage/browser/{urllib.parse.quote(self.t.bucket, safe='')}",
            {"project": where.project},
            self.t.bucket,
        )
        findings = record(
            got,
            cov,
            resource_for=lambda column: gcs_object_resource(
                where, self.t.bucket, name, generation, column=column
            ),
            link=link,
            seen_at=seen_at,
            facts=facts,
        )
        self._op.rescanned(findings, why)
        if findings is None:
            return
        location = f"{self.id}\n{name}"
        store.replace_location(location, findings)

    def prune(self, store: FindingStore, budget: Budget, limit: int = 200) -> int:
        """Drop stored findings whose object is gone."""
        gone = 0
        for location in store.locations(f"{self.id}\n")[:limit]:
            if not budget.time_left():
                break
            name = location.split("\n", 1)[1]
            try:
                self.rest.get(object_url(self.t.bucket, name), {"fields": "name"})
            except Exception as err:  # unknown: keep the finding
                if error_name(err) == "NOT_FOUND":
                    gone += store.remove_location(location)
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        return gone
