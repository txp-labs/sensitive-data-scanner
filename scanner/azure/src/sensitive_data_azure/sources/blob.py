"""Blob Storage and ADLS Gen2: every container of every storage account, read by blob.

**Discovery** (`DISCOVER` includes `azure_blob`): one Resource Graph query
lists the storage accounts of every subscription in scope, with their
encryption, network rules and whether the hierarchical namespace (ADLS Gen2)
is on. Each account's containers and encryption scopes are then listed from
Azure Resource Manager (Reader), so a container is in the run summary even
when the account's firewall keeps the scanner from its data. A store is one
container: `account/container`. A FileStorage account has no Blob service and
is not listed. The job's own state container is `self`.

**Reading** is the Blob service's data plane, with Storage Blob Data Reader:
`List Blobs` in name order, then ranged `Get Blob` reads, the same way the AWS
scanner reads an S3 object (the core's `scan/objects.py`): Parquet, ORC and
Avro by column, gzip and zstd inflated, JSON, CSV, transcripts and text.
ADLS Gen2 is read through the same Blob endpoint (its directories are
zero-length blobs, skipped); nothing is written, leased, rehydrated or copied.

- Incremental: a pass reads only blobs modified since the previous complete
  pass started (less the clock skew), and resumes after the budget at the
  listing page it stopped in.
- Sampling: `samplePercent` (a stable hash of the name) and at most n blobs
  per directory (`maxObjectsPerPrefix`), stated in the coverage, never silent.
- An Archive-tier blob would need a rehydration, which is a write: it is
  counted as skipped `archive_tier`. A blob under a customer-provided key
  (CPK) cannot be read without that key: it is counted in `kmsDenied`.
- A firewall or private-only account that keeps the job out is the store's
  `network` gap; a missing data role is `access_denied`.

**Encryption (1.5).** Every blob is encrypted at rest by Azure Storage. A
finding says under which key: the blob's own encryption scope (from the
listing), else its container's default scope, else the account's key:
`Microsoft.Storage` keys are `service_managed`; a key in Key Vault or Managed
HSM is `customer_managed_key`, named only by the SHA-256 of its versionless
key identifier (`resources.py`, FINDINGS.md).
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, apply_rules, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, finding_json
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.columnar import pyarrow_available
from sensitive_data_core.scan.objects import read_object, sample_point, skip_kind

from ..resources import BlobTarget, ResourceId, azure_fields, blob_resource, portal_link
from .base import Context, key_facts

KIND = "azure_blob"
STORAGE_API = "2023-05-01"
ACCOUNT_SCOPE = "$account-encryption-key"

STORAGE_ACCOUNTS = """resources
| where type =~ 'microsoft.storage/storageaccounts'
| project id, name, subscriptionId, resourceGroup, kind, tags,
    blobEndpoint = tostring(properties.primaryEndpoints.blob),
    tableEndpoint = tostring(properties.primaryEndpoints.table),
    queueEndpoint = tostring(properties.primaryEndpoints.queue),
    tableKeyType = tostring(properties.encryption.services.table.keyType),
    queueKeyType = tostring(properties.encryption.services.queue.keyType),
    hns = tobool(properties.isHnsEnabled),
    keySource = tostring(properties.encryption.keySource),
    keyVaultUri = tostring(properties.encryption.keyvaultproperties.keyvaulturi),
    keyName = tostring(properties.encryption.keyvaultproperties.keyname),
    publicNetworkAccess = tostring(properties.publicNetworkAccess),
    defaultAction = tostring(properties.networkAcls.defaultAction)
| order by id asc"""

# The data plane's answers when the account's network rules keep the caller out.
NETWORK_ERRORS = frozenset({"AuthorizationFailure", "AuthorizationSourceIPMismatch"})
CPK_ERRORS = frozenset({"BlobUsesCustomerSpecifiedEncryption", "BlobCustomerSpecifiedEncryption"})


def _tags(raw: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}


def _account_key_uri(row: dict[str, Any]) -> str | None:
    vault = str(row.get("keyVaultUri") or "").rstrip("/")
    name = str(row.get("keyName") or "")
    return f"{vault}/keys/{name}" if vault and name else None


def decide(store: Store, ctx: Context, tag_error: str | None = None) -> bool:
    """The allow and deny rules, then the store's sampling. False when it was skipped."""
    s = ctx.settings
    if not apply_rules(store, s.allow, s.deny, tag_error):
        return False
    pct, per = s.sampling_for(store.kind, store.name, store.tags)
    if store.kind == KIND:
        store.sample_percent = pct if pct is not None else s.sample_percent
        store.max_per_prefix = per if per is not None else s.blob_max_objects_per_prefix
    return True


class BlobAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        arm = ctx.clients.client("arm")
        own = ctx.settings.state
        for row in ctx.graph(STORAGE_ACCOUNTS):
            endpoint = str(row.get("blobEndpoint") or "")
            if str(row.get("kind") or "") == "FileStorage" or not endpoint:
                continue  # no Blob service: Azure Files only
            rid = ResourceId.parse(str(row.get("id") or ""))
            account = str(row.get("name") or rid.name)
            restricted = (
                str(row.get("publicNetworkAccess") or "").lower() == "disabled"
                or str(row.get("defaultAction") or "").lower() == "deny"
            )
            scopes = {"": key_facts(str(row.get("keySource") or ""), _account_key_uri(row))}
            try:
                for s in arm.list(f"{rid.value}/encryptionScopes", STORAGE_API):
                    props = s.get("properties") or {}
                    key = (props.get("keyVaultProperties") or {}).get("keyUri")
                    scopes[str(s.get("name") or "")] = key_facts(
                        str(props.get("source") or ""), key
                    )
            except Exception as err:  # the account's own key still says most blobs' key
                log_event("discovery.failed", kind=KIND, error=error_name(err))
            try:
                containers = list(
                    arm.list(f"{rid.value}/blobServices/default/containers", STORAGE_API)
                )
            except Exception as err:  # the account is reported, its containers unknown
                store = self._store(rid, f"{account}/*", row, restricted)
                store.facts = dict(scopes[""])
                out.stores.append(store)
                store.status, store.error = "error", error_name(err)
                store.reason = reason_for(store.error)
                continue
            for c in containers:
                container = str(c.get("name") or "")
                store = self._store(rid, f"{account}/{container}", row, restricted)
                default_scope = str((c.get("properties") or {}).get("defaultEncryptionScope") or "")
                scope = "" if default_scope in ("", ACCOUNT_SCOPE) else default_scope
                store.facts = dict(scopes.get(scope) or key_facts(None))
                store.table = BlobTarget(
                    rid=rid,
                    account=account,
                    container=container,
                    endpoint=endpoint,
                    network_restricted=restricted,
                    scopes={**scopes, ACCOUNT_SCOPE: scopes[""]},
                    default=dict(store.facts),
                )
                out.stores.append(store)
                if own is not None and own.account == account and own.container == container:
                    store.skip("self")
                    continue
                decide(store, ctx)

    def _store(self, rid: ResourceId, name: str, row: dict[str, Any], restricted: bool) -> Store:
        store = Store(KIND, name, tags=_tags(row.get("tags")))
        store.extra.update(azure_fields(rid))
        if row.get("hns"):
            store.extra["hierarchicalNamespace"] = True
        if restricted:
            store.extra["networkRestricted"] = True
        return store

    def source(self, ctx: Context, store: Store) -> BlobSource | None:
        t = store.table
        if not isinstance(t, BlobTarget):
            return None
        s = ctx.settings
        return BlobSource(
            ctx.clients.client("blob", t.endpoint).get_container_client(t.container),
            target=t,
            sample_percent=store.sample_percent or s.sample_percent,
            max_per_prefix=store.max_per_prefix or 0,
            max_object_bytes=s.max_object_bytes,
            max_inflated_bytes=s.max_inflated_bytes,
            max_rows=s.columnar_max_rows,
            skew_seconds=s.skew_seconds,
        )


def _page_token(pages: Any) -> str | None:
    token = getattr(pages, "continuation_token", None)
    return str(token) if token else None


class BlobSource:
    """One container (or a prefix of it): its blobs, listed in name order and read."""

    kind = KIND

    def __init__(
        self,
        container: Any,
        *,
        target: BlobTarget,
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
        self.container = container
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
        self.facts: dict[str, Any] | None = None  # the store's (runner), for blobs without a scope
        self.id = f"blob:{target.account}/{target.container}/{prefix}"
        self.target = f"{target.account}/{target.container}/{prefix}"

    def __repr__(self) -> str:
        return f"BlobSource({self.t!r})"

    def _blob_facts(self, props: Any) -> dict[str, Any] | None:
        scope = str(getattr(props, "encryption_scope", None) or "")
        if scope and scope in self.t.scopes:
            return dict(self.t.scopes[scope])
        if scope:
            return {"atRestEncryption": "unknown"}  # a scope created after discovery
        return self.facts or self.t.default or None

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
        try:
            pages = self.container.list_blobs(
                name_starts_with=self.prefix or None, results_per_page=self.page_size
            ).by_page(continuation_token=token)
            while budget.time_left():
                page_token = token
                try:
                    page = list(next(pages))
                except StopIteration:
                    done = True
                    break
                stop = False
                read_in_page = 0
                for i, props in enumerate(page):
                    if i < skip:
                        continue
                    read_in_page = i + 1
                    got = self._one(
                        props,
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
                    token, skip = page_token, read_in_page
                    break
                skip = 0
                token = _page_token(pages)
                if token is None:
                    done = True
                    break
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if cov.error in NETWORK_ERRORS and cov.scanned == 0:
                note = "network"
            log_event("source.failed", source=self.target, error=cov.error)
        if done and cov.error is None:
            cov.pass_complete = True
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
        if cov.error is None and cov.scanned == 0 and cov.unreadable > 0:
            cov.error = first_error
            if first_error in NETWORK_ERRORS:
                note = "network"
        return SourceRun(cov, new_cursor, note=note)

    def _one(
        self,
        props: Any,
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
        """One listed blob: read, skipped or counted. None when the budget has no room."""
        name = str(props.name)
        size = int(getattr(props, "size", 0) or 0)
        cov.listed += 1
        modified = getattr(props, "last_modified", None)
        if since is not None and modified is not None and modified <= since:
            return cur_dir, cur_n, None
        if name.endswith("/") or size == 0:
            return cur_dir, cur_n, None  # a directory (ADLS Gen2) or an empty blob
        cov.eligible += 1
        if sample_point(name) >= self.sample_percent:
            cov.sampled_out += 1
            return cur_dir, cur_n, None
        tier = str(getattr(props, "blob_tier", None) or "")
        if tier.lower() == "archive":
            cov.skipped["archive_tier"] = cov.skipped.get("archive_tier", 0) + 1
            return cur_dir, cur_n, None
        kind = skip_kind(name)
        if kind is not None:
            cov.skipped[kind] = cov.skipped.get(kind, 0) + 1
            return cur_dir, cur_n, None
        directory = name.rsplit("/", 1)[0] if "/" in name else ""
        if self.max_per_prefix:
            if directory != cur_dir:
                cur_dir, cur_n = directory, 0
            if cur_n >= self.max_per_prefix:
                cov.sampled_out += 1
                return cur_dir, cur_n, None
        want = min(size, self.max_object_bytes)
        if not budget.has(want):
            return None
        budget.take(want)
        cur_n += 1
        if getattr(props, "encryption_key_sha256", None):
            cov.unreadable += 1
            cov.kms_denied += 1  # a customer-provided key: unreadable without it
            return cur_dir, cur_n, "BlobUsesCustomerSpecifiedEncryption"
        try:
            self._read(props, cov=cov, detector=detector, store=store, seen_at=seen_at)
        except Exception as err:  # one bad blob must not stop the pass
            cov.unreadable += 1
            e = error_name(err)
            if e in CPK_ERRORS:
                cov.kms_denied += 1
            log_event("item.unreadable", source=self.target, error=e)
            return cur_dir, cur_n, e
        return cur_dir, cur_n, None

    def _read(
        self,
        props: Any,
        *,
        cov: Coverage,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
    ) -> None:
        name = str(props.name)
        size = int(getattr(props, "size", 0) or 0)
        version = getattr(props, "version_id", None) or None

        def fetch(start: int, end: int) -> bytes:
            kwargs: dict[str, Any] = {"offset": start, "length": end - start + 1}
            if version:
                kwargs["version_id"] = version
            data: bytes = self.container.download_blob(name, **kwargs).readall()
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
        cov.partial += int(got.partial)
        if got.skipped is not None:
            cov.skipped[got.skipped] = cov.skipped.get(got.skipped, 0) + 1
            return
        cov.scanned += 1
        cov.bytes_scanned += got.read
        facts = self._blob_facts(props)
        link = portal_link(self.t.rid, "containersList")
        location = f"{self.id}\n{name}"
        findings: list[dict[str, Any]] = []
        if got.table is not None:
            table = got.table
            cov.formats[table.format] = cov.formats.get(table.format, 0) + 1
            cov.redaction_markers += table.redaction_markers
            cov.test_values += table.test_values
            cov.suppressed += table.suppressed
            for column, item in sorted(table.by_column.items()):
                resource = blob_resource(self.t, name, version, column=column)
                findings.extend(
                    finding_json(resource, link, table.format, cf, seen_at, facts=facts)
                    for cf in item.findings.values()
                    if cf.count or cf.occurrences
                )
        elif got.item is not None:
            item = got.item
            cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
            cov.redaction_markers += item.redaction_markers
            cov.test_values += item.test_values
            cov.suppressed += item.suppressed
            resource = blob_resource(self.t, name, version)
            findings = [
                finding_json(resource, link, item.format, cf, seen_at, facts=facts)
                for cf in item.findings.values()
                if cf.count or cf.occurrences
            ]
        store.replace_location(location, findings)

    def prune(self, store: FindingStore, budget: Budget, limit: int = 200) -> int:
        """Drop stored findings whose blob is gone."""
        gone = 0
        for location in store.locations(f"{self.id}\n")[:limit]:
            if not budget.time_left():
                break
            name = location.split("\n", 1)[1]
            try:
                self.container.get_blob_client(name).get_blob_properties()
            except Exception as err:  # unknown: keep the finding
                if error_name(err) in ("BlobNotFound", "ResourceNotFoundError"):
                    gone += store.remove_location(location)
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        return gone
