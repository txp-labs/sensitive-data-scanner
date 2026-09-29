"""OpenSearch Service domains and Serverless collections: sampled documents per index.

**Discovery** (`DISCOVER` includes `opensearch`): `ListDomainNames` and
`DescribeDomains` for managed domains (OpenSearch and Elasticsearch
engines), `ListCollections` and `BatchGetCollection` for Serverless.

**Reading** is signed HTTPS (SigV4) GETs only, so the IAM grant is
`es:ESHttpGet`, the read verb:

1. `GET /_cat/indices?format=json` lists the indices (system indices, whose
   names start with `.`, are left out; data-stream backing indices,
   `.ds-*`, are read);
2. `GET /<index>/_search?size=n` samples up to `n` documents of each;
3. each document's `_source` is read field by field, with the field's name
   as context. A finding names the domain, the index and the top-level
   field (`store_field`).

Not read, and reported:
- a domain inside a VPC (`vpc_only`): the scanner's Lambda is not in the
  domain's VPC, so it cannot reach the endpoint;
- a domain still being created or deleted (`unsupported`);
- a domain whose access policy or fine-grained access control refuses the
  scanner's role (`access_denied`): map the role to a read-only backend role
  to include it;
- Serverless collections unless `OPENSEARCH_SERVERLESS_READ` is on
  (`read_not_configured`): IAM's `aoss:APIAccessAll` cannot be narrowed to
  reads, so the collection's data access policy (`aoss:ReadDocument` for the
  scanner's role) is what keeps them read-only.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import secrets
import urllib.parse
from collections.abc import Callable
from typing import Any, Protocol

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, column_findings
from sensitive_data_core.coverage import Discovery, Store
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.columnar import scan_rows

from ..discovery import decide, needs_tags
from ..resources import console_link
from .base import Context
from .exports import drop_other_passes

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("opensearch", "opensearchserverless")
HTTP = "opensearch-http"  # the key a test puts a fake HTTP client under
MAX_RESPONSE_BYTES = 20 * 1024**2


class HttpError(Exception):
    """An HTTP status the scanner cannot read past. `error_name` gives the status's name
    (`AccessDenied`, `Http500`); the body is never kept."""

    status = 0
    response: dict[str, Any] = {}  # noqa: RUF012 - set per instance by http_error


def http_error(status: int) -> HttpError:
    err = HttpError()
    err.status = status
    err.response = {"Error": {"Code": _status_error(status)}}
    return err


class Http(Protocol):
    def get(self, service: str, url: str) -> tuple[int, bytes]: ...


class SignedHttp:
    """HTTPS GETs signed with the scanner's own credentials (SigV4)."""

    def __init__(self, region: str) -> None:
        self.region = region

    def get(self, service: str, url: str) -> tuple[int, bytes]:
        import boto3  # noqa: PLC0415 - only in AWS, never in the tests
        from botocore.auth import SigV4Auth  # noqa: PLC0415
        from botocore.awsrequest import AWSRequest  # noqa: PLC0415
        from botocore.httpsession import URLLib3Session  # noqa: PLC0415

        credentials = boto3.Session().get_credentials()
        if credentials is None:
            err = http_error(401)
            raise err
        request = AWSRequest(method="GET", url=url)
        SigV4Auth(credentials.get_frozen_credentials(), service, self.region).add_auth(request)
        response = URLLib3Session(timeout=30).send(request.prepare())
        return int(response.status_code), bytes(response.content[:MAX_RESPONSE_BYTES])


def _status_error(status: int) -> str:
    return {401: "Unauthorized", 403: "AccessDenied", 404: "NotFound", 429: "Throttling"}.get(
        status, f"Http{status}"
    )


def _tags(
    raw: list[dict[str, Any]] | None, key: str = "Key", value: str = "Value"
) -> dict[str, str]:
    return {str(t.get(key)): str(t.get(value, "")) for t in raw or [] if t.get(key)}


class OpenSearchAdapter:
    kind = "opensearch"

    def discover(self, ctx: Context, out: Discovery) -> None:
        failures: list[BaseException] = []
        for step in (self._domains, self._collections):
            try:
                step(ctx, out)
            except Exception as err:  # the other deployment type is still listed
                failures.append(err)
        if failures:
            raise failures[0]

    def _domains(self, ctx: Context, out: Discovery) -> None:
        es = ctx.clients.client("opensearch")
        names = [str(d["DomainName"]) for d in es.list_domain_names().get("DomainNames", [])]
        for i in range(0, len(names), 5):  # DescribeDomains takes five at a time
            for d in es.describe_domains(DomainNames=names[i : i + 5]).get("DomainStatusList", []):
                store = Store("opensearch", str(d["DomainName"]))
                store.extra["deployment"] = "managed"
                out.stores.append(store)
                if d.get("Deleted") or not (d.get("Endpoint") or d.get("Endpoints")):
                    store.skip("unsupported")  # being created or deleted
                    store.extra["state"] = "deleted" if d.get("Deleted") else "creating"
                    continue
                if not d.get("Endpoint"):
                    store.skip("vpc_only")  # only a VPC endpoint: out of the Lambda's reach
                    continue
                store.extra["endpoint"] = str(d["Endpoint"])
                tag_error: str | None = None
                if needs_tags(ctx.config, "opensearch"):
                    try:
                        store.tags = _tags(es.list_tags(ARN=str(d.get("ARN"))).get("TagList"))
                    except Exception as err:
                        tag_error = error_name(err)
                decide(store, ctx.config, tag_error)

    def _collections(self, ctx: Context, out: Discovery) -> None:
        aoss = ctx.clients.client("opensearchserverless")
        summaries: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            r = aoss.list_collections(**({"nextToken": token} if token else {}))
            summaries.extend(r.get("collectionSummaries", []))
            token = r.get("nextToken")
            if not token:
                break
        ids = [str(c["id"]) for c in summaries if c.get("id")]
        details: dict[str, dict[str, Any]] = {}
        for i in range(0, len(ids), 100):
            for c in aoss.batch_get_collection(ids=ids[i : i + 100]).get("collectionDetails", []):
                details[str(c.get("id"))] = c
        for c in summaries:
            store = Store("opensearch", str(c.get("name")))
            store.extra["deployment"] = "serverless"
            out.stores.append(store)
            d = details.get(str(c.get("id")), {})
            status = str(c.get("status") or "")
            if status != "ACTIVE" or not d.get("collectionEndpoint"):
                store.skip("unsupported")
                store.extra["state"] = status[:60] or "unknown"
                continue
            store.extra["endpoint"] = str(d["collectionEndpoint"]).removeprefix("https://")
            tag_error: str | None = None
            if needs_tags(ctx.config, "opensearch"):
                try:
                    r = aoss.list_tags_for_resource(resourceArn=str(c.get("arn")))
                    store.tags = _tags(r.get("tags"), "key", "value")
                except Exception as err:
                    tag_error = error_name(err)
            decide(store, ctx.config, tag_error)
            if store.status == "pending" and not ctx.config.opensearch_serverless_read:
                store.skip("read_not_configured")

    def source(self, ctx: Context, store: Store) -> OpenSearchSource | None:
        endpoint = store.extra.get("endpoint")
        if not endpoint:
            return None
        http = ctx.clients.services.get(HTTP) or SignedHttp(ctx.region)
        return OpenSearchSource(
            http,
            name=store.name,
            endpoint=str(endpoint),
            serverless=store.extra.get("deployment") == "serverless",
            region=ctx.region,
            docs_per_index=ctx.config.opensearch_docs_per_index,
            max_indices=ctx.config.opensearch_max_indices,
        )


class OpenSearchSource:
    """One domain or collection: each index, a sample of its documents."""

    kind = "opensearch"

    def __init__(
        self,
        http: Http,
        *,
        name: str,
        endpoint: str,
        serverless: bool,
        region: str,
        docs_per_index: int = 100,
        max_indices: int = 500,
    ) -> None:
        self.http = http
        self.name = name
        self.endpoint = endpoint
        self.serverless = serverless
        self.region = region
        self.docs_per_index = docs_per_index
        self.max_indices = max_indices
        what = "collection" if serverless else "domain"
        digest = hashlib.sha256(f"{what}|{name}".encode()).hexdigest()[:16]
        self.id = f"opensearch:{digest}"
        self.target = f"{what}:{name}"
        self.signing = "aoss" if serverless else "es"
        self.service = "opensearch_serverless" if serverless else "opensearch"

    def _get(self, path: str) -> Any:
        status, body = self.http.get(self.signing, f"https://{self.endpoint}{path}")
        if status != 200:
            err = http_error(status)
            raise err
        return json.loads(body or b"null")

    def _resource(self, index: str) -> Callable[[str], dict[str, Any]]:
        def resource(field: str) -> dict[str, Any]:
            return store_field_resource(
                service=self.service, store=self.name, table=index, field=field, read_by="search"
            )

        return resource

    def link(self) -> str:
        q = urllib.parse.quote(self.name, safe="")
        page = f"collections/{q}" if self.serverless else f"domains/{q}"
        return console_link(
            self.region, f"aos/home?region={self.region}#opensearch/{page}", (self.name,)
        )

    def indices(self) -> list[str]:
        rows = self._get("/_cat/indices?format=json&h=index,status&expand_wildcards=open")
        names = {
            str(r.get("index"))
            for r in rows or []
            if isinstance(r, dict)
            and r.get("index")
            and (not str(r["index"]).startswith(".") or str(r["index"]).startswith(".ds-"))
            and str(r.get("status") or "open") == "open"
        }
        return sorted(names)[: self.max_indices]

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("opensearch", self.target)
        pass_id = cursor.get("passId") or secrets.token_hex(8)
        after: str | None = cursor.get("after")
        seen_at = now.isoformat()
        link = self.link()
        extra = {"deployment": "serverless" if self.serverless else "managed"}
        done = False
        try:
            indices = self.indices()
            cov.listed = len(indices)
            todo = [i for i in indices if after is None or i > after]
            cov.eligible = len(todo)
            done = True
            for index in todo:
                if not budget.has(0):
                    done = False
                    break
                path = f"/{urllib.parse.quote(index, safe='')}/_search?size={self.docs_per_index}"
                try:
                    found = self._get(path)
                except HttpError as err:
                    if err.status in (401, 403):
                        raise  # the whole store is refused: its error, not one index's
                    cov.unreadable += 1
                    log_event("item.unreadable", source=self.target, error=error_name(err))
                    after = index
                    continue
                hits = ((found or {}).get("hits") or {}).get("hits") or []
                docs = [h.get("_source") for h in hits if isinstance(h.get("_source"), dict)]
                size = len(json.dumps(docs, default=str))
                budget.take(size)
                columns = list(dict.fromkeys(k for d in docs for k in d))
                table = scan_rows("json", columns, docs, detector, self.docs_per_index)
                cov.scanned += 1
                cov.bytes_scanned += size
                cov.formats["json"] = cov.formats.get("json", 0) + 1
                total = ((found or {}).get("hits") or {}).get("total")
                count = total.get("value") if isinstance(total, dict) else total
                cov.partial += int(isinstance(count, int) and count > len(docs))
                cov.test_values += table.test_values
                cov.suppressed += table.suppressed
                cov.redaction_markers += table.redaction_markers
                findings = column_findings(table, self._resource(index), link, seen_at)
                for f in findings:
                    f["_pass"] = pass_id
                store.replace_location(f"{self.id}\n{index}", findings)
                after = index
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            done = False
            log_event("source.failed", source=self.target, error=cov.error)
        if done:
            cov.pass_complete = True
            gone = drop_other_passes(store, self.id, pass_id)
            if gone:
                log_event("finding.gone", source=self.target, count=gone)
            return SourceRun(cov, {"passId": None, "after": None}, None, extra)
        if cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"passId": pass_id, "after": after}, None, extra)
