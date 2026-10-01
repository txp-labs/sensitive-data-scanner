"""OpenSearch domains and Serverless collections: discovery, and sampled documents per index.

The OpenSearch and OpenSearch Serverless control planes answer through
botocore's Stubber; the signed HTTPS reads go to a fake that records every
request. Every value is made up.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

import boto3
from botocore.stub import Stubber
from jsonschema import Draft202012Validator

from aws_fixtures import Env, config
from conftest import REPO
from sensitive_data_scanner.config import read_config, store_rules
from sensitive_data_scanner.sources.opensearch import HTTP
from synthetic import CARDS, SSN_A, SSN_B, dashed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
OS = frozenset({"opensearch"})
ENDPOINT = "search-logs-abc.us-west-2.es.amazonaws.com"
COLLECTION_ENDPOINT = "abc123.us-west-2.aoss.amazonaws.com"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []
    # Every finding the runner writes says what storage encryption it sat under (1.5).
    assert all("atRestEncryption" in f for f in doc["findings"])


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in doc["discovery"]["stores"]}


def client(service: str) -> tuple[Any, Stubber]:
    c: Any = boto3.client(
        service,  # type: ignore[call-overload]
        region_name="us-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
    )
    stub = Stubber(c)
    stub.activate()
    return c, stub


class FakeHttp:
    """Answers signed GETs by host and path; records (signing service, method, url)."""

    def __init__(self) -> None:
        self.routes: dict[str, tuple[int, Any]] = {}
        self.seen: list[tuple[str, str]] = []

    def route(self, host: str, path: str, body: Any, status: int = 200) -> None:
        self.routes[f"https://{host}{path}"] = (status, body)

    def get(self, service: str, url: str) -> tuple[int, bytes]:
        self.seen.append((service, url))
        status, body = self.routes.get(url, (404, {"error": "no route"}))
        return status, json.dumps(body).encode()


def domain(name: str, **kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "DomainId": f"123456789012/{name}",
        "DomainName": name,
        "ARN": f"arn:aws:es:us-west-2:123456789012:domain/{name}",
        "ClusterConfig": {},
    }
    d.update(kw)
    return d


class Aws:
    def __init__(self, env: Env) -> None:
        self.es, self.es_stub = client("opensearch")
        self.aoss, self.aoss_stub = client("opensearchserverless")
        self.http = FakeHttp()
        env.clients.services.update(
            {"opensearch": self.es, "opensearchserverless": self.aoss, HTTP: self.http}
        )

    def estate(self, *, collections: bool = True) -> None:
        names = ["logs", "private", "gone"]
        self.es_stub.add_response(
            "list_domain_names", {"DomainNames": [{"DomainName": n} for n in names]}
        )
        self.es_stub.add_response(
            "describe_domains",
            {
                "DomainStatusList": [
                    domain("logs", Endpoint=ENDPOINT),
                    domain("private", Endpoints={"vpc": "vpc-private.es.amazonaws.com"}),
                    domain("gone", Deleted=True),
                ]
            },
            {"DomainNames": names},
        )
        summaries = (
            [
                {"id": "col-1", "name": "vectors", "status": "ACTIVE", "arn": "arn:c1"},
                {"id": "col-2", "name": "newbie", "status": "CREATING", "arn": "arn:c2"},
            ]
            if collections
            else []
        )
        self.aoss_stub.add_response("list_collections", {"collectionSummaries": summaries})
        if collections:
            self.aoss_stub.add_response(
                "batch_get_collection",
                {
                    "collectionDetails": [
                        {
                            "id": "col-1",
                            "name": "vectors",
                            "collectionEndpoint": f"https://{COLLECTION_ENDPOINT}",
                        },
                        {"id": "col-2", "name": "newbie"},
                    ]
                },
                {"ids": ["col-1", "col-2"]},
            )

    def indices(self, host: str, names: list[str]) -> None:
        self.http.route(
            host,
            "/_cat/indices?format=json&h=index,status&expand_wildcards=open",
            [{"index": n, "status": "open"} for n in names],
        )

    def docs(
        self, host: str, index: str, docs: list[dict[str, Any]], total: int | None = None
    ) -> None:
        path = f"/{urllib.parse.quote(index, safe='')}/_search?size=100"
        hits = [{"_index": index, "_id": str(i), "_source": d} for i, d in enumerate(docs)]
        self.http.route(
            host, path, {"hits": {"total": {"value": total or len(docs)}, "hits": hits}}
        )


def test_domains_are_sampled_by_index_and_field(env: Env) -> None:
    aws = Aws(env)
    aws.estate()
    aws.indices(ENDPOINT, ["orders", ".kibana_1", ".ds-events-000001", "empty"])
    aws.docs(
        ENDPOINT,
        "orders",
        [
            {"customer": {"card": CARDS["visa"]}, "note": "hi"},
            {"ssn": dashed(SSN_A), "flag": True},
        ],
        total=5000,
    )
    aws.docs(ENDPOINT, ".ds-events-000001", [{"message": f"card {CARDS['jcb']}"}])
    aws.docs(ENDPOINT, "empty", [])
    doc = env.run(config(s3_targets=[], discover=OS))
    assert doc is not None
    valid(doc)
    aws.es_stub.assert_no_pending_responses()
    # Only GETs, signed for es, and never the system index.
    assert {svc for svc, _ in aws.http.seen} == {"es"}
    assert not any(".kibana" in url for _, url in aws.http.seen)
    found = {(f["resource"]["table"], f["resource"]["field"], f["class"]) for f in doc["findings"]}
    assert found == {
        ("orders", "customer", "card"),
        ("orders", "ssn", "us_ssn"),
        (".ds-events-000001", "message", "card"),
    }
    f = next(f for f in doc["findings"] if f["resource"]["field"] == "customer")
    assert f["resource"] == {
        "type": "store_field",
        "service": "opensearch",
        "store": "logs",
        "table": "orders",
        "field": "customer",
        "readBy": "search",
    }
    assert f["link"].startswith("https://us-west-2.console.aws.amazon.com/aos/home")
    s = stores(doc)
    assert (s["logs"]["status"], s["logs"]["deployment"]) == ("scanned", "managed")
    assert (s["private"]["status"], s["private"]["reason"]) == ("skipped", "vpc_only")
    assert s["private"]["toggle"] == "VPC_SUBNET_IDS"  # #105: what would reach it
    assert s["vectors"]["toggle"] == "OPENSEARCH_SERVERLESS_READ"
    assert (s["gone"]["reason"], s["gone"]["state"]) == ("unsupported", "deleted")
    assert (s["vectors"]["reason"], s["vectors"]["deployment"]) == (
        "read_not_configured",
        "serverless",
    )
    assert (s["newbie"]["reason"], s["newbie"]["state"]) == ("unsupported", "CREATING")
    assert "endpoint" not in s["logs"]
    cov = next(c for c in doc["coverage"] if c["kind"] == "opensearch")
    assert (cov["listed"], cov["scanned"], cov["partial"], cov["passComplete"]) == (3, 3, 1, True)


def test_serverless_collections_when_turned_on(env: Env) -> None:
    aws = Aws(env)
    aws.estate()
    aws.indices(ENDPOINT, [])
    aws.indices(COLLECTION_ENDPOINT, ["embeddings"])
    aws.docs(COLLECTION_ENDPOINT, "embeddings", [{"text": f"my ssn is {dashed(SSN_B)}"}])
    doc = env.run(config(s3_targets=[], discover=OS, opensearch_serverless_read=True))
    assert doc is not None
    valid(doc)
    assert ("aoss", f"https://{COLLECTION_ENDPOINT}/embeddings/_search?size=100") in aws.http.seen
    [f] = doc["findings"]
    assert (f["resource"]["service"], f["resource"]["store"], f["class"]) == (
        "opensearch_serverless",
        "vectors",
        "us_ssn",
    )
    # A domain with no index: listed and read, nothing to find, not a gap.
    assert stores(doc)["logs"]["status"] == "scanned"


def test_a_refused_domain_is_access_denied(env: Env) -> None:
    aws = Aws(env)
    aws.estate(collections=False)
    aws.http.route(
        ENDPOINT, "/_cat/indices?format=json&h=index,status&expand_wildcards=open", {}, 403
    )
    doc = env.run(config(s3_targets=[], discover=OS))
    assert doc is not None
    valid(doc)
    s = stores(doc)["logs"]
    assert (s["status"], s["reason"], s["error"]) == ("error", "access_denied", "AccessDenied")


def test_one_index_that_fails_is_unreadable_and_the_budget_resumes(env: Env) -> None:
    aws = Aws(env)
    cfg = config(s3_targets=[], discover=OS, max_items_per_run=1)
    aws.estate(collections=False)
    aws.indices(ENDPOINT, ["a", "b", "c"])
    aws.http.route(ENDPOINT, "/a/_search?size=100", {}, 500)
    aws.docs(ENDPOINT, "b", [{"pan": CARDS["amex"]}])
    aws.docs(ENDPOINT, "c", [{"pan": CARDS["discover"]}])
    first = env.run(cfg)
    assert first is not None
    cov = next(c for c in first["coverage"] if c["kind"] == "opensearch")
    assert (cov["unreadable"], cov["scanned"], cov["backlog"]) == (1, 1, True)
    aws.estate(collections=False)
    second = env.run(cfg)
    assert second is not None
    cov = next(c for c in second["coverage"] if c["kind"] == "opensearch")
    assert (cov["scanned"], cov["passComplete"]) == (1, True)
    assert len(second["findings"]) == 2


def test_deny_by_name_and_settings(env: Env) -> None:
    aws = Aws(env)
    aws.estate(collections=False)
    doc = env.run(config(s3_targets=[], discover=OS, deny=store_rules("opensearch:logs")))
    assert doc is not None
    assert stores(doc)["logs"]["reason"] == "denied"
    assert aws.http.seen == []
    c = read_config({"RESULTS_BUCKET": "x"})
    assert (c.opensearch_docs_per_index, c.opensearch_max_indices) == (100, 500)
    assert c.opensearch_serverless_read is False
    c = read_config({"RESULTS_BUCKET": "x", "OPENSEARCH_SERVERLESS_READ": "true"})
    assert c.opensearch_serverless_read is True


def test_signed_http_sends_a_sigv4_get(monkeypatch: Any) -> None:
    """The real client signs a GET with the scanner's credentials; nothing leaves the test."""
    from botocore.httpsession import URLLib3Session

    from sensitive_data_scanner.sources.opensearch import SignedHttp

    sent: list[Any] = []

    class Response:
        status_code = 200
        content = b"[]"

    def send(self: Any, request: Any) -> Response:
        sent.append(request)
        return Response()

    monkeypatch.setattr(URLLib3Session, "send", send)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    status, body = SignedHttp("us-west-2").get("es", f"https://{ENDPOINT}/_cat/indices")
    assert (status, body) == (200, b"[]")
    [request] = sent
    assert request.method == "GET"
    auth = request.headers["Authorization"]
    auth = auth.decode() if isinstance(auth, bytes) else auth
    assert auth.startswith("AWS4-HMAC-SHA256 ") and "/us-west-2/es/aws4_request" in auth


def test_with_the_function_in_a_vpc_a_domains_vpc_endpoint_is_read(env: Env) -> None:
    """A6 (#105): with VPC_SUBNET_IDS set (the template attaches the function to the VPC), a
    domain that has only a VPC endpoint is read through it, the same signed GETs."""
    aws = Aws(env)
    aws.estate(collections=False)
    private = "vpc-private.es.amazonaws.com"
    aws.indices(ENDPOINT, [])
    aws.indices(private, ["patients"])
    aws.docs(private, "patients", [{"ssn": dashed(SSN_B)}])
    doc = env.run(
        config(
            s3_targets=[],
            discover=OS,
            vpc_subnet_ids=("subnet-0123456789abcdef0",),
            vpc_security_group_ids=("sg-0123abcd",),
        )
    )
    assert doc is not None
    valid(doc)
    s = stores(doc)
    assert s["private"]["status"] == "scanned" and "toggle" not in s["private"]
    [f] = doc["findings"]
    assert (f["resource"]["store"], f["resource"]["table"], f["class"]) == (
        "private",
        "patients",
        "us_ssn",
    )
    assert any(private in url for _, url in aws.http.seen)
    assert read_config({"RESULTS_BUCKET": "x"}).vpc_attached is False
    c = read_config(
        {
            "RESULTS_BUCKET": "x",
            "VPC_SUBNET_IDS": "subnet-0123456789abcdef0",
            "VPC_SECURITY_GROUP_IDS": "sg-0123abcd",
        }
    )
    assert c.vpc_attached
