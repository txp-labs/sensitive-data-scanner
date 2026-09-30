"""The Google Cloud scanner: settings, discovery, Cloud Storage, state, sinks.

Every Google call goes to a stubbed session (gcp_fakes.py); every value is made up.
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import io
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from gcp_fakes import (
    KEY,
    NOW,
    ORG,
    OTHER,
    OTHER_NUMBER,
    PROJECT,
    STATE_BUCKET,
    Cloud,
    Obj,
    bucket_row,
    error,
    settings,
    vpc_denied,
)
from sensitive_data_core.findings import key_hash
from sensitive_data_core.push import verify
from sensitive_data_gcp import __main__ as entry
from sensitive_data_gcp.clients import GcpError, Rest
from sensitive_data_gcp.config import ConfigError, read_settings
from sensitive_data_gcp.resources import resource_name_hash
from sensitive_data_gcp.runner import run_scan
from sensitive_data_gcp.sinks import FileSink, PubSubSink, sinks_for
from sensitive_data_gcp.sources.base import versionless_kms_key
from synthetic import CARDS, SSN_A, dashed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
BUCKET_TYPE = "storage.googleapis.com/Bucket"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def csv_body() -> bytes:
    return f"name,card_number,ssn\nA,{CARDS['visa']},{dashed(SSN_A)}\n".encode()


def parquet_body() -> bytes:
    import pyarrow as pa
    import pyarrow.parquet as pq

    buf = io.BytesIO()
    pq.write_table(pa.table({"card_number": [CARDS["mastercard"]], "note": ["x"]}), buf)
    return buf.getvalue()


def cloud() -> Cloud:
    c = Cloud()
    c.assets[BUCKET_TYPE] = [
        bucket_row("acme-lake", labels={"env": "prod"}),
        bucket_row("acme-cmek", project=OTHER, number=OTHER_NUMBER, kms=KEY),
        bucket_row("acme-perimeter"),
        bucket_row("acme-payer"),
        bucket_row(STATE_BUCKET),
    ]
    c.bucket("acme-lake").objects.update(
        {
            "exports/cards.csv": Obj(csv_body()),
            "exports/pay.csv": Obj(csv_body(), kms=KEY),
            "exports/cards.csv.gz": Obj(gzip.compress(csv_body())),
            "lake/part-0.parquet": Obj(parquet_body()),
            "media/call.wav": Obj(b"RIFF\x24\x00\x00\x00WAVEfmt made up"),
            "cold/old.csv": Obj(csv_body(), storage_class="ARCHIVE"),
            "csek/secret.csv": Obj(csv_body(), csek=True),
            "dir/": Obj(b""),
        }
    )
    c.bucket("acme-cmek").objects["c.json"] = Obj(
        json.dumps({"cardNumber": CARDS["amex"], "cvv": "cvv 123"}).encode(), kms=KEY
    )
    c.bucket("acme-perimeter").list_fail = vpc_denied()
    c.bucket("acme-payer").list_fail = error(
        400,
        "INVALID_ARGUMENT",
        reason="required",
        message="Bucket is a requester pays bucket but no user project provided.",
    )
    return c


def run(c: Cloud, **env: str) -> dict[str, Any]:
    doc, failed = run_scan(
        settings(**env), c.clients(), detector=shared_detector(), now=lambda: NOW
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in doc["discovery"]["stores"]}


# ------------------------------------------------------------------ settings


def test_settings_need_one_scope_a_site_and_a_destination() -> None:
    dest = {"FINDINGS_FILE": "/f"}
    for env, code in [
        ({}, "scanner_site"),
        ({"SCANNER_SITE": "x", **dest}, "no_scope"),
        ({"SCANNER_SITE": "x", "GCP_ORGANIZATION": ORG}, "no_findings_destination"),
        ({"SCANNER_SITE": "x", "GCP_ORGANIZATION": "acme", **dest}, "gcp_organization"),
        ({"SCANNER_SITE": "x", "GCP_FOLDERS": "12,x", **dest}, "gcp_folders"),
        ({"SCANNER_SITE": "x", "GCP_PROJECTS": "A!", **dest}, "gcp_projects"),
        (
            {"SCANNER_SITE": "x", "GCP_ORGANIZATION": ORG, "GCP_FOLDERS": "12", **dest},
            "scope_twice",
        ),
        ({"SCANNER_SITE": "x", "GCP_ORGANIZATION": ORG, "STATE_BUCKET": "s3://x"}, "state_bucket"),
        (
            {"SCANNER_SITE": "x", "GCP_ORGANIZATION": ORG, "FINDINGS_PUBSUB_TOPIC": "topic"},
            "findings_pubsub_topic",
        ),
        (
            {
                "SCANNER_SITE": "x",
                "GCP_ORGANIZATION": ORG,
                "FINDINGS_HTTPS_URL": "https://collector.example/x",
                "FINDINGS_HMAC_KEY": "short",
            },
            "findings_hmac_key",
        ),
        ({"SCANNER_SITE": "x", "GCP_ORGANIZATION": ORG, "DISCOVER": "s3", **dest}, "discover_kind"),
    ]:
        with pytest.raises(ConfigError) as err:
            read_settings(env)
        assert err.value.code == code


def test_settings_scopes_and_secrets() -> None:
    s = read_settings(
        {
            "SCANNER_SITE": "acme-folders",
            "GCP_FOLDERS": "111,222",
            "FINDINGS_HTTPS_URL": "https://collector.example/x?token=made-up-token",
            "FINDINGS_HMAC_KEY": "k" * 40,
            "DISCOVER": "storage,buckets",
        }
    )
    assert s.scopes == ("folders/111", "folders/222") and s.discover == ("gcs",)
    assert "made-up-token" not in repr(s) and "k" * 40 not in repr(s)
    p = read_settings(
        {"SCANNER_SITE": "x", "GCP_PROJECTS": f"{PROJECT},{OTHER}", **{"FINDINGS_FILE": "/f"}}
    )
    assert p.scopes == (f"projects/{PROJECT}", f"projects/{OTHER}")


# ------------------------------------------------------------------ discovery


def test_discovery_lists_every_bucket_under_the_organization() -> None:
    c = cloud()
    doc = run(c)
    searches = [(u, q) for m, u, q in c.requests if "searchAllResources" in u]
    assert all(f"/organizations/{ORG}:searchAllResources" in u for u, _ in searches)
    assert len([1 for _, q in searches if q["assetTypes"] == BUCKET_TYPE]) == 3  # 5, two a page
    s = stores(doc)
    lake = s["acme-lake"]
    assert lake["status"] == "scanned" and lake["project"] == PROJECT
    assert lake["resourceNameHash"] == resource_name_hash("//storage.googleapis.com/acme-lake")
    assert lake["atRestEncryption"] == "service_managed"
    cmek = s["acme-cmek"]
    assert cmek["project"] == OTHER  # the number, resolved to the project's id
    assert (cmek["atRestEncryption"], cmek["atRestKeyHash"]) == (
        "customer_managed_key",
        key_hash(KEY),
    )
    assert s[STATE_BUCKET]["reason"] == "self"
    assert (s["acme-perimeter"]["status"], s["acme-perimeter"]["reason"]) == ("skipped", "network")
    assert (s["acme-payer"]["status"], s["acme-payer"]["reason"]) == ("skipped", "requester_pays")
    assert doc["platform"] == "gcp" and doc["site"] == "acme-org"
    assert "account" not in doc and "region" not in doc


def test_a_search_failure_is_a_listing_error() -> None:
    c = cloud()
    c.asset_fail[BUCKET_TYPE] = error(403, "PERMISSION_DENIED", message=f"denied on {ORG}")
    doc = run(c)
    assert doc["discovery"]["listErrors"]["gcs"] == "PERMISSION_DENIED"


def test_allow_deny_and_sampling_rules_decide_buckets() -> None:
    c = cloud()
    doc = run(
        c,
        DISCOVER_DENY="gcs:acme-perimeter,tag:scan=false",
        DISCOVER_ALLOW="bucket:acme-*",
        DISCOVER_SAMPLING=json.dumps([{"match": "tag:env=prod", "samplePercent": 50}]),
    )
    s = stores(doc)
    assert s["acme-perimeter"]["reason"] == "denied"
    assert s["acme-lake"]["samplePercent"] == 50
    assert any(c["target"] == "acme-lake/" and c["samplePercent"] == 50 for c in doc["coverage"])


def test_projects_scope_searches_each_project() -> None:
    c = cloud()
    doc, _ = run_scan(
        read_settings(
            {
                "SCANNER_SITE": "two",
                "GCP_PROJECTS": f"{PROJECT},{OTHER}",
                "FINDINGS_FILE": "/dev/null",
            }
        ),
        c.clients(),
        detector=shared_detector(),
        now=lambda: NOW,
    )
    assert doc is not None
    urls = {u for _, u, _ in c.requests if "searchAllResources" in u}
    assert any(f"projects/{PROJECT}:" in u for u in urls)
    assert any(f"projects/{OTHER}:" in u for u in urls)


# ------------------------------------------------------------------ reading


def test_objects_are_read_by_format_with_their_own_key() -> None:
    c = cloud()
    doc = run(c)
    lake = next(x for x in doc["coverage"] if x["target"] == "acme-lake/")
    assert lake["scanned"] == 5  # the CSVs, the gzip, the Parquet file, the Archive-class CSV
    assert lake["skipped"] == {"audio": 1}
    assert (lake["unreadable"], lake["kmsDenied"]) == (1, 1)  # the customer-supplied key
    assert lake["formats"] == {"csv": 4, "parquet": 1}
    by_object: dict[str, list[dict[str, Any]]] = {}
    for f in doc["findings"]:
        by_object.setdefault(f["resource"]["object"], []).append(f)
    plain = {f["class"]: f for f in by_object["exports/cards.csv"]}
    assert {"card", "us_ssn"} <= set(plain)
    card = plain["card"]
    r = card["resource"]
    assert (r["type"], r["bucket"], r["generation"], r["project"]) == (
        "gcs_object",
        "acme-lake",
        "1700000000000001",
        PROJECT,
    )
    assert r["resourceNameHash"] == resource_name_hash("//storage.googleapis.com/acme-lake")
    assert card["atRestEncryption"] == "service_managed"
    assert card["pciNote"]["requirement"] == "3.5.1.2"
    assert card["link"] == (
        f"https://console.cloud.google.com/storage/browser/acme-lake?project={PROJECT}"
    )
    keyed = next(f for f in by_object["exports/pay.csv"] if f["class"] == "card")
    assert keyed["atRestEncryption"] == "customer_managed_key"
    assert keyed["atRestKeyHash"] == key_hash(KEY)  # the version is not part of it
    column = by_object["lake/part-0.parquet"][0]
    assert (column["resource"]["column"], column["format"]) == ("card_number", "parquet")
    # Reads are ranged media GETs; nothing is written but the job's own bucket.
    assert {b for b, _ in c.writes} == {STATE_BUCKET}
    media = [q for m, u, q in c.requests if q.get("alt") == "media" and "acme-lake" in u]
    assert media and all(q.get("generation") for q in media)


def test_the_next_run_reads_only_what_changed_and_keeps_findings() -> None:
    c = cloud()
    first = run(c)
    reads = sum(1 for _, u, q in c.requests if q.get("alt") == "media" and "acme-lake" in u)
    state = c.state("state/scanner-state.json")
    assert state["version"] == 1 and state["cursors"]
    second = run(c)
    again = sum(1 for _, u, q in c.requests if q.get("alt") == "media" and "acme-lake" in u)
    assert again == reads
    assert {f["id"] for f in second["findings"]} == {f["id"] for f in first["findings"]}
    assert c.state("findings/latest.json")["runId"] == second["runId"]
    assert f"findings/runs/{first['runId']}.json" in c.buckets[STATE_BUCKET].objects
    del c.bucket("acme-lake").objects["exports/cards.csv"]
    third = run(c)
    assert not any(f["resource"]["object"] == "exports/cards.csv" for f in third["findings"])


def test_the_budget_defers_and_the_next_run_resumes() -> None:
    c = cloud()
    c.bucket("acme-lake").per_page = 2
    doc = run(c, MAX_OBJECTS_PER_RUN="2")
    s = stores(doc)
    assert any(v["status"] == "deferred" or v.get("backlog") for v in s.values())
    before = sum(1 for _, u, q in c.requests if q.get("alt") == "media")
    run(c, MAX_OBJECTS_PER_RUN="50")
    assert sum(1 for _, u, q in c.requests if q.get("alt") == "media") > before


def test_a_missing_permission_is_access_denied() -> None:
    c = cloud()
    c.bucket("acme-cmek").list_fail = error(403, reason="forbidden", message="sds lacks list")
    s = stores(run(c))
    assert (s["acme-cmek"]["status"], s["acme-cmek"]["reason"], s["acme-cmek"]["error"]) == (
        "error",
        "access_denied",
        "PERMISSION_DENIED",
    )


def test_another_run_holding_the_lock_stops_this_one() -> None:
    c = cloud()
    c.bucket(STATE_BUCKET).objects["state/lock.json"] = Obj(b"{}", updated=NOW)
    doc, failed = run_scan(settings(), c.clients(), detector=shared_detector(), now=lambda: NOW)
    assert doc is None and failed == 0


def test_a_stale_lock_is_taken_over() -> None:
    c = cloud()
    c.bucket(STATE_BUCKET).objects["state/lock.json"] = Obj(
        b"{}", updated=NOW - dt.timedelta(hours=2)
    )
    doc, _ = run_scan(settings(), c.clients(), detector=shared_detector(), now=lambda: NOW)
    assert doc is not None
    assert "state/lock.json" not in c.buckets[STATE_BUCKET].objects  # released at the end


def test_versionless_kms_key_is_what_a_customer_hashes() -> None:
    assert versionless_kms_key(KEY + "/cryptoKeyVersions/7") == KEY
    assert versionless_kms_key("//cloudkms.googleapis.com/" + KEY) == KEY
    assert versionless_kms_key("") is None


def test_errors_are_named_by_code_never_by_message() -> None:
    class Session:
        def __init__(self, resp: Any) -> None:
            self.resp = resp
            self.calls = 0

        def request(self, *a: Any, **k: Any) -> Any:
            self.calls += 1
            return self.resp

    for resp, code in [
        (error(403, "PERMISSION_DENIED", message=f"no on {CARDS['visa']}"), "PERMISSION_DENIED"),
        (vpc_denied(), "VPC_SERVICE_CONTROLS"),
        (error(404, reason="notFound", message="gone"), "NOT_FOUND"),
        (error(503, message="busy"), "UNAVAILABLE"),
    ]:
        session = Session(resp)
        with pytest.raises(GcpError) as err:
            Rest(session, sleep=lambda s: None).get("https://example.googleapis.com/x")
        assert err.value.error_code == code
        assert CARDS["visa"] not in repr(err.value) and CARDS["visa"] not in str(err.value)
        assert session.calls == (3 if resp.status_code == 503 else 1)


# ------------------------------------------------------------------ sinks and entry point


def test_sinks_https_signed_pubsub_and_a_file(tmp_path: Path) -> None:
    key = "k" * 40
    s = read_settings(
        {
            "SCANNER_SITE": "acme-org",
            "GCP_ORGANIZATION": ORG,
            "FINDINGS_HTTPS_URL": "https://collector.example/findings",
            "FINDINGS_HMAC_KEY": key,
            "FINDINGS_PUBSUB_TOPIC": "projects/acme-sec/topics/sds-findings",
            "FINDINGS_FILE": str(tmp_path / "f.json"),
        }
    )
    c = cloud()
    got = sinks_for(s, c.clients())
    assert [type(x).__name__ for x in got] == ["HttpsSink", "PubSubSink", "FileSink"]

    posted: list[Any] = []

    class Response(io.BytesIO):
        status = 202

    def opener(req: Any, timeout: float) -> Response:
        posted.append(req)
        return Response(b"")

    https = got[0]
    https._open = opener  # type: ignore[attr-defined]
    doc, failed = run_scan(s, c.clients(), sinks=got, detector=shared_detector(), now=lambda: NOW)
    assert doc is not None and failed == 0
    req = posted[0]
    assert req.get_header("User-agent").startswith("sensitive-data-scanner-gcp/")
    assert verify(
        key.encode(), req.get_header("X-sds-signature"), req.data, now=dt.datetime.now().timestamp()
    )
    msg = c.published[0]
    assert msg["attributes"]["type"] == "Findings v1"
    assert msg["attributes"]["source"] == "sensitive-data-scanner"
    assert json.loads(base64.b64decode(msg["data"]))["runId"] == doc["runId"]
    publish = [u for m, u, _ in c.requests if u.endswith(":publish")]
    assert publish == [
        "https://pubsub.googleapis.com/v1/projects/acme-sec/topics/sds-findings:publish"
    ]
    assert json.loads((tmp_path / "f.json").read_text())["runId"] == doc["runId"]


def test_a_pubsub_failure_fails_the_sink(capsys: pytest.CaptureFixture[str]) -> None:
    c = Cloud()
    c.route(
        "POST", r":publish$", lambda *a: error(403, "PERMISSION_DENIED", message="topic says no")
    )
    sink = PubSubSink("projects/p/topics/t", c.clients().rest)
    assert sink.push({"runId": "r", "findings": [], "coverage": []}) == 0
    assert '"error":"PERMISSION_DENIED"' in capsys.readouterr().out
    assert FileSink.__name__ == "FileSink"


def test_the_entry_point_reports_a_bad_setting_by_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SCANNER_SITE", "acme-org")
    monkeypatch.setenv("GCP_ORGANIZATION", ORG)
    monkeypatch.setenv("FINDINGS_HTTPS_URL", "http://collector.example/made-up-token")
    assert entry.main(["scan"]) == 1
    out = capsys.readouterr().out
    assert '"error":"findings_url_not_https"' in out and "made-up-token" not in out
    assert entry.main(["nope"]) == 1


def test_check_lists_and_reads_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in {
        "SCANNER_SITE": "acme-org",
        "GCP_ORGANIZATION": ORG,
        "STATE_BUCKET": f"gs://{STATE_BUCKET}",
    }.items():
        monkeypatch.setenv(k, v)
    c = cloud()
    assert entry.main(["check"], clients=c.clients()) == 0
    assert not any(q.get("alt") == "media" for _, _, q in c.requests) and not c.writes
    c.asset_fail[BUCKET_TYPE] = error(403, "PERMISSION_DENIED")
    assert entry.main(["check"], clients=c.clients()) == 2
    monkeypatch.setenv("FINDINGS_FILE", "/nonexistent/dir/f.json")
    assert entry.main(["scan"], clients=cloud().clients()) == 1


def test_a_pass_resumes_mid_page_and_reads_each_object_once() -> None:
    import time

    from sensitive_data_core.adapter import Budget, FindingStore
    from sensitive_data_gcp.resources import Located
    from sensitive_data_gcp.sources.gcs import BucketTarget, GcsSource

    c = Cloud()
    box = c.bucket("acme-many")
    for i in range(7):
        box.objects[f"d/{i}.txt"] = Obj(f"row {i}".encode())
    target = BucketTarget(Located(PROJECT, "//storage.googleapis.com/acme-many"), "acme-many")
    source = GcsSource(c.clients().rest, target, page_size=2, columnar=False)
    cursor: dict[str, Any] = {}
    runs = 0
    while True:
        runs += 1
        budget = Budget(3, 10**9, time.monotonic() + 60)
        result = source.run(cursor, budget, shared_detector(), FindingStore("x"), NOW)
        cursor = result.cursor
        if result.coverage.pass_complete:
            break
        assert runs < 10
    reads = [u for _, u, q in c.requests if q.get("alt") == "media"]
    assert len(reads) == 7 and len(set(reads)) == 7


def test_a_large_bucket_is_named_for_a_storage_insights_report() -> None:
    """Storage Insights inventory reports are not read (#67, on demand): a bucket whose
    complete pass listed at least GCS_INVENTORY_MIN_OBJECTS is named in the run summary,
    and listed as before."""
    c = cloud()
    s = stores(run(c, GCS_INVENTORY_MIN_OBJECTS="5"))
    assert s["acme-lake"]["recommendation"] == "storage_insights"
    assert "recommendation" not in s["acme-cmek"]
    assert "recommendation" not in stores(run(c))["acme-lake"]
