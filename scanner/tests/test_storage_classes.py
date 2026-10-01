"""Storage classes and tiers: what is read, what is a gap, and the cost to scan (#109).

Every S3 storage class, Azure access tier and Cloud Storage class has a rule
(`sensitive_data_core.storage_classes`), decided from the listing alone: an object
left out is never fetched. Glacier Instant Retrieval and Azure Cold need their
setting; Glacier Flexible Retrieval, Deep Archive, the Intelligent-Tiering archive
tiers and Azure Archive are the gaps `needs_restore` / `needs_rehydration`, never
`unreadable`. Each object store's run-summary entry carries `storageClasses` and
`costEstimate` (findings schema 1.13), priced from the dated table in
`storage_prices.json`. S3 runs against moto; Azure and Google Cloud against the
fakes the other tests use. All values are made up.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
from typing import Any

import pytest
from botocore.exceptions import ClientError
from jsonschema import Draft202012Validator

from aws_fixtures import DATA, NOW, Env, config
from azure_fakes import Blob
from conftest import REPO
from gcp_fakes import Obj
from sensitive_data_core.adapter import Budget, FindingStore
from sensitive_data_core.coverage import Store, settle
from sensitive_data_core.storage_classes import (
    ARCHIVE_CLASS,
    COLD_TIER,
    GIB,
    NEEDS_REHYDRATION,
    NEEDS_RESTORE,
    NOT_IMPLEMENTED,
    ClassInventory,
    Rule,
    azure_rule,
    azure_tier,
    estimate,
    gcs_class,
    gcs_rule,
    price_table,
    prices_for,
    s3_class,
    s3_rule,
)
from sensitive_data_scanner.config import read_config
from sensitive_data_scanner.sources.s3 import S3Source
from synthetic import CARDS, printed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


# ------------------------------------------------------------------ the rules, every class

# (class as the listing gives it, extra listing fields, read with the defaults, reason, toggle)
S3_CASES: list[tuple[str, dict[str, Any], bool, str | None, str | None]] = [
    ("STANDARD", {}, True, None, None),
    ("REDUCED_REDUNDANCY", {}, True, None, None),
    ("STANDARD_IA", {}, True, None, None),
    ("ONEZONE_IA", {}, True, None, None),
    ("INTELLIGENT_TIERING", {}, True, None, None),
    ("EXPRESS_ONEZONE", {}, True, None, None),
    ("OUTPOSTS", {}, True, None, None),
    ("SNOW", {}, True, None, None),
    ("GLACIER_IR", {}, False, ARCHIVE_CLASS, "S3_READ_GLACIER_IR"),
    ("GLACIER", {}, False, NEEDS_RESTORE, "S3_RESTORE_ARCHIVED"),
    ("DEEP_ARCHIVE", {}, False, NEEDS_RESTORE, "S3_RESTORE_ARCHIVED"),
]


@pytest.mark.parametrize(("cls", "extra", "read", "reason", "toggle"), S3_CASES)
def test_every_s3_class_has_its_rule(
    cls: str, extra: dict[str, Any], read: bool, reason: str | None, toggle: str | None
) -> None:
    got = s3_rule(
        s3_class({"StorageClass": cls, **extra}), read_glacier_ir=False, restore_archived=False
    )
    assert (got.read, got.reason, got.toggle) == (read, reason, toggle)


def test_a_listing_with_no_class_is_standard() -> None:
    assert s3_class({}) == "STANDARD"


def test_glacier_ir_is_read_with_its_setting_on() -> None:
    assert s3_rule("GLACIER_IR", read_glacier_ir=True, restore_archived=False).read


@pytest.mark.parametrize("cls", ["GLACIER", "DEEP_ARCHIVE"])
def test_a_restored_copy_is_read_and_a_restore_in_progress_is_not(cls: str) -> None:
    restored = {
        "StorageClass": cls,
        "RestoreStatus": {"IsRestoreInProgress": False, "RestoreExpiryDate": NOW},
    }
    assert s3_class(restored) == f"{cls}_RESTORED"
    assert s3_rule(s3_class(restored), read_glacier_ir=False, restore_archived=False).read
    pending = {"StorageClass": cls, "RestoreStatus": {"IsRestoreInProgress": True}}
    assert s3_class(pending) == cls
    assert s3_rule(cls, read_glacier_ir=False, restore_archived=False).reason == NEEDS_RESTORE


@pytest.mark.parametrize(
    ("tier", "cls"),
    [
        ("ARCHIVE", "INTELLIGENT_TIERING_ARCHIVE_ACCESS"),
        ("DEEP_ARCHIVE", "INTELLIGENT_TIERING_DEEP_ARCHIVE_ACCESS"),
        ("FREQUENT", "INTELLIGENT_TIERING"),
        ("INFREQUENT", "INTELLIGENT_TIERING"),
        ("ARCHIVE_INSTANT_ACCESS", "INTELLIGENT_TIERING"),
    ],
)
def test_intelligent_tiering_tiers_from_an_inventory_report(tier: str, cls: str) -> None:
    got = s3_class({"StorageClass": "INTELLIGENT_TIERING", "IntelligentTieringAccessTier": tier})
    assert got == cls
    rule = s3_rule(got, read_glacier_ir=False, restore_archived=False)
    assert rule.read == (cls == "INTELLIGENT_TIERING")


def test_the_restore_hook_on_says_not_implemented_and_still_reads_nothing() -> None:
    rule = s3_rule("DEEP_ARCHIVE", read_glacier_ir=False, restore_archived=True)
    assert not rule.read and rule.reason == NEEDS_RESTORE and rule.entry_reason() == NOT_IMPLEMENTED


AZURE_CASES = [
    ("Hot", None, "Hot", True, None, None),
    ("Cool", None, "Cool", True, None, None),
    ("Cold", None, "Cold", False, COLD_TIER, "AZURE_READ_COLD_TIER"),
    ("Archive", None, "Archive", False, NEEDS_REHYDRATION, "AZURE_REHYDRATE_ARCHIVE"),
    ("Archive", "rehydrate-pending-to-hot", "Archive", False, NEEDS_REHYDRATION, None),
    ("Hot", "rehydrate-pending-to-hot", "Archive", False, NEEDS_REHYDRATION, None),
    (None, None, "Premium", True, None, None),
    ("cool", None, "Cool", True, None, None),
]


@pytest.mark.parametrize(("tier", "status", "name", "read", "reason", "toggle"), AZURE_CASES)
def test_every_azure_tier_has_its_rule(  # noqa: PLR0917 - one parametrized case
    tier: str | None,
    status: str | None,
    name: str,
    read: bool,
    reason: str | None,
    toggle: str | None,
) -> None:
    got = azure_tier(tier, status)
    assert got == name
    rule = azure_rule(got, read_cold=False, rehydrate_archive=False)
    assert (rule.read, rule.reason) == (read, reason)
    if toggle:
        assert rule.toggle == toggle


def test_azure_cold_is_read_with_its_setting_and_the_rehydrate_hook_reads_nothing() -> None:
    assert azure_rule("Cold", read_cold=True, rehydrate_archive=False).read
    hook = azure_rule("Archive", read_cold=False, rehydrate_archive=True)
    assert not hook.read and hook.entry_reason() == NOT_IMPLEMENTED


@pytest.mark.parametrize(
    ("cls", "read"),
    [
        ("STANDARD", True),
        ("NEARLINE", True),
        ("COLDLINE", True),
        ("ARCHIVE", False),
        ("MULTI_REGIONAL", True),
        ("REGIONAL", True),
        ("DURABLE_REDUCED_AVAILABILITY", True),
    ],
)
def test_every_cloud_storage_class_has_its_rule(cls: str, read: bool) -> None:
    rule = gcs_rule(gcs_class({"storageClass": cls.lower()}), read_archive=False)
    assert rule.read == read
    if not read:
        assert (rule.reason, rule.toggle) == (ARCHIVE_CLASS, "GCS_READ_ARCHIVE")
    assert gcs_rule(cls, read_archive=True).read


# ------------------------------------------------------------------ the price table


def test_the_price_table_is_dated_and_cites_its_sources() -> None:
    table = price_table()
    assert table["currency"] == "USD"
    for name in ("aws", "azure", "gcp"):
        p = table["platforms"][name]
        dt.date.fromisoformat(p["priceDate"])
        assert p["sources"] and all(s.startswith("https://") for s in p["sources"])
        assert p["fallbackRegion"] in p["regions"]
    aws = table["platforms"]["aws"]
    assert "https://aws.amazon.com/s3/pricing/" in aws["sources"]
    assert (
        "https://azure.microsoft.com/pricing/details/storage/blobs/"
        in (table["platforms"]["azure"]["sources"])
    )
    assert "https://cloud.google.com/storage/pricing" in table["platforms"]["gcp"]["sources"]
    for region, row in aws["regions"].items():
        for cls in ("STANDARD_IA", "ONEZONE_IA", "GLACIER_IR"):
            assert row[cls]["retrievalPerGb"] > 0 and row[cls]["getPer1k"] > 0, (region, cls)
    for region, row in table["platforms"]["azure"]["regions"].items():
        for tier in ("Cool", "Cold"):
            assert row[tier]["retrievalPerGb"] > 0, (region, tier)
    gcp = table["platforms"]["gcp"]["regions"]["*"]
    assert [gcp[c]["retrievalPerGb"] for c in ("NEARLINE", "COLDLINE", "ARCHIVE")] == [
        0.01,
        0.02,
        0.05,
    ]


def test_the_price_table_check_passes() -> None:
    got = subprocess.run(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, str(REPO / "scripts" / "storage_prices.py"), "--check"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert got.returncode == 0, got.stderr


def test_a_region_the_table_lacks_is_priced_as_the_fallback_and_says_so() -> None:
    got = prices_for("aws", "us-east-1")
    assert got is not None and not got.fallback
    far = prices_for("aws", "xx-nowhere-1")
    assert far is not None and far.fallback and far.region == "us-east-1"
    assert prices_for("azure", "nowhere") is not None
    gcs = prices_for("gcp", "us-central1")
    assert gcs is not None and not gcs.fallback and gcs.region == "us-central1"
    assert prices_for("nowhere", "x") is None


# ------------------------------------------------------------------ the estimate


def _inv(platform: str, region: str, rules: dict[str, Rule], **classes: int) -> ClassInventory:
    inv = ClassInventory(platform, region)
    for cls, gib in classes.items():
        for _ in range(1000):
            inv.add(cls, gib * GIB // 1000, gib * GIB // 1000, rules.get(cls, Rule(True)))
    return inv


def test_the_estimate_covers_ia_and_glacier_ir_and_not_what_needs_a_restore() -> None:
    off = s3_rule("GLACIER_IR", read_glacier_ir=False, restore_archived=False)
    archived = s3_rule("DEEP_ARCHIVE", read_glacier_ir=False, restore_archived=False)
    inv = _inv(
        "aws",
        "us-east-1",
        {"GLACIER_IR": off, "DEEP_ARCHIVE": archived},
        STANDARD=50,
        STANDARD_IA=100,
        ONEZONE_IA=10,
        GLACIER_IR=20,
        DEEP_ARCHIVE=500,
    )
    got = estimate(inv)
    assert got is not None
    row = price_table()["platforms"]["aws"]["regions"]["us-east-1"]
    ia = 100 * row["STANDARD_IA"]["retrievalPerGb"] + 1 * row["STANDARD_IA"]["getPer1k"]
    zia = 10 * row["ONEZONE_IA"]["retrievalPerGb"] + 1 * row["ONEZONE_IA"]["getPer1k"]
    gir = 20 * row["GLACIER_IR"]["retrievalPerGb"] + 1 * row["GLACIER_IR"]["getPer1k"]
    assert got["byClass"] == {
        "GLACIER_IR": round(gir, 4),
        "ONEZONE_IA": round(zia, 4),
        "STANDARD_IA": round(ia, 4),
    }
    # Read now: the IA classes. Glacier IR is off: in byClass (what turning it on costs) only.
    assert got["estimatedToScanUsd"] == round(ia + zia, 4)
    assert got["currency"] == "USD" and got["region"] == "us-east-1"
    assert got["priceDate"] == price_table()["platforms"]["aws"]["priceDate"]
    assert "DEEP_ARCHIVE" not in got["retrievalPerGb"] and "STANDARD" not in got["byClass"]
    assert "regionFallback" not in got


def test_the_estimate_uses_the_bytes_a_read_fetches() -> None:
    inv = ClassInventory("aws", "us-east-1")
    # One 10 GiB object read up to a 20 MiB cap: priced as 20 MiB, not 10 GiB.
    inv.add("STANDARD_IA", 10 * GIB, 20 * 1024**2, Rule(True))
    got = estimate(inv)
    assert got is not None
    row = price_table()["platforms"]["aws"]["regions"]["us-east-1"]["STANDARD_IA"]
    want = 20 * 1024**2 / GIB * row["retrievalPerGb"] + row["getPer1k"] / 1000
    assert got["estimatedToScanUsd"] == round(want, 4)


def test_no_estimate_without_a_class_that_charges_per_byte() -> None:
    archived = s3_rule("GLACIER", read_glacier_ir=False, restore_archived=False)
    assert estimate(_inv("aws", "us-east-1", {"GLACIER": archived}, STANDARD=5, GLACIER=5)) is None


def test_azure_and_cloud_storage_estimates() -> None:
    cold = azure_rule("Cold", read_cold=False, rehydrate_archive=False)
    archive = azure_rule("Archive", read_cold=False, rehydrate_archive=False)
    az = estimate(
        _inv(
            "azure",
            "westeurope",
            {"Cold": cold, "Archive": archive},
            Hot=1,
            Cool=10,
            Cold=10,
            Archive=99,
        )
    )
    assert az is not None
    assert set(az["byClass"]) == {"Cool", "Cold"}
    assert az["estimatedToScanUsd"] == az["byClass"]["Cool"]
    archive = gcs_rule("ARCHIVE", read_archive=False)
    gcs = estimate(_inv("gcp", "us", {"ARCHIVE": archive}, NEARLINE=10, COLDLINE=10, ARCHIVE=10))
    assert gcs is not None
    assert gcs["byClass"] == {"ARCHIVE": 0.55, "COLDLINE": 0.21, "NEARLINE": 0.101}
    assert gcs["estimatedToScanUsd"] == round(0.21 + 0.101, 4)
    far = estimate(_inv("aws", "xx-nowhere-1", {}, STANDARD_IA=1))
    assert far is not None and far["regionFallback"] is True and far["region"] == "us-east-1"


def test_settle_puts_the_inventory_and_the_estimate_on_the_store() -> None:
    from sensitive_data_core.findings import Coverage

    off = s3_rule("GLACIER_IR", read_glacier_ir=False, restore_archived=False)
    a = Coverage("s3", "b/x/")
    a.storage_classes = _inv("aws", "us-west-2", {"GLACIER_IR": off}, STANDARD_IA=1, GLACIER_IR=1)
    a.storage_classes.complete = True
    a.not_allowed["archive_class"] = 1000
    b = Coverage("s3", "b/y/")
    archived = s3_rule("GLACIER", read_glacier_ir=False, restore_archived=False)
    b.storage_classes = _inv("aws", "us-west-2", {"GLACIER": archived}, GLACIER=2)
    b.archived[NEEDS_RESTORE] = 1000
    st = Store("s3", "b")
    settle(st, [a, b])
    j = st.as_json()
    assert j["storageClasses"]["GLACIER"] == {
        "objects": 1000,
        "bytes": 1000 * (2 * GIB // 1000),
        "read": False,
        "reason": NEEDS_RESTORE,
        "toggle": "S3_RESTORE_ARCHIVED",
    }
    assert j["storageClasses"]["STANDARD_IA"]["read"] is True
    assert j["storageClassesPartial"] is True  # one source has not finished a pass
    assert j["gaps"] == {"needsRestore": 1000, "notAllowed": 1000}
    assert j["toggle"] == "S3_READ_GLACIER_IR"  # read at once with its setting on
    assert set(j["costEstimate"]["byClass"]) == {"GLACIER_IR", "STANDARD_IA"}


def test_the_inventory_survives_the_cursor() -> None:
    inv = ClassInventory("aws", "us-east-1")
    inv.add("GLACIER", 5, 5, Rule(False, NEEDS_RESTORE))
    back = ClassInventory.resume("aws", "us-east-1", json.loads(json.dumps(inv.cursor())))
    assert back.cursor() == inv.cursor()
    assert ClassInventory.resume("aws", None, {"X": "junk", "Y": [1, 2]}).counts == {}


# ------------------------------------------------------------------ S3, end to end (moto)


class Counting:
    """The S3 client, recording each GetObject's key, and refusing some as AWS would."""

    def __init__(self, s3: Any, *, refused: dict[str, str] | None = None) -> None:
        self._s3 = s3
        self.gets: list[str] = []
        self.listed_with: list[dict[str, Any]] = []
        self.refused = refused or {}  # key -> the ArchiveStatus HeadObject gives
        self.restore_status: dict[str, dict[str, Any]] = {}
        self.deny_optional = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._s3, name)

    def list_objects_v2(self, **kw: Any) -> Any:
        self.listed_with.append(kw)
        if self.deny_optional and "OptionalObjectAttributes" in kw:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "ListObjectsV2")
        page = self._s3.list_objects_v2(**kw)
        for obj in page.get("Contents", []):
            if obj["Key"] in self.restore_status and "OptionalObjectAttributes" in kw:
                obj["RestoreStatus"] = self.restore_status[obj["Key"]]
        return page

    def get_object(self, **kw: Any) -> Any:
        self.gets.append(kw["Key"])
        if kw["Key"] in self.refused:
            raise ClientError({"Error": {"Code": "InvalidObjectState"}}, "GetObject")
        return self._s3.get_object(**kw)

    def head_object(self, **kw: Any) -> Any:
        head = dict(self._s3.head_object(**kw))
        if kw["Key"] in self.refused:
            head["ArchiveStatus"] = self.refused[kw["Key"]]
        return head


BODY = f"card {printed(CARDS['visa'])}"
CLASSES = {
    "std.txt": "STANDARD",
    "ia.txt": "STANDARD_IA",
    "zia.txt": "ONEZONE_IA",
    "it.txt": "INTELLIGENT_TIERING",
    "gir.txt": "GLACIER_IR",
    "gfr.txt": "GLACIER",
    "gda.txt": "DEEP_ARCHIVE",
}


def _put_classes(env: Env) -> None:
    for key, cls in CLASSES.items():
        env.clients.s3.put_object(
            Bucket=DATA,
            Key=key,
            Body=BODY.encode(),
            StorageClass=cls,  # type: ignore[arg-type]
        )


def _source(client: Any, **kw: Any) -> S3Source:
    src = S3Source(client, bucket=DATA, prefix="", region="us-west-2")
    for k, v in kw.items():
        setattr(src, k, v)
    return src


def _run(src: S3Source, cursor: dict[str, Any] | None = None, items: int = 10_000) -> Any:
    import time

    budget = Budget(items, 10**9, time.monotonic() + 60)
    from aws_fixtures import shared_detector

    return src.run(cursor or {}, budget, shared_detector(), FindingStore(NOW.isoformat()), NOW)


def test_s3_classes_are_decided_from_the_listing_and_never_fetched(env: Env) -> None:
    _put_classes(env)
    client = Counting(env.clients.s3)
    result = _run(_source(client))
    cov = result.coverage
    # Read: Standard, both IA classes, Intelligent-Tiering. Never fetched: the rest.
    assert sorted(set(client.gets)) == ["ia.txt", "it.txt", "std.txt", "zia.txt"]
    assert cov.scanned == 4 and cov.unreadable == 0
    assert cov.not_allowed == {"archive_class": 1}
    assert cov.archived == {"needs_restore": 2}
    assert client.listed_with[0]["OptionalObjectAttributes"] == ["RestoreStatus"]
    j = cov.storage_classes.as_json()
    assert j["GLACIER_IR"] == {
        "objects": 1,
        "bytes": len(BODY),
        "read": False,
        "reason": "archive_class",
        "toggle": "S3_READ_GLACIER_IR",
    }
    assert j["DEEP_ARCHIVE"]["reason"] == "needs_restore"
    assert j["STANDARD_IA"] == {"objects": 1, "bytes": len(BODY), "read": True}
    assert result.cursor["classesPass"]["GLACIER"] == [1, len(BODY), len(BODY)]


def test_s3_glacier_ir_is_read_with_its_setting_and_the_hook_says_not_implemented(
    env: Env,
) -> None:
    _put_classes(env)
    client = Counting(env.clients.s3)
    cov = _run(_source(client, read_glacier_ir=True, restore_archived=True)).coverage
    assert "gir.txt" in client.gets and "gda.txt" not in client.gets
    assert cov.not_allowed == {} and cov.archived == {"needs_restore": 2}
    j = cov.storage_classes.as_json()
    assert j["GLACIER_IR"]["read"] is True
    assert j["GLACIER"]["reason"] == "not_implemented"


def test_s3_a_restored_glacier_copy_is_read(env: Env) -> None:
    _put_classes(env)
    client = Counting(env.clients.s3)
    # Restored by the customer (moto then serves its GET); the listing says so.
    env.clients.s3.restore_object(Bucket=DATA, Key="gfr.txt", RestoreRequest={"Days": 1})
    client.restore_status["gfr.txt"] = {"IsRestoreInProgress": False, "RestoreExpiryDate": NOW}
    cov = _run(_source(client)).coverage
    assert "gfr.txt" in client.gets
    assert cov.archived == {"needs_restore": 1}
    assert cov.storage_classes.as_json()["GLACIER_RESTORED"]["read"] is True


def test_s3_an_archived_intelligent_tiering_object_is_needs_restore_not_unreadable(
    env: Env,
) -> None:
    _put_classes(env)
    client = Counting(env.clients.s3, refused={"it.txt": "DEEP_ARCHIVE_ACCESS"})
    cov = _run(_source(client)).coverage
    assert cov.unreadable == 0 and cov.error is None
    assert cov.archived == {"needs_restore": 3}
    j = cov.storage_classes.as_json()
    assert "INTELLIGENT_TIERING" not in j
    assert j["INTELLIGENT_TIERING_DEEP_ARCHIVE_ACCESS"]["reason"] == "needs_restore"


def test_s3_a_listing_that_refuses_restore_status_is_asked_without_it(env: Env) -> None:
    _put_classes(env)
    client = Counting(env.clients.s3)
    client.deny_optional = True
    src = _source(client)
    cov = _run(src).coverage
    assert cov.error is None and cov.scanned == 4
    assert "OptionalObjectAttributes" not in client.listed_with[-1]
    _run(src)
    assert all("OptionalObjectAttributes" not in kw for kw in client.listed_with[2:])


def test_s3_the_inventory_spans_a_pass_over_several_runs(env: Env) -> None:
    _put_classes(env)
    src = _source(Counting(env.clients.s3))
    first = _run(src, items=1)  # a budget that stops the pass after its first read
    assert not first.coverage.pass_complete
    assert not first.coverage.storage_classes.complete
    cursor = first.cursor
    for _ in range(10):
        nxt = _run(src, cursor)
        cursor = nxt.cursor
        if nxt.coverage.pass_complete:
            break
    assert nxt.coverage.storage_classes.complete
    total = sum(c[0] for c in cursor["classesPass"].values())
    assert total == len(CLASSES)  # each object counted once over the pass's runs


def test_s3_run_summary_has_the_inventory_estimate_and_gaps(env: Env) -> None:
    _put_classes(env)
    doc = env.run(config(s3_targets=[], discover=frozenset({"s3"})))
    assert doc is not None
    valid(doc)
    store = next(s for s in doc["discovery"]["stores"] if s["name"] == DATA)
    assert store["status"] == "scanned"
    assert store["gaps"] == {"needsRestore": 2, "notAllowed": 1}
    assert store["toggle"] == "S3_READ_GLACIER_IR"
    assert set(store["storageClasses"]) == set(CLASSES.values())
    cost = store["costEstimate"]
    assert cost["region"] == "us-west-2" and cost["currency"] == "USD"
    assert set(cost["byClass"]) == {"STANDARD_IA", "ONEZONE_IA", "GLACIER_IR"}
    cov = next(c for c in doc["coverage"] if c["target"].startswith(DATA))
    assert cov["archived"] == {"needs_restore": 2} and cov["unreadable"] == 0


def test_s3_the_runner_passes_the_settings_to_the_source(env: Env) -> None:
    _put_classes(env)
    c = read_config({"RESULTS_BUCKET": "x", "S3_READ_GLACIER_IR": "true"})
    assert c.s3_read_glacier_ir and not c.s3_restore_archived
    doc = env.run(config(s3_targets=[], discover=frozenset({"s3"}), s3_read_glacier_ir=True))
    assert doc is not None
    store = next(s for s in doc["discovery"]["stores"] if s["name"] == DATA)
    assert store["storageClasses"]["GLACIER_IR"]["read"] is True
    assert store["gaps"] == {"needsRestore": 2}
    assert store["toggle"] == "S3_RESTORE_ARCHIVED"


def test_s3_inventory_report_rows_carry_the_class() -> None:
    from sensitive_data_scanner.sources.inventory import _entry

    got = _entry(
        {
            "Key": "a",
            "Size": "1",
            "StorageClass": "INTELLIGENT_TIERING",
            "IntelligentTieringAccessTier": "ARCHIVE",
        },
        encoded=False,
    )
    assert got is not None and s3_class(got) == "INTELLIGENT_TIERING_ARCHIVE_ACCESS"


# ------------------------------------------------------------------ Azure and Cloud Storage


def test_azure_tiers_in_the_run_summary() -> None:
    import test_azure_blob as tab

    t = tab.tenant()
    raw = t.container("contosolake", "raw").blobs
    raw["cool/a.csv"] = Blob(tab.csv_body(), blob_tier="Cool")
    raw["cold/b.csv"] = Blob(tab.csv_body(), blob_tier="Cold")
    raw["cold/c.csv"] = Blob(
        tab.csv_body(), blob_tier="Archive", archive_status="rehydrate-pending-to-hot"
    )
    doc = tab.run(t)
    downloaded = {d[0] for d in t.container("contosolake", "raw").downloads}
    assert "cool/a.csv" in downloaded
    assert not {"cold/b.csv", "cold/c.csv", "cold/old.csv"} & downloaded
    cov = next(c for c in doc["coverage"] if c["target"] == "contosolake/raw/")
    assert cov["notAllowed"] == {"cold_tier": 1}
    assert cov["archived"] == {"needs_rehydration": 2}
    store = tab.stores(doc)["contosolake/raw"]
    assert store["gaps"]["needsRehydration"] == 2
    assert store["storageClasses"]["Archive"]["reason"] == "needs_rehydration"
    assert store["storageClasses"]["Cold"]["toggle"] == "AZURE_READ_COLD_TIER"
    cost = store["costEstimate"]
    assert cost["region"] == "eastus" and set(cost["byClass"]) == {"Cool", "Cold"}
    on = tab.run(tab.tenant(), AZURE_READ_COLD_TIER="on", AZURE_REHYDRATE_ARCHIVE="on")
    lake = tab.stores(on)["contosolake/raw"]
    assert lake["storageClasses"]["Archive"]["reason"] == "not_implemented"


def test_cloud_storage_classes_in_the_run_summary() -> None:
    import test_gcp_gcs as tg

    c = tg.cloud()
    lake = c.bucket("acme-lake").objects
    lake["near/a.csv"] = Obj(tg.csv_body(), storage_class="NEARLINE")
    lake["cold/b.csv"] = Obj(tg.csv_body(), storage_class="COLDLINE")
    doc = tg.run(c)
    store = tg.stores(doc)["acme-lake"]
    classes = store["storageClasses"]
    assert classes["ARCHIVE"] == {
        "objects": 1,
        "bytes": len(tg.csv_body()),
        "read": False,
        "reason": "archive_class",
        "toggle": "GCS_READ_ARCHIVE",
    }
    assert classes["NEARLINE"]["read"] and classes["COLDLINE"]["read"]
    cost = store["costEstimate"]
    assert cost["region"] == "us" and set(cost["byClass"]) == {"ARCHIVE", "COLDLINE", "NEARLINE"}
    assert store["toggle"] == "GCS_READ_ARCHIVE"
