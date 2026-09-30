"""Allow lists per kind, and a bucket's key filter (`keyInclude` / `keyExclude`).

An allow rule for one kind restricts only that kind; a rule of no kind restricts
every kind. A bucket's key filter reads only the keys it allows; the rest are
counted `notAllowed` (`key_filter`), never read and never a finding. S3 runs
against moto. All values are made up.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aws_fixtures import DATA, Env, config
from conftest import REPO
from sensitive_data_core.coverage import Store, apply_rules
from sensitive_data_core.findings import Coverage
from sensitive_data_core.rules import KeyFilter
from sensitive_data_scanner.config import read_config, sampling_rules, store_rules
from sensitive_data_scanner.discovery import decide
from synthetic import CARDS, SSN_A, dashed, printed

SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def decided(kind: str, name: str, allow: str, tags: dict[str, str] | None = None) -> Store:
    s = Store(kind, name, tags=tags)
    apply_rules(s, store_rules(allow), ())
    return s


# ------------------------------------------------------------------ allow lists per kind


def test_an_allow_rule_for_one_kind_restricts_only_that_kind() -> None:
    allow = "s3:calls-*"
    assert decided("s3", "calls-2026", allow).status == "pending"
    assert decided("s3", "other", allow).reason == "not_allowed"
    # No allow rule names DynamoDB or CloudWatch Logs: they are not restricted.
    assert decided("dynamodb", "orders", allow).status == "pending"
    assert decided("cloudwatch_logs", "/aws/lambda/x", allow).status == "pending"


def test_each_kind_is_restricted_by_its_own_allow_rules() -> None:
    allow = "s3:calls-*,dynamodb:orders"
    assert decided("s3", "calls-1", allow).status == "pending"
    assert decided("dynamodb", "orders", allow).status == "pending"
    assert decided("dynamodb", "carts", allow).reason == "not_allowed"
    assert decided("s3", "carts", allow).reason == "not_allowed"
    assert decided("cloudwatch_logs", "/g", allow).status == "pending"


def test_an_allow_rule_of_no_kind_restricts_every_kind() -> None:
    # A tag or a name glob with no kind applies to every kind, as before.
    allow = "tag:pii-scan=yes"
    assert decided("s3", "a", allow, {"pii-scan": "yes"}).status == "pending"
    assert decided("s3", "a", allow, {}).reason == "not_allowed"
    assert decided("dynamodb", "t", allow, {}).reason == "not_allowed"
    # With a kind's own rule beside it, that kind is allowed by either.
    allow = "tag:pii-scan=yes,s3:calls-*"
    assert decided("s3", "calls-1", allow, {}).status == "pending"
    assert decided("dynamodb", "t", allow, {}).reason == "not_allowed"


def test_deny_still_wins_over_a_kinds_allow_rule() -> None:
    s = Store("s3", "calls-private")
    apply_rules(s, store_rules("s3:calls-*"), store_rules("s3:*-private"))
    assert s.reason == "denied"


def test_discovery_decides_per_kind() -> None:
    c = config(allow=store_rules("s3:calls-*"))
    table = Store("dynamodb", "orders")
    decide(table, c)
    assert table.status == "pending"
    other = Store("s3", "other")
    decide(other, c)
    assert other.reason == "not_allowed"


# ------------------------------------------------------------------ key filters


def test_key_filter_globs() -> None:
    f = KeyFilter(include=("*transcript.json",))
    assert f.allows("calls/2026/09/abc/transcript.json")
    assert not f.allows("calls/2026/09/abc/audio.wav")
    f = KeyFilter(exclude=("*.wav", "tmp/*"))
    assert f.allows("calls/a.json")
    assert not f.allows("calls/a.wav")
    assert not f.allows("tmp/x/y.json")
    f = KeyFilter(include=("calls/*",), exclude=("*.wav",))
    assert f.allows("calls/a/transcript.json")
    assert not f.allows("calls/a/audio.wav")
    assert not f.allows("other/transcript.json")
    assert not KeyFilter()
    assert KeyFilter().allows("anything")


def test_sampling_rules_take_key_filters() -> None:
    rules = sampling_rules(
        json.dumps(
            [
                {"match": "s3:*", "samplePercent": 50},
                {"match": "s3:calls-*", "keyInclude": "*transcript.json"},
                {"match": "s3:media", "keyInclude": ["a/*", "b/*"], "keyExclude": ["*.wav"]},
            ]
        )
    )
    c = config(sampling=rules)
    # Sampling from the first rule that fits; the key filter from the first that has one.
    assert c.sampling_for("s3", "calls-1", None) == (50, None)
    assert c.key_filter_for("s3", "calls-1", None) == KeyFilter(include=("*transcript.json",))
    assert c.key_filter_for("s3", "media", None) == KeyFilter(("a/*", "b/*"), ("*.wav",))
    assert not c.key_filter_for("s3", "other", None)
    for bad in (
        '[{"match": "s3:x", "keyInclude": 1}]',
        '[{"match": "s3:x", "keyInclude": [""]}]',
        '[{"match": "s3:x", "keyExclude": ["a", 2]}]',
    ):
        with pytest.raises(ValueError, match="glob"):
            sampling_rules(bad)


def test_discovery_gives_a_bucket_its_key_filter() -> None:
    c = config(sampling=sampling_rules('[{"match": "s3:calls-*", "keyInclude": "*.json"}]'))
    s = Store("s3", "calls-1")
    decide(s, c)
    assert s.key_filter == KeyFilter(include=("*.json",))
    t = Store("dynamodb", "calls-1")
    decide(t, c)
    assert not t.key_filter


def test_coverage_counts_keys_not_allowed() -> None:
    cov = Coverage("s3", "b/")
    assert "notAllowed" not in cov.as_json()
    cov.not_allowed["key_filter"] = 3
    assert cov.as_json()["notAllowed"] == {"key_filter": 3}


def _setup(env: Env) -> None:
    env.put("calls/1/transcript.json", json.dumps({"text": f"ssn {dashed(SSN_A)}"}))
    env.put("calls/1/audio.wav", f"card {printed(CARDS['visa'])}")
    env.put("calls/2/notes.txt", f"card {printed(CARDS['visa'])}")


def test_a_bucket_is_read_for_the_keys_its_filter_allows_only(env: Env) -> None:
    _setup(env)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"s3"}),
            sampling=sampling_rules(
                json.dumps([{"match": f"s3:{DATA}", "keyInclude": "*transcript.json"}])
            ),
        )
    )
    assert doc is not None
    valid(doc)
    keys = {f["resource"]["key"] for f in doc["findings"]}
    assert keys == {"calls/1/transcript.json"}
    cov = next(c for c in doc["coverage"] if c["target"].startswith(DATA))
    assert cov["notAllowed"] == {"key_filter": 2}
    assert cov["listed"] == 3
    assert cov["scanned"] == 1
    store = next(s for s in doc["discovery"]["stores"] if s["name"] == DATA)
    assert store["status"] == "scanned"
    assert store["gaps"]["notAllowed"] == 2


def test_a_named_bucket_takes_its_key_filter_too(env: Env) -> None:
    _setup(env)
    doc = env.run(
        config(
            s3_targets=[(DATA, "calls/")],
            sampling=sampling_rules(json.dumps([{"match": f"s3:{DATA}", "keyExclude": "*.wav"}])),
        )
    )
    assert doc is not None
    valid(doc)
    keys = {f["resource"]["key"] for f in doc["findings"]}
    assert keys == {"calls/1/transcript.json", "calls/2/notes.txt"}
    assert doc["coverage"][0]["notAllowed"] == {"key_filter": 1}


def test_read_config_reads_key_filters() -> None:
    c = read_config(
        {
            "RESULTS_BUCKET": "example-scanner-results",
            "DISCOVER_SAMPLING": '[{"match": "s3:calls", "keyInclude": ["*transcript.json"]}]',
        }
    )
    assert c.key_filter_for("s3", "calls", None).allows("x/transcript.json")
    assert not c.key_filter_for("s3", "calls", None).allows("x/audio.wav")
