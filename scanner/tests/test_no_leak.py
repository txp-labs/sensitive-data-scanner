"""No value leaves: not in findings, events, logs, exception messages or reprs.

Every vector is scanned end to end (as an S3 object and as log events),
along with #1067's synthetic values in every stored form, and the DynamoDB
fixtures (positive and negative controls, and items whose key holds a
value) through the DynamoDB source. Every output is searched for every
candidate value. A second set of tests audits the source:
the only log call is `safety.log_event` with a fixed event name, and no
exception carries a message from below.
"""

from __future__ import annotations

import ast
import json
import logging
import re
from pathlib import Path
from typing import Any

import pytest

from aws_fixtures import DATA, RESULTS, Env, config, epoch_ms
from conftest import all_conversation_vectors, turns_of
from ddb_fixtures import FIXTURES, Ddb, load_item, page, target
from sensitive_data_core import safety
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.conversation import classify
from sensitive_data_core.engine.normalize import normalize
from sensitive_data_core.engine.spec import load_spec
from sensitive_data_core.safety import ScanError, redact_digits
from sensitive_data_core.scan.attributes import scan_attributes
from sensitive_data_core.scan.item import scan_item_text
from sensitive_data_scanner.sources.dynamodb import DynamoDBSource
from synthetic import CARDS, SSN_A, SSN_B, all_values, dashed, printed, spaced, spoken_groups
from test_exports import READ_ONLY_PG

SPEC = load_spec()
VECTORS = all_conversation_vectors()
SCANNER = Path(__file__).resolve().parents[1]
# Every package the audit reads: the core, and each platform's package.
PACKAGES = sorted(
    pkg for src in (SCANNER / "src", *SCANNER.glob("*/src")) for pkg in src.glob("sensitive_data_*")
)
DIGIT_WORD = r"(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)"


def candidates() -> set[str]:
    """Every value a vector or fixture holds: digit runs of 6 or more, raw and normalized."""
    out = set(all_values())
    for case in VECTORS:
        for t in case["turns"]:
            for text in (t["text"], normalize(t["text"], SPEC.normalize).text):
                out.update(m[0] for m in re.finditer(r"[0-9]{6,}", text))
                for m in re.finditer(r"[0-9](?:[ -]?[0-9]){5,}", text):
                    out.add(m[0])
                    out.add(re.sub(r"[ -]", "", m[0]))
    for path in FIXTURES.glob("*.json"):
        out.update(m[0] for m in re.finditer(r"[0-9]{6,}", path.read_text()))
    return out


CANDIDATES = candidates()


def leaks(blob: str) -> list[str]:
    found = [c for c in CANDIDATES if re.search(rf"(?<![0-9]){re.escape(c)}(?![0-9])", blob)]
    if re.search(rf"\b{DIGIT_WORD}(?:[ ,]+{DIGIT_WORD}){{3,}}\b", blob, re.I):
        found.append("<spoken digits>")
    return found


def chat_document(case: dict[str, Any]) -> str:
    """A vector without a source document, as a Connect chat transcript."""
    role = {"agent": "AGENT", "customer": "CUSTOMER", "bot": "SYSTEM"}
    return json.dumps(
        {
            "Version": "2019-08-26",
            "ContactId": "11111111-2222-3333-4444-555555555555",
            "Transcript": [
                {
                    "Type": "MESSAGE",
                    "Content": t["text"],
                    "ParticipantId": t["speaker"],
                    "ParticipantRole": role[t["speaker"]],
                    "AbsoluteTime": "2026-09-28T15:00:00.000Z",
                }
                for t in case["turns"]
            ],
        }
    )


STORED = [
    ("stored/printed.txt", f"card {printed(CARDS['visa'])}"),
    ("stored/plain.log", f"value={CARDS['jcb']} ssn {dashed(SSN_A)} social {SSN_B}"),
    ("stored/export.csv", "name,card_number\n" + "\n".join(CARDS.values())),
    ("stored/spaced.txt", f"card: {spaced(CARDS['amex'])}"),
    ("stored/spoken.txt", f"my visa is {spoken_groups(CARDS['visa'])}"),
    (
        "stored/lambda.json",
        json.dumps({"cardNumber": CARDS["mir"], "ssn": dashed(SSN_B), "dob": "DOB 7/4/1981"}),
    ),
]


def test_candidates_cover_every_class_of_value() -> None:
    assert {CARDS["visa"], SSN_A, "010180", "123456789", "5555666677778888"} <= CANDIDATES


def test_no_value_in_findings_events_or_logs(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda

    for case in VECTORS:
        doc = case.get("document")
        if doc and doc["format"] == "lex_v2_log":
            env.put(f"vectors/{case['id']}.jsonl", doc["content"])
        elif doc:
            env.put(f"vectors/{case['id']}.json", doc["content"])
        else:
            env.put(f"vectors/{case['id']}.json", chat_document(case))
    for key, body in STORED:
        env.put(key, body)
    t = epoch_ms(__import__("datetime").datetime.now(__import__("datetime").UTC)) - 3_600_000
    messages = [(t + i, t_["text"]) for i, case in enumerate(VECTORS) for t_ in case["turns"][:1]]
    messages += [(t + 1000 + i, body) for i, (_, body) in enumerate(STORED)]
    env.log("/aws/lambda/everything", "stream", sorted(messages))

    sent: list[dict[str, Any]] = []

    class Bus:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            sent.extend(Entries)
            return {"FailedEntryCount": 0}

    env.clients.events = Bus()  # type: ignore[assignment]
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(log_groups=["/aws/lambda/everything"], event_bus_arn="arn:aws:events:x:1:b/c")
    )
    assert doc is not None
    assert doc["findingsTotal"] > 40  # the scan did find things
    outputs = {
        "findings/latest.json": json.dumps(env.latest()),
        "events": json.dumps(sent),
        "stdout+stderr": "".join(capsys.readouterr()),
        "log records": "\n".join(r.getMessage() for r in caplog.records),
    }
    for obj in env.clients.s3.list_objects_v2(Bucket=RESULTS)["Contents"]:
        if obj["Key"].startswith("findings/"):
            data = env.clients.s3.get_object(Bucket=RESULTS, Key=obj["Key"])["Body"].read()
            outputs[obj["Key"]] = data.decode()
    for name, blob in outputs.items():
        assert leaks(blob) == [], name


def ddb_items() -> list[dict[str, Any]]:
    """The positive and negative controls, and the positive one keyed by a card and an SSN."""
    keyed = load_item("stugum-positive")
    keyed["pk"] = {"S": f"CUST#{SSN_B}"}
    keyed["sk"] = {"S": f"CARD#{CARDS['mastercard']}"}
    others = [load_item(n) for n in ("stugum-negative", "stugum-regex-not-prompt", "stugum-failed")]
    return [load_item("stugum-positive"), keyed, *others]


def test_no_value_leaves_the_dynamodb_source(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda

    ddb = Ddb()
    ddb.describe()
    ddb.error("query", "ProvisionedThroughputExceededException")  # a throttle is logged
    ddb.query(page(ddb_items()))
    env.clients.dynamodb = ddb.client
    sent: list[dict[str, Any]] = []

    class Bus:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            sent.extend(Entries)
            return {"FailedEntryCount": 0}

    env.clients.events = Bus()  # type: ignore[assignment]
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(s3_targets=[], dynamodb_targets=[target()], event_bus_arn="arn:aws:events:x:1:b/c")
    )
    assert doc is not None
    assert doc["findingsTotal"] >= 6  # both clear items, three classes each
    outputs = {
        "findings/latest.json": json.dumps(env.latest()),
        "events": json.dumps(sent),
        "stdout+stderr": "".join(capsys.readouterr()),
        "log records": "\n".join(r.getMessage() for r in caplog.records),
    }
    for name, blob in outputs.items():
        assert leaks(blob) == [], name
    detector = __import__("aws_fixtures").shared_detector()
    rules = DynamoDBSource(Ddb().client, target=target(), region="us-west-2").rules
    results = [scan_attributes(item, detector, rules) for item in ddb_items()]
    assert results[0].by_path  # the positive control was found
    blobs = [repr(r) + repr(list(r.by_path.values())) for r in results]
    assert leaks("\n".join(blobs)) == []


def test_no_value_leaves_discovery(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """Stores whose very names hold a card number or an SSN, found by discovery, read,
    denied and deferred: the summary, findings, events and logs mask every name."""
    from botocore.stub import ANY

    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from sensitive_data_scanner.config import store_rules

    s3 = env.clients.s3
    card_bucket = f"{CARDS['visa']}-exports"
    denied_bucket = f"{SSN_A}-denied"
    for b in (card_bucket, denied_bucket):
        s3.create_bucket(Bucket=b, CreateBucketConfiguration={"LocationConstraint": "us-west-2"})
    s3.put_object(Bucket=card_bucket, Key=f"k/{SSN_B}.txt", Body=f"card {CARDS['jcb']}".encode())
    group = f"/app/cust-{SSN_B}"
    t = epoch_ms(__import__("datetime").datetime.now(__import__("datetime").UTC)) - 3_600_000
    env.log(group, f"stream-{CARDS['amex']}", [(t, f"ssn {dashed(SSN_A)}")])
    table = f"orders-{CARDS['mastercard']}"
    ddb = Ddb()
    ddb.stub.add_response("list_tables", {"TableNames": [table]})
    desc = {
        "Table": {
            "TableName": table,
            "TableStatus": "ACTIVE",
            "TableSizeBytes": 10,
            "TableArn": f"arn:aws:dynamodb:us-west-2:123456789012:table/{table}",
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        }
    }
    ddb.stub.add_response("describe_table", desc)
    ddb.stub.add_response("describe_table", desc)
    ddb.stub.add_response(
        "scan",
        {
            "Items": [{"pk": {"S": f"C#{CARDS['discover']}"}, "ssn": {"S": dashed(SSN_B)}}],
            "Count": 1,
            "ScannedCount": 1,
        },
        {"TableName": table, "Limit": ANY},
    )
    env.clients.dynamodb = ddb.client
    sent: list[dict[str, Any]] = []

    class Bus:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            sent.extend(Entries)
            return {"FailedEntryCount": 0}

    env.clients.events = Bus()  # type: ignore[assignment]
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"s3", "cloudwatch_logs", "dynamodb"}),
            deny=store_rules(f"s3:{SSN_A}-*"),
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    assert {f["resource"]["type"] for f in doc["findings"]} == {
        "s3_object",
        "log_event",
        "dynamodb_item",
    }
    reasons = {s.get("reason") for s in doc["discovery"]["stores"]}
    assert "denied" in reasons
    assert sum(1 for s in doc["discovery"]["stores"] if s.get("nameMasked")) >= 4
    outputs = {
        "findings/latest.json": json.dumps(env.latest()),
        "events": json.dumps(sent),
        "stdout+stderr": "".join(capsys.readouterr()),
        "log records": "\n".join(r.getMessage() for r in caplog.records),
    }
    for name, blob in outputs.items():
        assert leaks(blob) == [], name


def test_no_value_leaves_columnar_formats_or_the_catalog(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """Parquet, ORC, Avro and zstd JSON lines with values in cells, in column names and in
    nested keys, and a Glue table whose database, name and location hold values."""
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from table_fixtures import (
        Glue,
        arrow_table,
        avro_bytes,
        glue_table,
        orc_bytes,
        parquet_bytes,
        zstd_bytes,
    )

    rows = [
        {
            f"acct_{CARDS['visa']}": CARDS["visa"],
            "ssn": int(SSN_A),
            "nested": {CARDS["jcb"]: dashed(SSN_B), "pan": CARDS["amex"]},
        }
    ]
    env.put("lake/a.parquet", parquet_bytes(arrow_table(rows)))
    env.put("lake/b.orc", orc_bytes(arrow_table(rows)))
    env.put("lake/c.avro", avro_bytes("snappy"))
    env.put("lake/d.jsonl.zst", zstd_bytes(json.dumps(rows[0], default=str).encode()))
    env.put(f"gov/{SSN_B}/part-0.parquet", parquet_bytes(arrow_table(rows)))
    glue = Glue()
    glue.databases(f"db_{SSN_A}")
    glue.tables(
        f"db_{SSN_A}",
        [glue_table(f"t_{CARDS['mastercard']}", f"s3://{DATA}/gov/{SSN_B}/")],
    )
    env.clients.glue = glue.client
    sent: list[dict[str, Any]] = []

    class Bus:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            sent.extend(Entries)
            return {"FailedEntryCount": 0}

    env.clients.events = Bus()  # type: ignore[assignment]
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"s3", "glue_table"}),
            deny=__import__("sensitive_data_scanner.config").config.store_rules(f"s3:{RESULTS}"),
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    formats = {f["format"] for f in doc["findings"]}
    assert {"parquet", "orc", "avro", "json"} <= formats
    assert any(f["resource"].get("catalog") for f in doc["findings"])
    outputs = {
        "findings/latest.json": json.dumps(env.latest()),
        "events": json.dumps(sent),
        "stdout+stderr": "".join(capsys.readouterr()),
        "log records": "\n".join(r.getMessage() for r in caplog.records),
    }
    for name, blob in outputs.items():
        assert leaks(blob) == [], name
    from sensitive_data_core.scan.columnar import scan_rows

    result = scan_rows(
        "parquet", list(rows[0]), rows, __import__("aws_fixtures").shared_detector(), 10
    )
    assert result.by_column
    # Column names are names from the account, like keys: a repr shows counts only.
    assert leaks(repr(result)) == []


def test_no_value_leaves_the_exports_or_the_data_api(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """An RDS snapshot export whose cluster, table and column names hold values, and a
    Data API read of a table named by a card number: nothing but masked names leaves."""
    from botocore.stub import ANY

    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from table_fixtures import arrow_table, parquet_bytes
    from test_exports import CLUSTER_ARN, KEY, ROLE, SECRET_ARN, client, target

    ident = f"orders-{SSN_A}"
    rds, stub = client("rds")
    rd, dstub = client("rds-data")
    env.clients.rds = rds
    env.clients.rds_data = rd
    stub.add_response(
        "describe_db_clusters",
        {"DBClusters": [{"DBClusterIdentifier": ident, "Engine": "aurora-postgresql"}]},
    )
    stub.add_response("describe_db_instances", {"DBInstances": []})
    stub.add_response(
        "describe_db_cluster_snapshots",
        {
            "DBClusterSnapshots": [
                {
                    "DBClusterSnapshotArn": (
                        f"arn:aws:rds:us-west-2:123456789012:cluster-snapshot:rds:{ident}-1"
                    ),
                    "DBClusterSnapshotIdentifier": f"rds:{ident}-1",
                    "SnapshotCreateTime": __import__("datetime").datetime(2026, 9, 29),
                    "Status": "available",
                }
            ]
        },
    )
    stub.add_response("start_export_task", {"ExportTaskIdentifier": "t"})

    # The Data API reads a table named by a card, with values in its rows.
    def for_data_api(dstub: Any) -> None:
        dstub.add_response("begin_transaction", {"transactionId": "tx"})
        dstub.add_response("execute_statement", {})
        dstub.add_response("execute_statement", {"formattedRecords": json.dumps([READ_ONLY_PG])})
        listed = [{"table_schema": "public", "table_name": f"t_{CARDS['visa']}"}]
        dstub.add_response("execute_statement", {"formattedRecords": json.dumps(listed)})
        rows = [{f"c_{CARDS['jcb']}": CARDS["amex"], "ssn": dashed(SSN_B)}]
        dstub.add_response("execute_statement", {"formattedRecords": json.dumps(rows)})
        dstub.add_response("rollback_transaction", {})

    for_data_api(dstub)
    cfg = config(
        s3_targets=[],
        discover=frozenset({"rds"}),
        rds_export_role_arn=ROLE,
        rds_export_kms_key_arn=KEY,
        data_api_targets=[target()],
        event_bus_arn="arn:aws:events:x:1:b/c",
    )
    env.run(cfg)
    task = env.state()["cursors"][f"rds:cluster:{ident}"]["task"]
    rows = [{f"col_{CARDS['mastercard']}": CARDS["visa"], "ssn": int(SSN_A)}]
    env.clients.s3.put_object(
        Bucket=RESULTS,
        Key=f"exports/rds/{task}/app_{SSN_B}/public.cust_{SSN_B}/1/part-0.gz.parquet",
        Body=parquet_bytes(arrow_table(rows)),
    )
    stub.add_response(
        "describe_db_clusters",
        {"DBClusters": [{"DBClusterIdentifier": ident, "Engine": "aurora-postgresql"}]},
    )
    stub.add_response("describe_db_instances", {"DBInstances": []})
    stub.add_response(
        "describe_export_tasks",
        {"ExportTasks": [{"Status": "COMPLETE"}]},
        {"ExportTaskIdentifier": ANY},
    )
    for_data_api(dstub)
    sent: list[dict[str, Any]] = []

    class Bus:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            sent.extend(Entries)
            return {"FailedEntryCount": 0}

    env.clients.events = Bus()  # type: ignore[assignment]
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(cfg)
    assert doc is not None
    stub.assert_no_pending_responses()
    kinds = {(f["resource"]["type"], f["resource"]["readBy"]) for f in doc["findings"]}
    assert kinds == {("rds_column", "snapshot_export"), ("rds_column", "data_api")}
    assert all(f["resource"].get("keyMasked") for f in doc["findings"])
    outputs = {
        "findings/latest.json": json.dumps(env.latest()),
        "events": json.dumps(sent),
        "stdout+stderr": "".join(capsys.readouterr()),
        "log records": "\n".join(r.getMessage() for r in caplog.records),
    }
    for name, blob in outputs.items():
        assert leaks(blob) == [], name
    del CLUSTER_ARN, SECRET_ARN


def _outputs(env: Env, sent: list[dict[str, Any]], capsys: Any, caplog: Any) -> dict[str, str]:
    # state/ is the scanner's own (cursors name the last key read, as for S3 and
    # DynamoDB); what leaves the account is the findings, the events and the logs.
    return {
        "findings/latest.json": json.dumps(env.latest()),
        "events": json.dumps(sent),
        "stdout+stderr": "".join(capsys.readouterr()),
        "log records": "\n".join(r.getMessage() for r in caplog.records),
    }


def _bus(env: Env) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    class Bus:
        def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
            sent.extend(Entries)
            return {"FailedEntryCount": 0}

    env.clients.events = Bus()  # type: ignore[assignment]
    return sent


def test_no_value_leaves_redshift(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """A cluster and a workgroup whose names, databases, tables and columns hold values, read
    by sampled SQL: findings, state, events and logs hold masked names and counts only."""
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from test_redshift import Aws

    aws = Aws(env)
    cluster = f"wh-{SSN_A}"
    group = f"wg-{CARDS['visa']}"
    aws.rs_stub.add_response(
        "describe_clusters",
        {"Clusters": [{"ClusterIdentifier": cluster, "ClusterStatus": "available"}]},
    )
    aws.sl_stub.add_response(
        "list_namespaces", {"namespaces": [{"namespaceName": "n-1", "dbName": f"db_{SSN_B}"}]}
    )
    aws.sl_stub.add_response(
        "list_workgroups",
        {"workgroups": [{"workgroupName": group, "namespaceName": "n-1", "status": "AVAILABLE"}]},
    )
    rows = [{f"c_{CARDS['jcb']}": CARDS["amex"], "ssn": dashed(SSN_B), "n": int(SSN_A)}]
    # Stores run in name order: the workgroup ("wg-") before the cluster ("wh-").
    wg = {"WorkgroupName": group}
    aws.data_stub.add_response("list_databases", {"Databases": [f"db_{SSN_B}"]})
    aws.database(f"db_{SSN_B}", {(f"s_{SSN_A}", f"t_{CARDS['mastercard']}"): rows}, auth=wg)
    cl = {"ClusterIdentifier": cluster}
    aws.data_stub.add_response("list_databases", {"Databases": ["dev"]})
    aws.database("dev", {("public", f"cust_{SSN_B}"): rows}, auth=cl)
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"redshift"}),
            redshift_read="iam",
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    aws.data_stub.assert_no_pending_responses()
    assert {f["resource"]["service"] for f in doc["findings"]} == {
        "redshift",
        "redshift_serverless",
    }
    assert all(f["resource"].get("keyMasked") and f["link"] is None for f in doc["findings"])
    assert all(s.get("nameMasked") for s in doc["discovery"]["stores"])
    for name, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name


def test_no_value_leaves_opensearch(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """A domain, indices and fields named with values, and values in documents."""
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from test_opensearch import ENDPOINT, Aws, domain

    aws = Aws(env)
    name = f"logs-{SSN_A}"
    aws.es_stub.add_response("list_domain_names", {"DomainNames": [{"DomainName": name}]})
    aws.es_stub.add_response(
        "describe_domains", {"DomainStatusList": [domain(name, Endpoint=ENDPOINT)]}
    )
    aws.aoss_stub.add_response("list_collections", {"collectionSummaries": []})
    index = f"cust-{CARDS['visa']}"
    aws.indices(ENDPOINT, [index, f"idx-{SSN_B}"])
    docs = [{f"f_{CARDS['jcb']}": CARDS["amex"], "ssn": dashed(SSN_B), "n": int(SSN_A)}]
    aws.docs(ENDPOINT, index, docs)
    aws.http.route(ENDPOINT, f"/idx-{SSN_B}/_search?size=100", {}, 500)
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"opensearch"}),
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    assert len(doc["findings"]) >= 2
    assert all(f["resource"].get("keyMasked") and f["link"] is None for f in doc["findings"])
    for name_, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name_


def test_no_value_leaves_snapshots_backups_or_clusters(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """EBS blocks holding values, and a Backup vault and DocumentDB cluster named with them."""
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from test_snapshots import T2, blocks, snapshot, stubs

    s = stubs(env, "ec2", "ebs", "backup", "docdb", "docdb-elastic")
    s["ec2"].add_response("describe_volumes", {"Volumes": [{"VolumeId": "vol-0a1", "Size": 1}]})
    s["ec2"].add_response(
        "describe_snapshots", {"Snapshots": [snapshot("snap-new", "vol-0a1", T2)]}
    )
    s["backup"].add_response(
        "list_backup_vaults",
        {"BackupVaultList": [{"BackupVaultName": f"vault-{SSN_A}", "BackupVaultArn": "arn:v"}]},
    )
    s["backup"].add_response("list_recovery_points_by_backup_vault", {"RecoveryPoints": []})
    s["docdb"].add_response(
        "describe_db_clusters",
        {"DBClusters": [{"DBClusterIdentifier": f"docs-{SSN_B}", "Engine": "docdb"}]},
    )
    s["docdb-elastic"].add_response(
        "list_clusters",
        {"clusters": [{"clusterName": f"e-{CARDS['visa']}", "clusterArn": "a", "status": "x"}]},
    )
    blocks(
        s["ebs"],
        "snap-new",
        0,
        [f"card {CARDS['jcb']} ssn {dashed(SSN_B)}", f"{CARDS['amex']} and {SSN_A}"],
    )
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"ebs", "backup", "documentdb"}),
            ebs_direct_read=True,
            ebs_blocks_per_snapshot=4,
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    assert {f["class"] for f in doc["findings"]} >= {"card", "us_ssn"}
    assert sum(1 for x in doc["discovery"]["stores"] if x.get("nameMasked")) == 3
    for name_, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name_


def test_no_value_leaves_streams_or_queues(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """A Kinesis stream, a Firehose stream and its prefix, and a dead-letter queue, named with
    values and carrying values."""
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from test_streams import describe, stubs

    s = stubs(env, "kinesis", "firehose", "sqs")
    stream = f"clicks-{SSN_A}"
    s["kinesis"].add_response(
        "list_streams",
        {
            "StreamNames": [stream],
            "HasMoreStreams": False,
            "StreamSummaries": [
                {"StreamName": stream, "StreamARN": "arn:k", "StreamStatus": "ACTIVE"}
            ],
        },
    )
    s["kinesis"].add_response(
        "list_shards",
        {
            "Shards": [
                {
                    "ShardId": "shardId-000000000000",
                    "HashKeyRange": {"StartingHashKey": "0", "EndingHashKey": "1"},
                    "SequenceNumberRange": {"StartingSequenceNumber": "1"},
                }
            ]
        },
    )
    s["kinesis"].add_response("get_shard_iterator", {"ShardIterator": "it"})
    data = json.dumps({f"k_{CARDS['mir']}": CARDS["visa"], "ssn": dashed(SSN_B)}).encode()
    s["kinesis"].add_response(
        "get_records",
        {"Records": [{"SequenceNumber": "1", "Data": data, "PartitionKey": SSN_A}]},
    )
    env.put(f"fh/{SSN_B}/part-1", json.dumps({"card": CARDS["jcb"]}))
    s["firehose"].add_response(
        "list_delivery_streams",
        {"DeliveryStreamNames": [f"fh-{SSN_B}"], "HasMoreDeliveryStreams": False},
    )
    s["firehose"].add_response(
        "describe_delivery_stream",
        describe(
            f"fh-{SSN_B}",
            [
                {
                    "DestinationId": "d",
                    "S3DestinationDescription": {
                        "BucketARN": f"arn:aws:s3:::{DATA}",
                        "Prefix": f"fh/{SSN_B}/",
                        "RoleARN": "arn:aws:iam::123456789012:role/r",
                        "BufferingHints": {},
                        "CompressionFormat": "UNCOMPRESSED",
                        "EncryptionConfiguration": {},
                    },
                }
            ],
        ),
    )
    dlq = f"dlq-{CARDS['amex']}"
    url = f"https://sqs.us-west-2.amazonaws.com/123456789012/{dlq}"
    src = "https://sqs.us-west-2.amazonaws.com/123456789012/src"
    s["sqs"].add_response("list_queues", {"QueueUrls": [url, src]})
    s["sqs"].add_response(
        "get_queue_attributes", {"Attributes": {"QueueArn": f"arn:aws:sqs:us-west-2:1:{dlq}"}}
    )
    s["sqs"].add_response(
        "get_queue_attributes",
        {
            "Attributes": {
                "QueueArn": "arn:aws:sqs:us-west-2:1:src",
                "RedrivePolicy": json.dumps(
                    {"deadLetterTargetArn": f"arn:aws:sqs:us-west-2:1:{dlq}"}
                ),
            }
        },
    )
    body = json.dumps({"pan": CARDS["discover"], "dob": "DOB 7/4/1981", "n": SSN_A})
    s["sqs"].add_response("receive_message", {"Messages": [{"MessageId": SSN_B, "Body": body}]})
    s["sqs"].add_response("receive_message", {"Messages": []})
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"kinesis", "firehose", "sqs"}),
            sqs_dlq_read=True,
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    services = {f["resource"].get("service", f["resource"]["type"]) for f in doc["findings"]}
    assert services == {"kinesis", "sqs", "s3_object"}
    for name_, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name_


def test_no_value_or_key_name_leaves_the_encryption_facts(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """A stream encrypted with a customer key named by an alias that holds a value (1.5): the
    finding names the key only by the hash of its id, never the alias, the id or the ARN."""
    from test_streams import stubs

    s = stubs(env, "kinesis", "kms")
    cmk = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
    alias = f"alias/pan-{CARDS['visa']}"
    s["kms"].add_response(
        "list_aliases",
        {"Aliases": [{"AliasName": alias, "TargetKeyId": cmk}], "Truncated": False},
    )
    stream = f"pay-{SSN_A}"
    s["kinesis"].add_response(
        "list_streams",
        {
            "StreamNames": [stream],
            "HasMoreStreams": False,
            "StreamSummaries": [
                {"StreamName": stream, "StreamARN": "arn:k", "StreamStatus": "ACTIVE"}
            ],
        },
    )
    s["kinesis"].add_response(
        "describe_stream_summary",
        {
            "StreamDescriptionSummary": {
                "StreamName": stream,
                "StreamARN": "arn:k",
                "StreamStatus": "ACTIVE",
                "RetentionPeriodHours": 24,
                "StreamCreationTimestamp": "2026-09-01T00:00:00Z",
                "EnhancedMonitoring": [],
                "EncryptionType": "KMS",
                "KeyId": f"arn:aws:kms:us-west-2:123456789012:{alias}",
                "OpenShardCount": 1,
            }
        },
    )
    s["kinesis"].add_response(
        "list_shards",
        {
            "Shards": [
                {
                    "ShardId": "shardId-000000000000",
                    "HashKeyRange": {"StartingHashKey": "0", "EndingHashKey": "1"},
                    "SequenceNumberRange": {"StartingSequenceNumber": "1"},
                }
            ]
        },
    )
    s["kinesis"].add_response("get_shard_iterator", {"ShardIterator": "it"})
    data = json.dumps({"card": CARDS["amex"], "cvv": "CVV 482"}).encode()
    s["kinesis"].add_response(
        "get_records", {"Records": [{"SequenceNumber": "1", "Data": data, "PartitionKey": "p"}]}
    )
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[], discover=frozenset({"kinesis"}), event_bus_arn="arn:aws:events:x:1:b/c"
        )
    )
    assert doc is not None
    card = next(f for f in doc["findings"] if f["class"] == "card")
    assert card["atRestEncryption"] == "customer_managed_key"
    for name_, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name_
        assert cmk not in blob and "pan-" not in blob, name_


def test_no_value_leaves_workflows_functions_traces_or_code(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """Group 7's defaults (#35): a state machine, a function and its variables, a traced
    service, a repository and a file path named with values, all carrying values."""
    import datetime as dt

    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from test_streams import stubs

    t0 = dt.datetime(2026, 9, 29, tzinfo=dt.UTC)
    s = stubs(env, "stepfunctions", "lambda", "xray", "codecommit")
    machine = f"orders-{SSN_A}"
    arn = f"arn:aws:states:us-west-2:123456789012:stateMachine:{machine}"
    sfn = s["stepfunctions"]
    sfn.add_response(
        "list_state_machines",
        {
            "stateMachines": [
                {"stateMachineArn": arn, "name": machine, "type": "STANDARD", "creationDate": t0}
            ]
        },
    )
    sfn.add_response(
        "describe_state_machine",
        {
            "stateMachineArn": arn,
            "name": machine,
            "definition": "{}",
            "roleArn": "arn:aws:iam::1:role/r",
            "type": "STANDARD",
            "creationDate": t0,
        },
    )
    ex = f"arn:aws:states:us-west-2:123456789012:execution:{machine}:{CARDS['mir']}"
    sfn.add_response(
        "list_executions",
        {
            "executions": [
                {
                    "executionArn": ex,
                    "stateMachineArn": arn,
                    "name": CARDS["mir"],
                    "status": "FAILED",
                    "startDate": t0,
                }
            ]
        },
    )
    sfn.add_response(
        "get_execution_history",
        {
            "events": [
                {
                    "timestamp": t0,
                    "type": "ExecutionStarted",
                    "id": 1,
                    "executionStartedEventDetails": {
                        "input": json.dumps({"card": CARDS["visa"], "ssn": dashed(SSN_B)})
                    },
                },
                {
                    "timestamp": t0,
                    "type": "ExecutionFailed",
                    "id": 2,
                    "executionFailedEventDetails": {"cause": f"declined {CARDS['amex']}"},
                },
            ]
        },
    )
    fn = f"pay-{SSN_B}"
    s["lambda"].add_response(
        "list_functions",
        {"Functions": [{"FunctionName": fn, "FunctionArn": f"arn:aws:lambda:x:1:function:{fn}"}]},
    )
    s["lambda"].add_response(
        "get_function_configuration",
        {
            "FunctionName": fn,
            "Environment": {"Variables": {f"K_{CARDS['jcb']}": CARDS["discover"], "S": SSN_A}},
        },
    )
    x = s["xray"]
    x.add_response("get_encryption_config", {"EncryptionConfig": {"Type": "NONE"}})
    x.add_response("get_trace_summaries", {"TraceSummaries": [{"Id": "1-00000000-0"}]})
    document = {
        "id": "a",
        "name": f"svc-{SSN_A}",
        "annotations": {f"a_{CARDS['visa13']}": CARDS["mastercard"]},
        "metadata": {"default": {"ssn": dashed(SSN_A)}},
    }
    x.add_response(
        "batch_get_traces",
        {"Traces": [{"Id": "t", "Segments": [{"Id": "s", "Document": json.dumps(document)}]}]},
    )
    for _ in range(3):
        x.add_response("get_trace_summaries", {"TraceSummaries": []})
    repo = f"repo-{SSN_B}"
    cc = s["codecommit"]
    cc.add_response(
        "list_repositories", {"repositories": [{"repositoryName": repo, "repositoryId": "r"}]}
    )
    cc.add_response(
        "get_repository",
        {"repositoryMetadata": {"repositoryName": repo, "defaultBranch": "main", "Arn": "a"}},
    )
    cc.add_response("get_branch", {"branch": {"branchName": "main", "commitId": "c"}})
    path = f"data/{CARDS['unionpay']}.txt"
    cc.add_response(
        "get_folder",
        {
            "commitId": "c",
            "folderPath": "/",
            "files": [{"absolutePath": path, "relativePath": path, "blobId": "b"}],
        },
    )
    cc.add_response(
        "get_file",
        {
            "commitId": "c",
            "blobId": "b",
            "filePath": path,
            "fileMode": "NORMAL",
            "fileSize": 10,
            "fileContent": f"card {CARDS['maestro']} ssn {dashed(SSN_A)}".encode(),
        },
    )
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"stepfunctions", "lambda", "xray", "codecommit"}),
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    services = {f["resource"]["service"] for f in doc["findings"]}
    assert services == {"stepfunctions", "lambda", "xray", "codecommit"}
    for name_, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name_


def test_no_value_leaves_directory_buckets(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """An S3 directory bucket whose keys hold values (#35), read through the S3 source."""
    import datetime as dt
    import io

    import boto3
    from botocore.response import StreamingBody
    from botocore.stub import Stubber

    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda

    s3: Any = boto3.client(
        "s3",
        region_name="us-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
    )
    stub = Stubber(s3)
    env.clients.services["s3"] = s3
    bucket = "pan--usw2-az1--x-s3"
    key = f"cards/{CARDS['visa']}/{SSN_A}.json"
    data = json.dumps({"card": CARDS["amex"], "ssn": dashed(SSN_B)}).encode()
    stub.add_response("list_directory_buckets", {"Buckets": [{"Name": bucket}]})
    stub.add_response(
        "list_objects_v2",
        {
            "Contents": [{"Key": key, "Size": len(data), "LastModified": dt.datetime.now(dt.UTC)}],
            "IsTruncated": False,
        },
    )
    stub.add_response("get_object", {"Body": StreamingBody(io.BytesIO(data), len(data))})
    stub.activate()
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"s3_directory"}),
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    assert {f["class"] for f in doc["findings"]} == {"card", "us_ssn"}
    for name_, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name_


def test_no_value_leaves_the_brokers(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """An MSK cluster and topic and an ActiveMQ broker and queue named with values, carrying
    values; the broker user's password is never written anywhere (#35)."""
    import base64

    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from sensitive_data_scanner.config import MqTarget
    from test_brokers import READ_ONLY_CONFIG, FakeConsumer
    from test_streams import stubs

    s = stubs(env, "kafka", "mq", "secretsmanager")
    cluster = f"pay-{SSN_A}"
    arn = f"arn:aws:kafka:us-west-2:123456789012:cluster/{cluster}/x"
    s["kafka"].add_response(
        "list_clusters_v2",
        {
            "ClusterInfoList": [
                {
                    "ClusterName": cluster,
                    "ClusterArn": arn,
                    "ClusterType": "SERVERLESS",
                    "State": "ACTIVE",
                }
            ]
        },
    )
    s["kafka"].add_response("get_bootstrap_brokers", {"BootstrapBrokerStringSaslIam": "b:9098"})
    topic = f"cards-{CARDS['visa']}"
    consumer = FakeConsumer({topic: {0: [json.dumps({"pan": CARDS["amex"]}).encode()]}})
    env.clients.services["kafka-consumer"] = lambda b, r, g: consumer
    broker = f"mq-{SSN_B}"
    broker_id = "b-1234abcd-56ef-78ab-90cd-ef1234567890"
    password = f"pw-{CARDS['jcb']}"
    s["mq"].add_response(
        "list_brokers",
        {
            "BrokerSummaries": [
                {
                    "BrokerName": broker,
                    "BrokerId": broker_id,
                    "EngineType": "ACTIVEMQ",
                    "DeploymentMode": "SINGLE_INSTANCE",
                }
            ]
        },
    )
    described = {
        "BrokerId": broker_id,
        "BrokerName": broker,
        "BrokerState": "RUNNING",
        "EngineType": "ACTIVEMQ",
        "BrokerInstances": [{"Endpoints": ["stomp+ssl://h:61614"]}],
        "Configurations": {"Current": {"Id": "c", "Revision": 1}},
    }
    s["mq"].add_response("describe_broker", described)
    s["mq"].add_response("describe_broker", described)
    user_ref = "arn:aws:secretsmanager:us-west-2:123456789012:secret:mq-AbCdEf"
    s["secretsmanager"].add_response(
        "get_secret_value",
        {"SecretString": json.dumps({"username": f"u{SSN_A}", "password": password})},
    )
    s["mq"].add_response(
        "describe_user",
        {"BrokerId": broker_id, "Username": f"u{SSN_A}", "Groups": ["readers"]},
    )
    s["mq"].add_response(
        "describe_configuration_revision",
        {"Data": base64.b64encode(READ_ONLY_CONFIG.encode()).decode()},
    )
    queue = f"q-{CARDS['discover']}"

    class Browser:
        def __init__(self, endpoints: list[str], username: str, pw: str) -> None:
            assert pw == password

        def browse(self, name: str, limit: int) -> list[bytes]:
            return [f"ssn {dashed(SSN_A)} card {CARDS['mastercard']}".encode()]

        def close(self) -> None:
            return None

    env.clients.services["stomp"] = Browser
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"msk", "mq"}),
            msk_read=True,
            mq_read=True,
            mq_brokers=[MqTarget(broker, user_ref, (queue,))],
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    assert {f["resource"]["service"] for f in doc["findings"]} == {"msk", "mq"}
    for name_, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name_
        assert "pw-" not in blob, name_


def test_no_value_leaves_images_graphs_or_archives(
    env: Env,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ECR repository, layer paths, a graph, its properties, an archive and a vault named
    with values, carrying values (#35)."""
    import io

    from botocore.stub import ANY

    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from test_images_archives import layer
    from test_streams import stubs

    s = stubs(env, "ecr", "neptune-graph", "events", "sqs", "glacier")
    repo = f"app-{SSN_A}"
    s["ecr"].add_response(
        "describe_repositories",
        {"repositories": [{"repositoryName": repo, "repositoryArn": "arn:aws:ecr:x:1:r/a"}]},
    )
    digest = "sha256:" + "c" * 64
    s["ecr"].add_response("describe_images", {"imageDetails": [{"imageDigest": digest}]})
    manifest = {
        "layers": [{"digest": digest, "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]
    }
    s["ecr"].add_response("batch_get_image", {"images": [{"imageManifest": json.dumps(manifest)}]})
    s["ecr"].add_response("get_download_url_for_layer", {"downloadUrl": "https://l.example/x"})
    blob = layer({f"app/{CARDS['visa']}.json": json.dumps({"pan": CARDS["amex"]}).encode()})
    env.clients.services["layer-fetch"] = lambda url, n: io.BytesIO(blob)
    graph = f"g-{SSN_B}"
    s["neptune-graph"].add_response(
        "list_graphs",
        {
            "graphs": [
                {
                    "id": "g-1",
                    "name": graph,
                    "arn": "arn:aws:neptune-graph:x:1:graph/g-1",
                    "status": "AVAILABLE",
                }
            ]
        },
    )
    s["neptune-graph"].add_response(
        "get_export_task",
        {
            "graphId": "g-1",
            "roleArn": "arn:aws:iam::1:role/r",
            "taskId": "t-1",
            "status": "SUCCEEDED",
            "format": "CSV",
            "destination": "s3://b/",
            "kmsKeyIdentifier": "k",
        },
    )
    env.clients.s3.put_object(
        Bucket=RESULTS,
        Key="exports/neptune-graph/t-1/Nodes/n.csv",
        Body=f"~id,c_{CARDS['jcb']}:String\n1,{CARDS['discover']}\n".encode(),
    )
    archive = f"arch-{CARDS['mir']}"
    s["events"].add_response("list_archives", {"Archives": [{"ArchiveName": archive}]})
    s["events"].add_response(
        "describe_archive",
        {
            "ArchiveArn": "arn:aws:events:x:1:archive/a",
            "ArchiveName": archive,
            "EventSourceArn": "arn:aws:events:x:1:event-bus/b",
            "State": "ENABLED",
        },
    )
    s["events"].add_response("describe_replay", {"State": "COMPLETED"})
    event = {"replay-name": "sds-r", "detail": {"ssn": dashed(SSN_A), "card": CARDS["mastercard"]}}
    s["sqs"].add_response(
        "receive_message",
        {"Messages": [{"MessageId": "1", "ReceiptHandle": "h", "Body": json.dumps(event)}]},
    )
    s["sqs"].add_response("delete_message", {})
    s["sqs"].add_response("receive_message", {"Messages": []})
    s["events"].add_response("remove_targets", {"FailedEntryCount": 0})
    s["events"].add_response("delete_rule", {})
    s["glacier"].add_response(
        "list_vaults",
        {"VaultList": [{"VaultName": f"v-{SSN_A}", "NumberOfArchives": 1}]},
        {"accountId": ANY},
    )
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    cfg = config(
        s3_targets=[],
        discover=frozenset({"ecr", "neptune_analytics", "eventbridge_archive", "glacier"}),
        ecr_read=True,
        neptune_analytics_export_role_arn="arn:aws:iam::123456789012:role/r",
        neptune_analytics_export_kms_key_arn="arn:aws:kms:us-west-2:123456789012:key/k",
        eventbridge_replay=True,
        eventbridge_replay_queue_url="https://sqs.us-west-2.amazonaws.com/123456789012/q",
        eventbridge_replay_queue_arn="arn:aws:sqs:us-west-2:123456789012:q",
        event_bus_arn="arn:aws:events:x:1:b/c",
    )
    # The graph's export and the archive's replay as a previous run left them: finished.
    import sensitive_data_scanner.sources.archives as archives_mod
    import sensitive_data_scanner.sources.ml as ml_mod

    real_graph, real_replay = (
        ml_mod.NeptuneGraphExportSource.run,
        archives_mod.EventBridgeReplaySource.run,
    )

    def graph_run(self: Any, cursor: dict[str, Any], *a: Any) -> Any:
        return real_graph(self, {"task": "t-1", "phase": "exporting", "passId": "p"}, *a)

    def replay_run(self: Any, cursor: dict[str, Any], *a: Any) -> Any:
        return real_replay(self, {"replay": "sds-r", "phase": "replaying", "passId": "p"}, *a)

    monkeypatch.setattr(ml_mod.NeptuneGraphExportSource, "run", graph_run)
    monkeypatch.setattr(archives_mod.EventBridgeReplaySource, "run", replay_run)
    doc = env.run(cfg)
    assert doc is not None
    services = {f["resource"]["service"] for f in doc["findings"]}
    assert services == {"ecr", "neptune_analytics", "eventbridge"}
    for name_, blob_ in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob_) == [], name_


# A made-up tenant id holding a bare nine-digit run, keyed the way Stugum keys its
# tables (#24). The run passes the SSN structure rules, so it is masked however
# masking is tuned; the finding keeps its link because the link names the table only.
TENANT = "T#t_314159265"


def test_a_masked_key_keeps_a_link_that_holds_no_value(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda

    item = load_item("stugum-positive")
    item["pk"] = {"S": TENANT}
    item["sk"] = {"S": f"CALL#{CARDS['mastercard']}"}
    ddb = Ddb()
    ddb.describe()
    ddb.query(page([item]))
    env.clients.dynamodb = ddb.client
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            dynamodb_targets=[target(partition=TENANT)],
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    assert doc["findings"]
    for f in doc["findings"]:
        assert f["resource"]["key"]["pk"] == "T#t_#########"
        assert f["resource"]["keyMasked"] is True
        assert f["link"] == (
            "https://us-west-2.console.aws.amazon.com/dynamodbv2/home?region=us-west-2"
            "#item-explorer?table=example-call-tests"
        )
    for name, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name
        assert "314159265" not in blob, name
        assert CARDS["mastercard"] not in blob, name


def test_a_link_built_from_a_masked_name_is_dropped() -> None:
    from sensitive_data_core.findings import link_for
    from sensitive_data_scanner.resources import (
        console_link,
        dynamodb_link,
        dynamodb_resource,
        s3_link,
        s3_resource,
    )

    table = f"orders-{SSN_A}"
    res = dynamodb_resource(table, {"pk": "a"}, "h", "x")
    assert link_for(res, dynamodb_link("us-west-2", table)) is None
    # The object's key is in its link: a masked key drops it.
    key = f"receipts/{SSN_B}.txt"
    assert link_for(s3_resource("b", key, None), s3_link("us-west-2", "b", key, None)) is None
    # A masked column is not in the object's link: it stays.
    res = s3_resource("b", "t.parquet", None, column=f"c_{SSN_B}")
    assert res["keyMasked"] is True
    assert link_for(res, s3_link("us-west-2", "b", "t.parquet", None)) is not None
    # A link that does not say what it was built from is dropped when anything is masked.
    assert link_for({"keyMasked": True}, console_link("us-west-2", "x")) is None
    assert (
        link_for({}, console_link("us-west-2", "x")) == "https://us-west-2.console.aws.amazon.com/x"
    )
    assert type(link_for({}, dynamodb_link("us-west-2", "t"))) is str


def test_no_value_leaves_parameters_or_secrets(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """Parameters and secrets named with values and holding values: counts only, and the
    secret's value (the credential beside the card) never appears."""
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from test_config_stores import stubs

    s = stubs(env, "ssm", "secretsmanager")
    p1, p2 = f"/cust/{SSN_A}/card", f"/cust/{CARDS['visa']}"
    s["ssm"].add_response(
        "describe_parameters",
        {"Parameters": [{"Name": p1, "Type": "SecureString"}, {"Name": p2, "Type": "String"}]},
    )
    s["ssm"].add_response(
        "get_parameters",
        {
            "Parameters": [
                {"Name": p1, "Type": "SecureString", "Value": f"card {CARDS['amex']}"},
                {"Name": p2, "Type": "String", "Value": json.dumps({"ssn": dashed(SSN_B)})},
            ]
        },
    )
    secret = f"cust-{SSN_B}"
    s["secretsmanager"].add_response("list_secrets", {"SecretList": [{"Name": secret}]})
    # A made-up credential beside the values, built here so no literal looks like one.
    marker = "-".join(["made", "up", "marker", str(len(CARDS) * 7)])
    value = json.dumps({"card": CARDS["jcb"], "pw": marker, "ssn": SSN_A})
    s["secretsmanager"].add_response("get_secret_value", {"Name": secret, "SecretString": value})
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"ssm", "secretsmanager"}),
            secrets_read=True,
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    assert {f["resource"]["service"] for f in doc["findings"]} == {"ssm", "secretsmanager"}
    for name_, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name_
        assert marker not in blob, name_


def test_no_value_leaves_time_series_keyspaces_or_caches(
    env: Env, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """Timestream and Keyspaces tables and columns named with values, holding values; a cache
    named with one; an exported RDB snapshot holding one."""
    import sensitive_data_scanner.handler  # noqa: F401 - sets library log levels as in Lambda
    from sensitive_data_core.scan.sql import sample_sql
    from sensitive_data_scanner.sources.other_stores import CQL, KeyspacesSource
    from test_other_stores import KS, FakeSession, stubs

    s = stubs(env, "timestream-write", "timestream-query", "timestream-influxdb", "keyspaces")
    s["timestream-write"].add_response("list_databases", {"Databases": [{"DatabaseName": "iot"}]})
    table = f"t_{SSN_A}"
    s["timestream-write"].add_response(
        "list_tables", {"Tables": [{"TableName": table, "TableStatus": "ACTIVE"}]}
    )
    s["timestream-influxdb"].add_response("list_db_instances", {"items": []})
    s["timestream-query"].add_response(
        "query",
        {
            "QueryId": "q",
            "ColumnInfo": [{"Name": f"c_{CARDS['visa']}", "Type": {"ScalarType": "VARCHAR"}}],
            "Rows": [{"Data": [{"ScalarValue": f"card {CARDS['jcb']}"}]}],
        },
    )
    s["keyspaces"].add_response(
        "list_keyspaces",
        {
            "keyspaces": [
                {
                    "keyspaceName": f"ks_{SSN_B}",
                    "resourceArn": f"{KS}/ks/",
                    "replicationStrategy": "SINGLE_REGION",
                }
            ]
        },
    )
    s["keyspaces"].add_response(
        "list_tables",
        {
            "tables": [
                {
                    "keyspaceName": f"ks_{SSN_B}",
                    "tableName": f"u_{CARDS['amex']}",
                    "resourceArn": f"{KS}/ks/table/u",
                }
            ]
        },
    )
    rows = [{f"n_{SSN_A}": dashed(SSN_B), "pan": CARDS["discover"]}]
    cql = sample_sql(CQL, f"ks_{SSN_B}", f"u_{CARDS['amex']}", 1000)
    session = FakeSession({cql: rows})
    env.clients.services["keyspaces-cql"] = lambda region: session
    body = b"REDIS0011" + f"\x10k:{CARDS['mastercard']}\x00ssn:{SSN_A}".encode()
    env.put(f"exports/cache-{SSN_B}.rdb", body)
    sent = _bus(env)
    capsys.readouterr()
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    doc = env.run(
        config(
            discover=frozenset({"timestream", "keyspaces"}),
            event_bus_arn="arn:aws:events:x:1:b/c",
        )
    )
    assert doc is not None
    KeyspacesSource._sessions.clear()
    services = {f["resource"].get("service", f["resource"]["type"]) for f in doc["findings"]}
    assert services == {"timestream", "keyspaces", "s3_object"}
    for name_, blob in _outputs(env, sent, capsys, caplog).items():
        assert leaks(blob) == [], name_


def test_ddb_candidates_hold_the_fixture_values() -> None:
    assert {"010180", "123456789", "5555666677778888", SSN_B, CARDS["mastercard"]} <= CANDIDATES


def test_a_value_in_an_object_key_is_masked(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.put(f"receipts/{CARDS['visa']}.txt", f"card {CARDS['visa']}")
    doc = env.run(config())
    assert doc is not None
    f = doc["findings"][0]
    assert f["resource"]["key"] == "receipts/################.txt"
    assert f["resource"]["keyMasked"] is True
    assert f["link"] is None
    assert leaks(json.dumps(doc) + "".join(capsys.readouterr())) == []


def test_exceptions_quote_nothing(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.put("stored/a.txt", f"card {CARDS['visa']}")

    class Boom(Detector):
        def analyze_text(self, text: str, context: list[str] | None = None) -> Any:
            raise ValueError(f"cannot read {text}")

    env.detector = Boom.__new__(Boom)
    doc = env.run(config())
    assert doc is not None
    assert doc["coverage"][0]["unreadable"] == 1
    assert doc["coverage"][0]["error"] == "ValueError"
    assert leaks(json.dumps(doc) + "".join(capsys.readouterr())) == []

    def refuse(**kwargs: Any) -> Any:
        raise RuntimeError(f"denied writing {CARDS['visa']}")

    env.detector = __import__("aws_fixtures").shared_detector()
    env.clients.s3.put_object = refuse  # type: ignore[method-assign]
    with pytest.raises(ScanError) as info:
        env.run(config(results_prefix="elsewhere/"))
    assert leaks(str(info.value) + repr(info.value) + "".join(capsys.readouterr())) == []


def test_reprs_hold_no_values() -> None:
    detector = __import__("aws_fixtures").shared_detector()
    blobs = []
    for case in VECTORS:
        turns = turns_of(case)
        r = classify(SPEC, turns)
        blobs.append(repr(r.matches) + repr(r.excluded))
        a = detector.analyze_conversation(turns)
        blobs.append(repr(a) + repr(a.detections))
    for _, body in STORED:
        item = scan_item_text("x.txt", body, detector)
        blobs.append(repr(item) + repr(detector.analyze_text(body)))
    assert leaks("\n".join(blobs)) == []


def test_redact_digits_masks_numbers_and_keeps_dates_and_ids() -> None:
    assert redact_digits(f"receipts/{CARDS['visa']}.txt") == "receipts/################.txt"
    assert redact_digits(f"x/{printed(CARDS['visa'])}") == "x/#### #### #### ####"
    assert redact_digits(f"ssn-{dashed(SSN_A)}.csv") == "ssn-###-##-####.csv"
    # A nine-digit run is masked whatever follows it (a snapshot name, a suffix).
    assert redact_digits(f"rds:orders-{SSN_A}-2026-09-29-06-10") == (
        "rds:orders-#########-2026-09-29-06-10"
    )
    assert redact_digits(f"x/{SSN_A}-1.csv") == "x/#########-1.csv"
    for kept in [
        "connect/i/ChatTranscripts/2026/09/28/abc_20260928T15:00_UTC.json",
        "2026/09/28/[$LATEST]0123456789abcdef",
    ]:
        assert redact_digits(kept) == kept
    assert redact_digits("ts 1727500000000123") == "ts ################"


def test_log_event_masks_and_refuses_unknown_events(capsys: pytest.CaptureFixture[str]) -> None:
    safety.log_event("source.failed", source=f"bucket/{CARDS['visa']}", error="AccessDenied")
    out = capsys.readouterr().out
    assert CARDS["visa"] not in out
    assert "################" in out
    with pytest.raises(ValueError, match="unknown log event"):
        safety.log_event("anything.goes")


# ------------------------------------------------------------ source audit


def _modules() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text())) for pkg in PACKAGES for p in sorted(pkg.rglob("*.py"))]


def test_only_safety_writes_output() -> None:
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = ast.unparse(f)
                assert name != "print", f"{path.name}: print()"
                if path.name != "safety.py":
                    assert not name.startswith(("sys.stdout", "sys.stderr")), f"{path.name}: {name}"
                    assert not re.match(
                        r"(logging|logger|log)\.(debug|info|warning|error|exception|critical|log)$",
                        name,
                    ), f"{path.name}: {name}"
                    if name.endswith((".debug", ".info", ".warning", ".exception")):
                        raise AssertionError(f"{path.name}: {name}")


def test_every_log_event_uses_a_fixed_name_and_safe_fields() -> None:
    calls = 0
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "log_event":
                calls += 1
                first = node.args[0]
                assert isinstance(first, ast.Constant), f"{path.name}: event name not literal"
                assert first.value in safety.EVENTS, f"{path.name}: {first.value!r}"
                for kw in node.keywords:
                    value = ast.unparse(kw.value)
                    assert not isinstance(kw.value, ast.JoinedStr), f"{path.name}: f-string field"
                    assert not re.search(r"\b(str|repr|format)\(|\.args\b|\.message\b", value), (
                        f"{path.name}: {value}"
                    )
                    if kw.arg == "error":
                        assert re.fullmatch(r"error_name\(\w+\)|\w+(\.\w+)*|'[A-Za-z]+'", value), (
                            f"{path.name}: error={value}"
                        )
    assert calls >= 10


def test_raised_exceptions_carry_no_message_from_below() -> None:
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                for arg in node.exc.args:
                    ok = isinstance(arg, ast.Constant) or (
                        isinstance(arg, ast.Name) and arg.id in ("name",)
                    )
                    assert ok, f"{path.name}: raise {ast.unparse(node.exc)}"


# ------------------------------------------------------------ the databases runner


def test_no_value_leaves_the_databases_runner(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Values in cells, and in schema, table, column, collection and field names; a password
    and a host holding numbers too: none of them in findings, logs, files or reprs."""
    from db_fakes import (
        Collection,
        Db,
        Driver,
        MongoClient,
        MongoDb,
        MongoDriver,
        read_only_mongo_status,
    )
    from sensitive_data_db.config import read_settings
    from sensitive_data_db.runner import run
    from sensitive_data_db.sinks import sinks_for

    password = f"pw{SSN_B}x"
    host = f"db-{CARDS['jcb']}.internal"
    rows = [
        {
            f"card_{CARDS['visa']}": CARDS["discover"],
            f"ssn_{dashed(SSN_A)}": dashed(SSN_B),
            "note": f"call me, my card is {printed(CARDS['mastercard'])} and SSN {SSN_A}",
            "nested": json.dumps({"k": spaced(SSN_B)}),
        }
    ]
    db = Db(tables={(f"hr_{SSN_A}", f"staff_{CARDS['amex']}"): rows})
    db.on(
        r"FROM pg_roles r",
        [
            {
                "superuser": False,
                "createrole": False,
                "createdb": False,
                "database_create": False,
                "table_write": 0,
                "schema_create": 0,
            }
        ],
    )
    refused = Db(tables={("public", "t"): rows}).on(
        r"FROM pg_roles r",
        [
            {
                "superuser": True,
                "createrole": True,
                "createdb": False,
                "database_create": False,
                "table_write": 9,
                "schema_create": 0,
            }
        ],
    )
    mongo = MongoClient(
        {
            f"crm_{SSN_B}": MongoDb(
                {
                    f"people_{CARDS['visa']}": Collection(
                        [
                            {
                                f"card_{CARDS['mir']}": CARDS["unionpay"],
                                "profile": {f"ssn_{SSN_A}": dashed(SSN_A)},
                            }
                        ]
                    ),
                    "broken": Collection([], fail=PermissionError(f"denied {CARDS['visa']}")),
                }
            )
        },
        read_only_mongo_status(),
    )
    out_file = tmp_path / "findings.json"
    settings = read_settings(
        {
            "SCANNER_SITE": "dc-1",
            f"DATABASE_URL_HR_{SSN_A}": f"postgresql://ro:{password}@{host}:5432/app_{SSN_B}",
            "DATABASE_URL_RW": f"postgresql://admin:{password}@{host}/app",
            "DATABASE_URL_DOCS": f"mongodb://ro:{password}@{host}/",
            "DATABASE_URL_DOWN": f"oracle://ro:{password}@{host}:1521/ERP",
            "FINDINGS_FILE": str(out_file),
        }
    )

    class Down:
        def connect(self, **kwargs: Any) -> None:
            raise ConnectionError(f"could not reach {kwargs['host']} as {kwargs['password']}")

    pg_ro, pg_rw = Driver(db), Driver(refused)

    class Pg:
        def connect(self, url: str, **kwargs: Any) -> Any:
            return (pg_rw if "admin:" in url else pg_ro).connect(url, **kwargs)

    capsys.readouterr()
    doc, failed = run(
        settings,
        sinks_for(settings),
        drivers={"postgresql": Pg(), "mongodb": MongoDriver(mongo), "oracle": Down()},
    )
    out = capsys.readouterr().out
    assert failed == 0
    classes_found = {f["class"] for f in doc["findings"]}
    assert {"card", "us_ssn"} <= classes_found
    stores = {
        s["kind"] + ":" + s["reason"] if "reason" in s else s["kind"]
        for s in doc["discovery"]["stores"]
    }
    assert "postgresql:db_user_can_write" in stores and "oracle:error" in stores
    blobs = {
        "document": json.dumps(doc),
        "file": out_file.read_text(),
        "logs": out,
        "settings": repr(settings),
        "databases": repr(settings.databases),
    }
    for where, blob in blobs.items():
        assert leaks(blob) == [], where
        assert password not in blob, where
        assert host not in blob, where
        assert CARDS["jcb"] not in blob, where
    # The names that held values are masked, and say so.
    masked = [f["resource"] for f in doc["findings"] if f["resource"].get("keyMasked")]
    assert masked and all("#" in (r.get("table", "") + r.get("field", "")) for r in masked)
