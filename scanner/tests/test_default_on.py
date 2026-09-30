"""Group 7, read by default (#35): Step Functions history, Lambda environment variables,
X-Ray traces, CodeCommit files and S3 directory buckets.

Every service answers through botocore's Stubber (S3 for directory buckets too). Every
value is made up.
"""

from __future__ import annotations

import datetime as dt
import io
import json
from typing import Any

import boto3
from botocore.awsrequest import AWSResponse, HTTPHeaders
from botocore.response import StreamingBody
from botocore.stub import ANY, Stubber

from aws_fixtures import Env, config
from sensitive_data_core.findings import key_hash
from sensitive_data_scanner.config import read_config
from sensitive_data_scanner.sources.code import read_only_sessions
from synthetic import CARDS, SSN_A, SSN_B, dashed
from test_streams import stores, stubs, valid

T0 = dt.datetime(2026, 9, 29, 10, 0, tzinfo=dt.UTC)
ACCOUNT = "123456789012"
CMK = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
CMK_ARN = f"arn:aws:kms:us-west-2:{ACCOUNT}:key/{CMK}"
SM = f"arn:aws:states:us-west-2:{ACCOUNT}:stateMachine:orders"


def run(env: Env, *kinds: str, **kw: Any) -> dict[str, Any]:
    doc = env.run(config(s3_targets=[], discover=frozenset(kinds), **kw))
    assert doc is not None
    valid(doc)
    return doc


def by_class(doc: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    return {
        (f["resource"]["store"], f["resource"].get("field", ""), f["class"]): f
        for f in doc["findings"]
    }


# ------------------------------------------------------------------ Step Functions


def state_machines(sfn: Stubber) -> None:
    sfn.add_response(
        "list_state_machines",
        {
            "stateMachines": [
                {"stateMachineArn": SM, "name": "orders", "type": "STANDARD", "creationDate": T0},
                {
                    "stateMachineArn": f"{SM}-fast",
                    "name": "orders-fast",
                    "type": "EXPRESS",
                    "creationDate": T0,
                },
            ]
        },
    )
    sfn.add_response(
        "describe_state_machine",
        {
            "stateMachineArn": SM,
            "name": "orders",
            "definition": "{}",
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/r",
            "type": "STANDARD",
            "creationDate": T0,
            "encryptionConfiguration": {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": CMK_ARN},
        },
        {"stateMachineArn": SM},
    )


def execution(n: int) -> dict[str, Any]:
    return {
        "executionArn": f"arn:aws:states:us-west-2:{ACCOUNT}:execution:orders:run-{n}",
        "stateMachineArn": SM,
        "name": f"run-{n}",
        "status": "SUCCEEDED",
        "startDate": T0,
    }


def history(sfn: Stubber, n: int, events: list[dict[str, Any]]) -> None:
    sfn.add_response(
        "get_execution_history",
        {
            "events": [
                {"timestamp": T0, "type": "TaskStateEntered", "id": i + 1, **e}
                for i, e in enumerate(events)
            ]
        },
        {
            "executionArn": execution(n)["executionArn"],
            "maxResults": ANY,
            "includeExecutionData": True,
        },
    )


def test_step_functions_history_is_read_and_express_is_reported(env: Env) -> None:
    s = stubs(env, "stepfunctions")
    sfn = s["stepfunctions"]
    state_machines(sfn)
    sfn.add_response("list_executions", {"executions": [execution(2), execution(1)]})
    card = json.dumps({"payment": {"card": CARDS["visa"]}})
    history(
        sfn,
        2,
        [
            {"executionStartedEventDetails": {"input": card, "roleArn": "arn:aws:iam::1:role/r"}},
            {"stateExitedEventDetails": {"name": "Charge", "output": json.dumps({"ok": True})}},
        ],
    )
    history(
        sfn,
        1,
        [
            {
                "taskFailedEventDetails": {
                    "resourceType": "lambda",
                    "resource": "x",
                    "cause": (f"customer ssn {dashed(SSN_A)} rejected"),
                }
            },
        ],
    )
    doc = run(env, "stepfunctions")
    sfn.assert_no_pending_responses()
    found = by_class(doc)
    assert set(found) == {("orders", "input", "card"), ("orders", "cause", "us_ssn")}
    f = found[("orders", "input", "card")]
    assert f["resource"] == {
        "type": "store_field",
        "service": "stepfunctions",
        "store": "orders",
        "field": "input",
        "readBy": "execution_history",
    }
    assert f["offsets"] == []
    assert f["atRestEncryption"] in ("customer_managed_key", "unknown")
    assert f["atRestKeyHash"] == key_hash(CMK)
    st = stores(doc)
    assert st[("stepfunctions", "orders")]["status"] == "scanned"
    fast = st[("stepfunctions", "orders-fast")]
    assert (fast["status"], fast["reason"], fast["workflowType"]) == (
        "skipped",
        "unsupported",
        "express",
    )
    cov = next(c for c in doc["coverage"] if c["kind"] == "stepfunctions")
    assert (cov["listed"], cov["scanned"], cov["passComplete"]) == (2, 2, True)
    c = read_config({"RESULTS_BUCKET": "x"})
    assert (c.stepfunctions_executions, c.stepfunctions_events) == (20, 500)


def test_step_functions_resume_within_a_pass(env: Env) -> None:
    s = stubs(env, "stepfunctions")
    sfn = s["stepfunctions"]
    cfg = {"max_items_per_run": 1}
    state_machines(sfn)
    sfn.add_response("list_executions", {"executions": [execution(2), execution(1)]})
    history(sfn, 2, [{"executionStartedEventDetails": {"input": json.dumps({"n": "x"})}}])
    first = run(env, "stepfunctions", **cfg)
    assert stores(first)[("stepfunctions", "orders")]["backlog"] is True
    cursor = next(v for k, v in env.state()["cursors"].items() if k.startswith("stepfunctions:"))
    assert "run-2" not in json.dumps(cursor)  # executions read are kept as hashes only
    state_machines(sfn)
    sfn.add_response("list_executions", {"executions": [execution(2), execution(1)]})
    history(sfn, 1, [{"executionStartedEventDetails": {"input": json.dumps({"n": "y"})}}])
    second = run(env, "stepfunctions", **cfg)
    sfn.assert_no_pending_responses()
    cov = next(c for c in second["coverage"] if c["kind"] == "stepfunctions")
    assert (cov["eligible"], cov["scanned"], cov["passComplete"]) == (1, 1, True)


# ------------------------------------------------------------------ Lambda


def test_lambda_environment_values_are_counted_never_reported(env: Env) -> None:
    s = stubs(env, "lambda")
    lam = s["lambda"]
    lam.add_response(
        "list_functions",
        {
            "Functions": [
                {
                    "FunctionName": "checkout",
                    "FunctionArn": "arn:aws:lambda:us-west-2:1:function:c",
                },
                {
                    "FunctionName": "locked",
                    "FunctionArn": "arn:aws:lambda:us-west-2:1:function:l",
                    "KMSKeyArn": CMK_ARN,
                },
                {
                    "FunctionName": "sensitive-data-scanner",
                    "FunctionArn": "arn:aws:lambda:us-west-2:1:function:s",
                },
            ]
        },
    )
    lam.add_response(
        "get_function_configuration",
        {
            "FunctionName": "checkout",
            "Environment": {
                "Variables": {
                    "TEST_CARD": CARDS["amex"],
                    "OWNER_SSN": dashed(SSN_B),
                    "TABLE": "orders",
                }
            },
        },
        {"FunctionName": "checkout"},
    )
    lam.add_response(
        "get_function_configuration",
        {
            "FunctionName": "locked",
            "Environment": {
                "Error": {"ErrorCode": "KMSAccessDeniedException", "Message": "made up"}
            },
        },
        {"FunctionName": "locked"},
    )
    doc = run(env, "lambda", self_function="sensitive-data-scanner")
    lam.assert_no_pending_responses()
    found = by_class(doc)
    assert set(found) == {("checkout", "TEST_CARD", "card"), ("checkout", "OWNER_SSN", "us_ssn")}
    f = found[("checkout", "TEST_CARD", "card")]
    assert f["resource"]["readBy"] == "get_function_configuration"
    assert (f["count"], f["offsets"]) == (1, [])
    assert f["atRestEncryption"] == "service_managed"
    assert f["pciNote"]["requirement"] == "3.5.1.2"
    st = stores(doc)
    assert st[("lambda", "sensitive-data-scanner")]["reason"] == "self"
    locked = st[("lambda", "locked")]
    assert (locked["status"], locked["gaps"]) == ("scanned", {"kmsDenied": 1, "unreadable": 1})
    assert locked["atRestEncryption"] in ("customer_managed_key", "unknown")
    assert (
        read_config({"RESULTS_BUCKET": "x", "AWS_LAMBDA_FUNCTION_NAME": "f"}).self_function == "f"
    )


# ------------------------------------------------------------------ X-Ray


def segment(name: str, **parts: Any) -> dict[str, Any]:
    return {"Id": f"seg-{name}", "Document": json.dumps({"id": "a", "name": name, **parts})}


def test_xray_annotations_and_metadata_are_read_since_the_last_run(env: Env) -> None:
    s = stubs(env, "xray")
    x = s["xray"]
    x.add_response("get_encryption_config", {"EncryptionConfig": {"Type": "NONE"}})
    x.add_response(
        "get_trace_summaries",
        {"TraceSummaries": [{"Id": f"1-00000000-{i:024x}"} for i in range(6)]},
    )
    doc_parts = segment(
        "checkout-api",
        annotations={"customer_card": CARDS["mastercard"]},
        subsegments=[
            {"id": "b", "name": "ledger", "metadata": {"default": {"ssn": dashed(SSN_A)}}}
        ],
    )
    x.add_response(
        "batch_get_traces",
        {"Traces": [{"Id": "t1", "Segments": [doc_parts]}]},
        {"TraceIds": [f"1-00000000-{i:024x}" for i in range(5)]},
    )
    x.add_response(
        "batch_get_traces",
        {"Traces": [{"Id": "t2", "Segments": [segment("quiet")]}]},
        {"TraceIds": ["1-00000000-000000000000000000000005"]},
    )
    for _ in range(3):  # the day's other six-hour windows
        x.add_response("get_trace_summaries", {"TraceSummaries": []})
    doc = run(env, "xray", xray_lookback_hours=24)
    x.assert_no_pending_responses()
    found = by_class(doc)
    assert set(found) == {
        ("checkout-api", "annotations", "card"),
        ("ledger", "metadata", "us_ssn"),
    }
    assert found[("ledger", "metadata", "us_ssn")]["atRestEncryption"] == "service_managed"
    st = stores(doc)[("xray", "xray-traces")]
    assert st["status"] == "scanned"
    cov = next(c for c in doc["coverage"] if c["kind"] == "xray")
    assert (cov["listed"], cov["scanned"]) == (6, 2)
    mark = dt.datetime.fromisoformat(env.state()["cursors"]["xray:traces"]["watermark"])
    assert dt.datetime.now(dt.UTC) - mark < dt.timedelta(minutes=5)  # the next run starts here


# ------------------------------------------------------------------ CodeCommit


def repo(cc: Stubber, *, default_branch: str | None = "main") -> None:
    cc.add_response(
        "list_repositories",
        {"repositories": [{"repositoryName": "payments", "repositoryId": "r1"}]},
    )
    meta: dict[str, Any] = {
        "repositoryName": "payments",
        "Arn": f"arn:aws:codecommit:us-west-2:{ACCOUNT}:payments",
    }
    if default_branch:
        meta["defaultBranch"] = default_branch
    cc.add_response("get_repository", {"repositoryMetadata": meta}, {"repositoryName": "payments"})


def tree(cc: Stubber, commit: str) -> None:
    cc.add_response(
        "get_branch",
        {"branch": {"branchName": "main", "commitId": commit}},
        {"repositoryName": "payments", "branchName": "main"},
    )
    cc.add_response(
        "get_folder",
        {
            "commitId": commit,
            "folderPath": "/",
            "subFolders": [{"absolutePath": "fixtures", "relativePath": "fixtures", "treeId": "t"}],
            "files": [
                {"absolutePath": "README.md", "relativePath": "README.md", "blobId": "b1"},
                {"absolutePath": "logo.png", "relativePath": "logo.png", "blobId": "b2"},
            ],
        },
        {"repositoryName": "payments", "commitSpecifier": commit, "folderPath": "/"},
    )
    cc.add_response(
        "get_folder",
        {
            "commitId": commit,
            "folderPath": "fixtures",
            "files": [
                {"absolutePath": "fixtures/users.csv", "relativePath": "users.csv", "blobId": "b3"}
            ],
        },
        {"repositoryName": "payments", "commitSpecifier": commit, "folderPath": "fixtures"},
    )


def blob(cc: Stubber, commit: str, path: str, content: bytes) -> None:
    cc.add_response(
        "get_file",
        {
            "commitId": commit,
            "blobId": "b",
            "filePath": path,
            "fileMode": "NORMAL",
            "fileSize": len(content),
            "fileContent": content,
        },
        {"repositoryName": "payments", "commitSpecifier": commit, "filePath": path},
    )


def test_codecommit_samples_files_at_head_and_skips_binaries(env: Env) -> None:
    s = stubs(env, "codecommit")
    cc = s["codecommit"]
    repo(cc)
    tree(cc, "c1")
    files = {
        "README.md": b"Run the tests with the sample data.",
        "fixtures/users.csv": f"name,ssn,card\nA,{dashed(SSN_B)},{CARDS['discover']}\n".encode(),
    }
    # The sample's order is a hash of the path: stubs answer by what is asked.
    from sensitive_data_scanner.sources.s3 import sample_point

    for path in sorted(files, key=lambda p: (sample_point(p), p)):
        blob(cc, "c1", path, files[path])
    doc = run(env, "codecommit")
    cc.assert_no_pending_responses()
    found = by_class(doc)
    assert set(found) == {
        ("payments", "fixtures/users.csv", "us_ssn"),
        ("payments", "fixtures/users.csv", "card"),
    }
    assert found[("payments", "fixtures/users.csv", "card")]["resource"]["readBy"] == "get_file"
    cov = next(c for c in doc["coverage"] if c["kind"] == "codecommit")
    assert (cov["listed"], cov["eligible"], cov["scanned"], cov["skipped"]) == (
        3,
        2,
        2,
        {"image": 1},
    )
    # The same head again: nothing is read twice.
    repo(cc)
    cc.add_response(
        "get_branch",
        {"branch": {"branchName": "main", "commitId": "c1"}},
        {"repositoryName": "payments", "branchName": "main"},
    )
    again = run(env, "codecommit")
    cc.assert_no_pending_responses()
    assert {f["id"] for f in again["findings"]} == {f["id"] for f in doc["findings"]}


def test_an_empty_repository_is_reported(env: Env) -> None:
    s = stubs(env, "codecommit")
    repo(s["codecommit"], default_branch=None)
    doc = run(env, "codecommit")
    st = stores(doc)[("codecommit", "payments")]
    assert (st["status"], st["reason"], st["state"]) == ("skipped", "unsupported", "empty")


# ------------------------------------------------------------------ S3 directory buckets

EXPRESS = "lake--usw2-az1--x-s3"


def body(data: bytes) -> StreamingBody:
    return StreamingBody(io.BytesIO(data), len(data))


def test_directory_buckets_are_read_through_read_only_sessions(env: Env) -> None:
    s3: Any = boto3.client(
        "s3",
        region_name="us-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
    )
    stub = Stubber(s3)
    env.clients.services["s3"] = s3
    stub.add_response("list_directory_buckets", {"Buckets": [{"Name": EXPRESS}]})
    listed = [
        {"Key": "b/2.json", "Size": 40, "LastModified": T0},
        {"Key": "a/1.txt", "Size": 30, "LastModified": T0},
    ]
    stub.add_response(
        "list_objects_v2",
        {"Contents": listed, "IsTruncated": True, "NextContinuationToken": "tok-2"},
        {"Bucket": EXPRESS, "MaxKeys": 1000},
    )
    stub.add_response(
        "get_object",
        {
            "Body": body(json.dumps({"card": CARDS["jcb"]}).encode()),
            "ServerSideEncryption": "AES256",
        },
        {"Bucket": EXPRESS, "Key": "b/2.json"},
    )
    stub.activate()
    first = run(env, "s3_directory", max_items_per_run=1)
    stub.assert_no_pending_responses()
    cursor = next(v for k, v in env.state()["cursors"].items() if k.startswith("s3x:"))
    assert (cursor["token"], cursor["skip"], cursor["startAfter"]) == (None, 1, None)
    (f,) = first["findings"]
    assert f["resource"]["bucket"] == EXPRESS and f["atRestEncryption"] == "service_managed"
    assert "bucketType=directory" in f["link"]
    # The next run lists the same page again and starts after what it read.
    stub.add_response("list_directory_buckets", {"Buckets": [{"Name": EXPRESS}]})
    stub.add_response(
        "list_objects_v2",
        {"Contents": listed, "IsTruncated": True, "NextContinuationToken": "tok-2"},
        {"Bucket": EXPRESS, "MaxKeys": 1000},
    )
    stub.add_response(
        "get_object",
        {"Body": body(f"ssn {dashed(SSN_A)}".encode())},
        {"Bucket": EXPRESS, "Key": "a/1.txt"},
    )
    stub.add_response(
        "list_objects_v2",
        {"Contents": [], "IsTruncated": False},
        {"Bucket": EXPRESS, "MaxKeys": 1000, "ContinuationToken": "tok-2"},
    )
    second = run(env, "s3_directory")
    stub.assert_no_pending_responses()
    assert {g["class"] for g in second["findings"]} == {"card", "us_ssn"}
    st = stores(second)[("s3_directory", EXPRESS)]
    assert st["status"] == "scanned"
    cov = next(c for c in second["coverage"] if c["kind"] == "s3_directory")
    assert cov["passComplete"] is True


def test_every_express_session_is_read_only() -> None:
    """The CreateSession botocore sends before a directory bucket's GET or LIST asks for a
    read-only session (the `x-amz-create-session-mode` header), however it is called."""
    s3: Any = boto3.client(
        "s3",
        region_name="us-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
    )
    read_only_sessions(s3)
    read_only_sessions(s3)  # registering twice is one handler
    sent: list[dict[str, Any]] = []

    def capture(params: dict[str, Any], **_: Any) -> Any:
        sent.append(dict(params["headers"]))
        creds = {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c", "Expiration": T0}
        return (AWSResponse("https://x", 200, HTTPHeaders(), None), {"Credentials": creds})

    s3.meta.events.register("before-call.s3.CreateSession", capture)
    s3.create_session(Bucket=EXPRESS)
    s3.create_session(Bucket=EXPRESS, SessionMode="ReadWrite")  # overridden
    assert [h.get("x-amz-create-session-mode") for h in sent] == ["ReadOnly", "ReadOnly"]
