"""Brokers, opt-in (#35): MSK sampled with IAM authentication and never committed, Amazon MQ
(ActiveMQ) browsed by a checked read-only user, RabbitMQ reported.

The AWS APIs answer through botocore's Stubber; the Kafka consumer and the STOMP connection
are fakes. Every value is made up.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from botocore.stub import Stubber
from kafka import TopicPartition

from aws_fixtures import Env, config
from sensitive_data_scanner.config import MqTarget, mq_brokers, read_config
from sensitive_data_scanner.sources.brokers import (
    GROUP_PREFIX,
    BrokerUnreachable,
    StompBrowser,
    authorization_grants,
)
from synthetic import CARDS, SSN_A, SSN_B, dashed
from test_streams import stores, stubs, valid

ACCOUNT = "123456789012"
CLUSTER = f"arn:aws:kafka:us-west-2:{ACCOUNT}:cluster/payments/abc-1"
CMK = f"arn:aws:kms:us-west-2:{ACCOUNT}:key/0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"


def run(env: Env, *kinds: str, **kw: Any) -> dict[str, Any]:
    doc = env.run(config(s3_targets=[], discover=frozenset(kinds), **kw))
    assert doc is not None
    valid(doc)
    return doc


# ------------------------------------------------------------------ MSK


class Record:
    def __init__(self, value: bytes | None) -> None:
        self.value = value


class FakeConsumer:
    """A Kafka consumer: topics, partitions, and records from the start of each partition."""

    def __init__(self, data: dict[str, dict[int, list[bytes | None]]]) -> None:
        self.data = data
        self.assigned: list[TopicPartition] = []
        self.polled = False
        self.closed: dict[str, Any] | None = None
        self.commits = 0

    def topics(self) -> set[str]:
        return {*self.data, "__consumer_offsets", "__amazon_msk_canary"}

    def partitions_for_topic(self, topic: str) -> set[int]:
        return set(self.data.get(topic, {}))

    def assign(self, tps: list[TopicPartition]) -> None:
        self.assigned = list(tps)
        self.polled = False

    def seek_to_beginning(self, *tps: TopicPartition) -> None:
        assert list(tps) == self.assigned

    def poll(self, timeout_ms: int, max_records: int) -> dict[TopicPartition, list[Record]]:
        if self.polled:
            return {}
        self.polled = True
        return {tp: [Record(v) for v in self.data[tp.topic][tp.partition]] for tp in self.assigned}

    def commit(self, *a: Any, **k: Any) -> None:  # pragma: no cover - must never be called
        self.commits += 1

    def close(self, **kwargs: Any) -> None:
        self.closed = kwargs


def clusters(k: Stubber, *, iam: bool = True, state: str = "ACTIVE") -> None:
    k.add_response(
        "list_clusters_v2",
        {
            "ClusterInfoList": [
                {
                    "ClusterName": "payments",
                    "ClusterArn": CLUSTER,
                    "ClusterType": "PROVISIONED",
                    "State": state,
                    "Tags": {"team": "pay"},
                    "Provisioned": {
                        "BrokerNodeGroupInfo": {
                            "ClientSubnets": ["s"],
                            "InstanceType": "kafka.m5.large",
                        },
                        "NumberOfBrokerNodes": 3,
                        "EncryptionInfo": {"EncryptionAtRest": {"DataVolumeKMSKeyId": CMK}},
                        "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": iam}}},
                    },
                },
                {
                    "ClusterName": "events",
                    "ClusterArn": f"arn:aws:kafka:us-west-2:{ACCOUNT}:cluster/events/def-2",
                    "ClusterType": "SERVERLESS",
                    "State": "CREATING",
                },
            ]
        },
    )


def test_msk_is_sampled_from_the_earliest_offset_and_never_committed(env: Env) -> None:
    s = stubs(env, "kafka")
    clusters(s["kafka"])
    s["kafka"].add_response(
        "get_bootstrap_brokers",
        {
            "BootstrapBrokerStringSaslIam": "b-1.payments.internal:9098",
            "BootstrapBrokerStringPublicSaslIam": "b-1-public.payments.example:9198",
        },
        {"ClusterArn": CLUSTER},
    )
    consumer = FakeConsumer(
        {
            "orders": {
                0: [json.dumps({"card": CARDS["visa"]}).encode(), b"\x00\x01binary\x00"],
                1: [f"ssn {dashed(SSN_A)}".encode(), None],
            },
            "clicks": {0: [b'{"page": "home"}']},
        }
    )
    made: list[tuple[str, str, str]] = []

    def factory(bootstrap: str, region: str, group: str) -> FakeConsumer:
        made.append((bootstrap, region, group))
        return consumer

    env.clients.services["kafka-consumer"] = factory
    doc = run(env, "msk", msk_read=True)
    s["kafka"].assert_no_pending_responses()
    (bootstrap, _, group) = made[0]
    assert bootstrap == "b-1-public.payments.example:9198"  # the public IAM endpoint first
    assert group.startswith(GROUP_PREFIX) and len(group) > len(GROUP_PREFIX) + 8
    assert consumer.commits == 0 and consumer.closed == {"autocommit": False}
    found = {(f["resource"]["table"], f["class"]): f for f in doc["findings"]}
    assert set(found) == {("orders", "card"), ("orders", "us_ssn")}
    f = found[("orders", "card")]
    assert f["resource"] == {
        "type": "store_field",
        "service": "msk",
        "store": "payments",
        "table": "orders",
        "field": "records",
        "readBy": "consumer_sample",
    }
    assert f["atRestEncryption"] in ("customer_managed_key", "unknown")
    cov = next(c for c in doc["coverage"] if c["kind"] == "msk")
    assert (cov["listed"], cov["scanned"], cov["skipped"], cov["passComplete"]) == (
        2,
        3,
        {"binary": 1},
        True,
    )
    st = stores(doc)
    assert st[("msk", "payments")]["status"] == "scanned"
    assert st[("msk", "events")]["reason"] == "unsupported"
    c = read_config({"RESULTS_BUCKET": "x"})
    assert (c.msk_read, c.msk_records_per_partition, c.msk_max_topics) == (False, 100, 50)


def test_msk_off_without_iam_and_out_of_reach(env: Env) -> None:
    s = stubs(env, "kafka")
    clusters(s["kafka"])
    assert stores(run(env, "msk"))[("msk", "payments")]["reason"] == "read_not_configured"
    clusters(s["kafka"], iam=False)
    doc = run(env, "msk", msk_read=True)
    assert stores(doc)[("msk", "payments")]["reason"] == "no_read_path"

    class NoBrokersAvailable(Exception):
        pass

    def unreachable(bootstrap: str, region: str, group: str) -> Any:
        raise NoBrokersAvailable

    env.clients.services["kafka-consumer"] = unreachable
    clusters(s["kafka"])
    s["kafka"].add_response(
        "get_bootstrap_brokers", {"BootstrapBrokerStringSaslIam": "b-1.payments.internal:9098"}
    )
    doc = run(env, "msk", msk_read=True)
    s["kafka"].assert_no_pending_responses()
    st = stores(doc)[("msk", "payments")]
    assert (st["status"], st["reason"]) == ("skipped", "vpc_only")


# ------------------------------------------------------------------ Amazon MQ

BROKER_ID = "b-1234abcd-56ef-78ab-90cd-ef1234567890"
SECRET = f"arn:aws:secretsmanager:us-west-2:{ACCOUNT}:secret:mq-ro-AbCdEf"
READ_ONLY_CONFIG = """<broker xmlns="http://activemq.apache.org/schema/core"><plugins>
<authorizationPlugin><map><authorizationMap><authorizationEntries>
<authorizationEntry queue=">" read="readers,admins" write="admins" admin="admins"/>
<authorizationEntry topic="ActiveMQ.Advisory.>" read="readers" write="readers" admin="readers"/>
</authorizationEntries></authorizationMap></map></authorizationPlugin></plugins></broker>"""


def brokers(mq: Stubber, *, engine: str = "ACTIVEMQ") -> dict[str, Any]:
    mq.add_response(
        "list_brokers",
        {
            "BrokerSummaries": [
                {
                    "BrokerName": "orders-mq",
                    "BrokerId": BROKER_ID,
                    "BrokerState": "RUNNING",
                    "DeploymentMode": "SINGLE_INSTANCE",
                    "EngineType": engine,
                    "HostInstanceType": "mq.m5.large",
                }
            ]
        },
    )
    described = {
        "BrokerId": BROKER_ID,
        "BrokerName": "orders-mq",
        "BrokerState": "RUNNING",
        "EngineType": engine,
        "EncryptionOptions": {"UseAwsOwnedKey": True},
        "BrokerInstances": [
            {"Endpoints": ["ssl://b-1.mq.example:61617", "stomp+ssl://b-1.mq.example:61614"]}
        ],
        "Configurations": {"Current": {"Id": "c-1", "Revision": 3}},
    }
    mq.add_response("describe_broker", described, {"BrokerId": BROKER_ID})
    return described


def mq_check(sm: Stubber, mq: Stubber, *, console: bool, xml: str, groups: list[str]) -> None:
    sm.add_response(
        "get_secret_value",
        {"SecretString": json.dumps({"username": "scanner", "password": "made-up"})},
        {"SecretId": SECRET},
    )
    mq.add_response(
        "describe_user",
        {"BrokerId": BROKER_ID, "Username": "scanner", "ConsoleAccess": console, "Groups": groups},
        {"BrokerId": BROKER_ID, "Username": "scanner"},
    )
    mq.add_response(
        "describe_configuration_revision",
        {
            "ConfigurationId": "c-1",
            "Data": base64.b64encode(xml.encode()).decode(),
        },
        {"ConfigurationId": "c-1", "ConfigurationRevision": "3"},
    )


class FakeBrowser:
    """A STOMP browse session: messages per queue, recorded calls."""

    made: list[tuple[list[str], str]] = []  # noqa: RUF012 - per test

    def __init__(self, endpoints: list[str], username: str, password: str) -> None:
        FakeBrowser.made.append((endpoints, username))
        self.closed = False

    def browse(self, queue: str, limit: int) -> list[bytes]:
        return {
            "orders.dlq": [json.dumps({"pan": CARDS["amex"]}).encode(), b"plain"],
            "audit": [f"ssn {dashed(SSN_B)}".encode()],
        }.get(queue, [])[:limit]

    def close(self) -> None:
        self.closed = True


TARGET = MqTarget("orders-mq", SECRET, ("orders.dlq", "audit"))


def test_activemq_queues_are_browsed_by_a_read_only_user(env: Env) -> None:
    s = stubs(env, "mq", "secretsmanager")
    described = brokers(s["mq"])
    s["mq"].add_response("describe_broker", described, {"BrokerId": BROKER_ID})
    mq_check(s["secretsmanager"], s["mq"], console=False, xml=READ_ONLY_CONFIG, groups=["readers"])
    FakeBrowser.made = []
    env.clients.services["stomp"] = FakeBrowser
    doc = run(env, "mq", mq_read=True, mq_brokers=[TARGET])
    s["mq"].assert_no_pending_responses()
    assert FakeBrowser.made == [(["stomp+ssl://b-1.mq.example:61614"], "scanner")]
    found = {(f["resource"]["table"], f["class"]): f for f in doc["findings"]}
    assert set(found) == {("orders.dlq", "card"), ("audit", "us_ssn")}
    assert found[("audit", "us_ssn")]["resource"]["readBy"] == "browse"
    assert found[("orders.dlq", "card")]["atRestEncryption"] == "service_managed"
    assert stores(doc)[("mq", "orders-mq")]["status"] == "scanned"


@pytest.mark.parametrize(
    ("console", "xml", "groups", "grants"),
    [
        (True, READ_ONLY_CONFIG, ["readers"], ["console_access"]),
        (False, "<broker/>", ["readers"], ["no_authorization_map"]),
        (False, READ_ONLY_CONFIG, ["admins"], ["queue_admin", "queue_write"]),
    ],
)
def test_an_mq_user_that_can_write_is_refused_before_any_read(
    env: Env, console: bool, xml: str, groups: list[str], grants: list[str]
) -> None:
    s = stubs(env, "mq", "secretsmanager")
    described = brokers(s["mq"])
    s["mq"].add_response("describe_broker", described, {"BrokerId": BROKER_ID})
    mq_check(s["secretsmanager"], s["mq"], console=console, xml=xml, groups=groups)
    FakeBrowser.made = []
    env.clients.services["stomp"] = FakeBrowser
    doc = run(env, "mq", mq_read=True, mq_brokers=[TARGET])
    assert FakeBrowser.made == []  # never connected
    st = stores(doc)[("mq", "orders-mq")]
    assert (st["status"], st["reason"], st["writeGrants"]) == ("skipped", "user_can_write", grants)
    assert doc["findings"] == []


def test_rabbitmq_unconfigured_and_unreachable_brokers_are_reported(env: Env) -> None:
    s = stubs(env, "mq", "secretsmanager")
    brokers(s["mq"], engine="RABBITMQ")
    doc = run(env, "mq", mq_read=True, mq_brokers=[TARGET])
    assert stores(doc)[("mq", "orders-mq")]["reason"] == "no_read_path"
    brokers(s["mq"])
    assert stores(run(env, "mq"))[("mq", "orders-mq")]["reason"] == "read_not_configured"

    def unreachable(endpoints: list[str], username: str, password: str) -> Any:
        raise BrokerUnreachable

    described = brokers(s["mq"])
    s["mq"].add_response("describe_broker", described, {"BrokerId": BROKER_ID})
    mq_check(s["secretsmanager"], s["mq"], console=False, xml=READ_ONLY_CONFIG, groups=["readers"])
    env.clients.services["stomp"] = unreachable
    doc = run(env, "mq", mq_read=True, mq_brokers=[TARGET])
    assert stores(doc)[("mq", "orders-mq")]["reason"] == "vpc_only"


def test_mq_brokers_setting() -> None:
    raw = json.dumps([{"broker": "b", "secretArn": SECRET, "queues": ["a.b", "c"]}])
    assert mq_brokers(raw) == [MqTarget("b", SECRET, ("a.b", "c"))]
    for bad in ('{"broker": "b"}', '[{"broker": "b", "secretArn": "x"}]', '[{"x": 1}]'):
        with pytest.raises(ValueError, match="MQ_BROKERS"):
            mq_brokers(bad)


def test_authorization_grants() -> None:
    assert authorization_grants(READ_ONLY_CONFIG, {"readers"}) == []
    assert authorization_grants(READ_ONLY_CONFIG, {"admins"}) == ["queue_admin", "queue_write"]
    star = READ_ONLY_CONFIG.replace('write="admins"', 'write="*"')
    assert authorization_grants(star, {"readers"}) == ["queue_write"]
    assert authorization_grants("<broker", set()) == ["configuration_unreadable"]


# ------------------------------------------------------------------ STOMP browse


class FakeSocket:
    def __init__(self, replies: list[bytes]) -> None:
        self.replies = replies
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, n: int) -> bytes:
        return self.replies.pop(0) if self.replies else b""

    def close(self) -> None:
        return None


def frame(command: str, headers: dict[str, str], body: bytes = b"") -> bytes:
    head = "".join(f"{k}:{v}\n" for k, v in headers.items())
    return f"{command}\n{head}\n".encode() + body + b"\x00"


def test_stomp_browses_and_never_acknowledges(monkeypatch: pytest.MonkeyPatch) -> None:
    import secrets

    monkeypatch.setattr(secrets, "token_hex", lambda n: "s1")
    body = json.dumps({"card": CARDS["visa"]}).encode()
    sock = FakeSocket(
        [
            frame("CONNECTED", {"version": "1.2"}) + b"\n",
            frame("MESSAGE", {"subscription": "s1", "content-length": str(len(body))}, body)
            + frame("MESSAGE", {"subscription": "s1"}, b"second\x01"),
            frame("MESSAGE", {"subscription": "s1", "browser": "end"}),
        ]
    )
    opened: list[tuple[str, int]] = []

    def connect(host: str, port: int, timeout: float) -> FakeSocket:
        opened.append((host, port))
        if host == "down.example":
            raise TimeoutError
        return sock

    browser = StompBrowser(
        ["stomp+ssl://down.example:61614", "stomp+ssl://b-2.mq.example:61614"],
        "scanner",
        "made-up",
        connect=connect,
    )
    got = browser.browse("orders.dlq", 10)
    browser.close()
    assert opened == [("down.example", 61614), ("b-2.mq.example", 61614)]
    assert got == [body, b"second\x01"]
    sent = b"".join(sock.sent).decode("utf-8", "replace")
    assert "browser:true" in sent and "destination:/queue/orders.dlq" in sent
    assert "\nACK\n" not in sent and not sent.startswith("ACK") and "UNSUBSCRIBE" in sent
    with pytest.raises(BrokerUnreachable):
        StompBrowser(["stomp+ssl://down.example:61614"], "u", "p", connect=connect)
    refused = FakeSocket([frame("CONNECTED", {}), frame("ERROR", {"message": "denied"})])
    b2 = StompBrowser(["stomp+ssl://x:1"], "u", "p", connect=lambda h, p, t: refused)
    with pytest.raises(PermissionError):
        b2.browse("q", 5)
