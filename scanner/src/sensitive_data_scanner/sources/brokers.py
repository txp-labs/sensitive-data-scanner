"""Message brokers: Amazon MSK (Kafka) and Amazon MQ (ActiveMQ), both opt-in (#35).

**MSK** (`DISCOVER` includes `msk`; reading needs `MSK_READ`): `ListClustersV2`,
provisioned and Serverless. A cluster is read with IAM authentication
(`AWS_MSK_IAM`, the scanner's own role; no password), by `GetBootstrapBrokers`
(the public IAM endpoint when there is one) and a Kafka consumer that is never
a member of anything: a throwaway group id (`sensitive-data-scanner-<random>`,
the only groups the role may describe), partitions assigned by hand, each read
from its earliest offset, auto-commit off and no commit ever made (the role
denies `AlterGroup`, so none could be). Each topic's partitions are sampled
(`MSK_RECORDS_PER_PARTITION` records, `MSK_MAX_TOPICS` topics); internal topics
(`__*`) are left out. A cluster whose brokers the scanner cannot reach (the
Lambda is not in its VPC) is `vpc_only`, and one without IAM authentication is
`no_read_path`.

**Amazon MQ** (`mq`; reading needs `MQ_READ` and a broker entry in `MQ_BROKERS`):
`ListBrokers`, `DescribeBroker`. RabbitMQ has no read that leaves a queue as it
was (a get requeues and marks the message redelivered), so it is reported
`no_read_path`. An ActiveMQ broker's named queues are **browsed**, never
consumed: STOMP over TLS with `browser:true`, which ActiveMQ answers with a
queue browser. The broker has no IAM for its data, so a read-only user's name
and password come from a Secrets Manager secret the entry names, and **the user
is checked first**, like the databases runner's: a user with web console access
(an administrator), a broker without an authorization map, or a user whose group
may write to or administer a queue is refused (`user_can_write`, with
`writeGrants`) and nothing is read. Unreachable brokers are `vpc_only`.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import secrets
import ssl
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Callable
from socket import create_connection
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, class_findings
from sensitive_data_core.coverage import Discovery, Store, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.item import scan_item_text

from ..config import MqTarget
from ..discovery import decide
from ..resources import console_link
from .base import Context
from .encryption import classifier
from .exports import drop_other_passes, merge
from .streams import _decode

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("kafka", "mq", "secretsmanager")

GROUP_PREFIX = "sensitive-data-scanner-"
UNREACHABLE = frozenset(
    {
        "NoBrokersAvailable",
        "KafkaTimeoutError",
        "KafkaConnectionError",
        "timeout",
        "TimeoutError",
        "ConnectionRefusedError",
        "gaierror",
        "OSError",
        "BrokerUnreachable",
    }
)
MAX_WRITE_GRANTS = 30


class BrokerUnreachable(Exception):
    """None of a broker's endpoints answered: it is reached only inside its VPC."""


class UserCanWrite(Exception):
    """The broker user given can change a queue (or administer the broker): refused. It
    carries the grants by name (`grants`), never a message."""

    grants: list[str] = []  # noqa: RUF012 - set per instance before it is raised


def _unreachable(err: BaseException) -> bool:
    return isinstance(err, OSError | BrokerUnreachable) or error_name(err) in UNREACHABLE


# ------------------------------------------------------------------ MSK


class MskAdapter:
    kind = "msk"

    def discover(self, ctx: Context, out: Discovery) -> None:
        kafka = ctx.clients.client("kafka")
        keys = classifier(ctx.clients)
        for page in kafka.get_paginator("list_clusters_v2").paginate():
            for c in page.get("ClusterInfoList", []):
                store = Store(self.kind, str(c["ClusterName"]))
                out.stores.append(store)
                serverless = str(c.get("ClusterType") or "") == "SERVERLESS"
                store.extra["deployment"] = "serverless" if serverless else "provisioned"
                prov = c.get("Provisioned") or {}
                at_rest = ((prov.get("EncryptionInfo") or {}).get("EncryptionAtRest")) or {}
                # MSK always encrypts its volumes: the cluster's KMS key, or AWS's.
                key = at_rest.get("DataVolumeKMSKeyId")
                store.facts = keys.facts(key=key, aws_owned=serverless or not key)
                store.tags = {str(k): str(v) for k, v in (c.get("Tags") or {}).items()}
                state = str(c.get("State") or "")
                if state != "ACTIVE":
                    store.skip("unsupported")
                    store.extra["state"] = state[:60]
                    continue
                decide(store, ctx.config)
                if store.status != "pending":
                    continue
                sasl = (prov.get("ClientAuthentication") or {}).get("Sasl") or {}
                if not serverless and not (sasl.get("Iam") or {}).get("Enabled"):
                    store.skip("no_read_path")  # no IAM authentication: no password is kept
                    continue
                if not ctx.config.msk_read:
                    store.skip("read_not_configured")
                    continue
                store.extra["arn"] = str(c["ClusterArn"])

    def source(self, ctx: Context, store: Store) -> MskSource | None:
        arn = store.extra.get("arn")
        if not arn:
            return None
        c = ctx.config
        return MskSource(
            ctx.clients.client("kafka"),
            ctx.clients.services.get("kafka-consumer") or kafka_consumer,
            name=store.name,
            arn=str(arn),
            region=ctx.region,
            records_per_partition=c.msk_records_per_partition,
            max_topics=c.msk_max_topics,
            max_partitions=c.msk_max_partitions,
        )


def kafka_consumer(bootstrap: str, region: str, group: str) -> Any:
    """A consumer that authenticates with the scanner's role and can never commit."""
    import os  # noqa: PLC0415

    from kafka import KafkaConsumer  # noqa: PLC0415 - only when MSK is read

    os.environ.setdefault("AWS_DEFAULT_REGION", region)  # AWS_MSK_IAM signs for this region
    return KafkaConsumer(
        bootstrap_servers=bootstrap.split(","),
        security_protocol="SASL_SSL",
        sasl_mechanism="AWS_MSK_IAM",
        group_id=group,
        enable_auto_commit=False,
        auto_offset_reset="earliest",
        client_id="sensitive-data-scanner",
        request_timeout_ms=30_000,
        api_version_auto_timeout_ms=10_000,
        consumer_timeout_ms=5_000,
        max_poll_records=500,
    )


class MskSource:
    """One cluster's topics, each partition sampled from its earliest offset; never committed."""

    kind = "msk"
    facts: dict[str, Any] | None = None

    def __init__(
        self,
        kafka: Any,
        consumer: Callable[[str, str, str], Any],
        *,
        name: str,
        arn: str,
        region: str,
        records_per_partition: int = 100,
        max_topics: int = 50,
        max_partitions: int = 50,
    ) -> None:
        self.kafka = kafka
        self.consumer = consumer
        self.name = name
        self.arn = arn
        self.region = region
        self.records_per_partition = records_per_partition
        self.max_topics = max_topics
        self.max_partitions = max_partitions
        self.id = f"msk:{hashlib.sha256(arn.encode()).hexdigest()[:16]}"
        self.target = name

    def link(self) -> str:
        q = urllib.parse.quote(self.arn, safe="")
        return console_link(self.region, f"msk/home?region={self.region}#/cluster/{q}/view")

    def _bootstrap(self) -> str | None:
        r = self.kafka.get_bootstrap_brokers(ClusterArn=self.arn)
        for k in ("BootstrapBrokerStringPublicSaslIam", "BootstrapBrokerStringSaslIam"):
            if r.get(k):
                return str(r[k])
        return None

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        pass_id = str(cursor.get("passId") or secrets.token_hex(8))
        after: str | None = cursor.get("after")  # a topic name: which topic is next, no offset
        seen_at, link = now.isoformat(), self.link()
        consumer: Any = None
        complete = True
        try:
            bootstrap = self._bootstrap()
            if bootstrap is None:
                return SourceRun(cov, {}, "no_read_path", {})
            consumer = self.consumer(bootstrap, self.region, GROUP_PREFIX + secrets.token_hex(8))
            topics = sorted(t for t in consumer.topics() if not str(t).startswith("__"))
            topics = topics[: self.max_topics]
            cov.listed = len(topics)
            todo = [t for t in topics if after is None or t > after]
            cov.eligible = len(todo)
            for topic in todo:
                if not budget.has(0):
                    complete = False
                    break
                self._topic(consumer, topic, cov, budget, detector, store, seen_at, link, pass_id)
                after = topic
        except Exception as err:  # recorded by name on the source
            if _unreachable(err):
                return SourceRun(cov, {}, "vpc_only", {})
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
            complete = False
        finally:
            if consumer is not None:
                try:
                    consumer.close(autocommit=False)
                except Exception:  # closing: nothing left to do
                    log_event("source.failed", source=self.target, error="CloseFailed")
        if complete:
            cov.pass_complete = True
            drop_other_passes(store, self.id, pass_id)
            return SourceRun(cov, {}, None, {})
        if cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"passId": pass_id, "after": after}, None, {})

    def _topic(  # noqa: PLR0917 - one topic's pass, called once
        self,
        consumer: Any,
        topic: str,
        cov: Coverage,
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        link: str,
        pass_id: str,
    ) -> None:
        from kafka import TopicPartition  # noqa: PLC0415 - only when MSK is read

        parts = sorted(consumer.partitions_for_topic(topic) or [])[: self.max_partitions]
        tps = [TopicPartition(topic, p) for p in parts]
        if not tps:
            return
        consumer.assign(tps)
        consumer.seek_to_beginning(*tps)
        read = dict.fromkeys(parts, 0)
        want = self.records_per_partition
        resource = store_field_resource(
            service="msk", store=self.name, table=topic, field="records", read_by="consumer_sample"
        )
        for _ in range(3 + len(parts)):  # a few polls; an empty one ends the topic
            if all(n >= want for n in read.values()) or not budget.has(0):
                break
            batch = consumer.poll(timeout_ms=2_000, max_records=500)
            if not batch:
                break
            for tp, records in batch.items():
                for rec in records:
                    if read.get(tp.partition, want) >= want:
                        continue
                    read[tp.partition] += 1
                    if rec.value is None:
                        continue  # a tombstone: a deleted key, no data
                    data = bytes(rec.value)
                    budget.take(len(data))
                    text = _decode(data)
                    if text is None:
                        cov.skipped["binary"] = cov.skipped.get("binary", 0) + 1
                        continue
                    item = scan_item_text("record.json", text, detector)
                    cov.scanned += 1
                    cov.bytes_scanned += len(data)
                    cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
                    cov.test_values += item.test_values
                    cov.suppressed += item.suppressed
                    cov.redaction_markers += item.redaction_markers
                    for f in class_findings(
                        item.findings, resource, link, item.format, seen_at, facts=self.facts
                    ):
                        merge(store, f"{self.id}\n{topic}", f, pass_id)
        cov.partial += sum(1 for n in read.values() if n >= want)


# ------------------------------------------------------------------ Amazon MQ


class MqAdapter:
    kind = "mq"

    def discover(self, ctx: Context, out: Discovery) -> None:
        mq = ctx.clients.client("mq")
        keys = classifier(ctx.clients)
        targets = {t.broker: t for t in ctx.config.mq_brokers}
        for page in mq.get_paginator("list_brokers").paginate():
            for b in page.get("BrokerSummaries", []):
                store = Store(self.kind, str(b.get("BrokerName")))
                out.stores.append(store)
                engine = str(b.get("EngineType") or "").lower()
                store.extra["engine"] = engine
                try:
                    d = mq.describe_broker(BrokerId=str(b["BrokerId"]))
                except Exception as err:
                    store.status, store.error = "error", error_name(err)
                    store.reason = reason_for(store.error)
                    continue
                enc = d.get("EncryptionOptions") or {}
                owned = enc.get("UseAwsOwnedKey", True)
                store.facts = keys.facts(key=enc.get("KmsKeyId"), aws_owned=bool(owned))
                store.tags = {str(k): str(v) for k, v in (d.get("Tags") or {}).items()}
                state = str(d.get("BrokerState") or b.get("BrokerState") or "")
                if state != "RUNNING":
                    store.skip("unsupported")
                    store.extra["state"] = state[:60]
                    continue
                decide(store, ctx.config)
                if store.status != "pending":
                    continue
                if engine != "activemq":
                    store.skip("no_read_path")  # RabbitMQ: no read leaves a queue as it was
                    continue
                target = targets.get(store.name)
                if not ctx.config.mq_read or target is None or not target.queues:
                    store.skip("read_not_configured")
                    continue
                store.extra["arn"] = str(b["BrokerId"])

    def source(self, ctx: Context, store: Store) -> MqSource | None:
        broker_id = store.extra.get("arn")
        target = next((t for t in ctx.config.mq_brokers if t.broker == store.name), None)
        if not broker_id or target is None:
            return None
        return MqSource(
            ctx.clients.client("mq"),
            ctx.clients.client("secretsmanager"),
            ctx.clients.services.get("stomp") or StompBrowser,
            broker_id=str(broker_id),
            target=target,
            region=ctx.region,
            max_messages=ctx.config.mq_messages_per_queue,
        )


def authorization_grants(xml: str, groups: set[str]) -> list[str]:
    """What an ActiveMQ configuration lets these groups do beyond reading queues: every
    `authorizationEntry` for queues whose `write` or `admin` names one of them. A broker
    with no authorization map lets every user do everything."""
    try:
        root = ET.fromstring(xml)  # noqa: S314 - the broker's own configuration, from its API
    except ET.ParseError:
        return ["configuration_unreadable"]
    entries = [e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "authorizationEntry"]
    if not entries:
        return ["no_authorization_map"]
    grants: set[str] = set()
    for e in entries:
        if "queue" not in e.attrib:
            continue  # topics, advisories included: no queue's messages change through them
        for right in ("write", "admin"):
            names = {g.strip() for g in e.attrib.get(right, "").split(",") if g.strip()}
            if names & groups or "*" in names:
                grants.add(f"queue_{right}")
    return sorted(grants)


class MqSource:
    """One ActiveMQ broker's named queues, browsed (never consumed) by a checked user."""

    kind = "mq"
    facts: dict[str, Any] | None = None

    def __init__(
        self,
        mq: Any,
        secrets_client: Any,
        browser: Callable[..., Any],
        *,
        broker_id: str,
        target: MqTarget,
        region: str,
        max_messages: int = 100,
    ) -> None:
        self.mq = mq
        self.secrets = secrets_client
        self.browser = browser
        self.broker_id = broker_id
        self.t = target
        self.region = region
        self.max_messages = max_messages
        self.id = f"mq:{hashlib.sha256(broker_id.encode()).hexdigest()[:16]}"
        self.target = target.broker

    def link(self) -> str:
        q = urllib.parse.quote(self.broker_id, safe="")
        return console_link(
            self.region, f"amazon-mq/home?region={self.region}#/brokers/details?id={q}"
        )

    def _user(self) -> tuple[str, str]:
        raw = self.secrets.get_secret_value(SecretId=self.t.secret_arn).get("SecretString") or "{}"
        doc = json.loads(raw)
        return str(doc.get("username") or ""), str(doc.get("password") or "")

    def _check(self, username: str, broker: dict[str, Any]) -> None:
        """Refuse a user that can write: an administrator, or a group that may write to or
        administer queues (or a broker with no authorization map at all)."""
        user = self.mq.describe_user(BrokerId=self.broker_id, Username=username)
        grants: list[str] = []
        if user.get("ConsoleAccess"):
            grants.append("console_access")
        current = (broker.get("Configurations") or {}).get("Current") or {}
        rev = self.mq.describe_configuration_revision(
            ConfigurationId=str(current.get("Id")),
            ConfigurationRevision=str(current.get("Revision")),
        )
        xml = base64.b64decode(str(rev.get("Data") or "")).decode("utf-8", "replace")
        grants += authorization_grants(xml, {str(g) for g in user.get("Groups") or []})
        if grants:
            refused = UserCanWrite()
            refused.grants = sorted(grants)[:MAX_WRITE_GRANTS]
            raise refused

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        pass_id = secrets.token_hex(8)
        seen_at, link = now.isoformat(), self.link()
        try:
            broker = self.mq.describe_broker(BrokerId=self.broker_id)
            username, password = self._user()
            self._check(username, broker)
            endpoints = [
                e
                for i in broker.get("BrokerInstances") or []
                for e in i.get("Endpoints") or []
                if str(e).startswith("stomp+ssl://")
            ]
            session = self.browser(endpoints, username, password)
        except UserCanWrite as refused:
            log_event("source.refused", source=self.target, kind=self.kind, reason="user_can_write")
            return SourceRun(cov, {}, "user_can_write", {"writeGrants": refused.grants})
        except Exception as err:  # recorded by name on the source
            if _unreachable(err):
                return SourceRun(cov, {}, "vpc_only", {})
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, {}, None, {})
        try:
            cov.listed = cov.eligible = len(self.t.queues)
            for queue in self.t.queues:
                if not budget.has(0):
                    cov.backlog = True
                    break
                resource = store_field_resource(
                    service="mq", store=self.target, table=queue, field="messages", read_by="browse"
                )
                n = 0
                for body in session.browse(queue, self.max_messages):
                    n += 1
                    budget.take(len(body))
                    text = _decode(body)
                    if text is None:
                        cov.skipped["binary"] = cov.skipped.get("binary", 0) + 1
                        continue
                    item = scan_item_text("message.json", text, detector)
                    cov.scanned += 1
                    cov.bytes_scanned += len(body)
                    cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
                    cov.test_values += item.test_values
                    cov.suppressed += item.suppressed
                    for f in class_findings(
                        item.findings, resource, link, item.format, seen_at, facts=self.facts
                    ):
                        merge(store, f"{self.id}\n{queue}", f, pass_id)
                cov.partial += int(n >= self.max_messages)
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, {}, None, {})
        finally:
            session.close()
        cov.pass_complete = not cov.backlog
        if cov.pass_complete:
            drop_other_passes(store, self.id, pass_id)
        return SourceRun(cov, {}, None, {})


# ------------------------------------------------------------------ STOMP, browse only


def _frame(command: str, headers: dict[str, str], body: bytes = b"") -> bytes:
    def esc(v: str) -> str:
        return v.replace("\\", "\\\\").replace("\n", "\\n").replace(":", "\\c")

    head = "".join(f"{esc(k)}:{esc(v)}\n" for k, v in headers.items())
    return f"{command}\n{head}\n".encode() + body + b"\x00"


class StompBrowser:
    """A STOMP 1.2 connection over TLS that only ever browses: `SUBSCRIBE` with
    `browser:true` (an ActiveMQ queue browser: messages are sent, never consumed or acked),
    read until `browser:end` or the cap, then `UNSUBSCRIBE`."""

    def __init__(
        self,
        endpoints: list[str],
        username: str,
        password: str,
        *,
        timeout: float = 10.0,
        connect: Callable[[str, int, float], Any] | None = None,
    ) -> None:
        self.timeout = timeout
        self.buf = b""
        self.sock: Any = None
        opener = connect or self._tls
        last: BaseException | None = None
        for e in endpoints:
            host, _, port = e.removeprefix("stomp+ssl://").rpartition(":")
            try:
                self.sock = opener(host, int(port or 61614), timeout)
                break
            except OSError as err:
                last = err
        if self.sock is None:
            raise BrokerUnreachable("unreachable") from last
        host = endpoints[0].removeprefix("stomp+ssl://").rpartition(":")[0]
        self.sock.sendall(
            _frame(
                "CONNECT",
                {
                    "accept-version": "1.2",
                    "host": host,
                    "login": username,
                    "passcode": password,
                    "heart-beat": "0,0",
                },
            )
        )
        command, _, _ = self._read()
        if command != "CONNECTED":
            raise ConnectionRefusedError("not connected")

    @staticmethod
    def _tls(host: str, port: int, timeout: float) -> Any:
        raw = create_connection((host, port), timeout=timeout)
        return ssl.create_default_context().wrap_socket(raw, server_hostname=host)

    def _read(self) -> tuple[str, dict[str, str], bytes]:
        while True:
            self.buf = self.buf.lstrip(b"\r\n")  # heart-beats
            head_end = self.buf.find(b"\n\n")
            if head_end >= 0:
                lines = self.buf[:head_end].decode("utf-8", "replace").split("\n")
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    k, _, v = line.partition(":")
                    headers.setdefault(k, v.replace("\\c", ":").replace("\\n", "\n"))
                start = head_end + 2
                if "content-length" in headers:
                    end = start + int(headers["content-length"])
                    if len(self.buf) > end:
                        body, self.buf = self.buf[start:end], self.buf[end + 1 :]
                        return lines[0], headers, body
                else:
                    end = self.buf.find(b"\x00", start)
                    if end >= 0:
                        body, self.buf = self.buf[start:end], self.buf[end + 1 :]
                        return lines[0], headers, body
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionResetError("closed")
            self.buf += chunk

    def browse(self, queue: str, limit: int) -> list[bytes]:
        sub = secrets.token_hex(4)
        self.sock.sendall(
            _frame(
                "SUBSCRIBE",
                {"id": sub, "destination": f"/queue/{queue}", "ack": "client", "browser": "true"},
            )
        )
        out: list[bytes] = []
        try:
            while len(out) < limit:
                command, headers, body = self._read()
                if command == "ERROR":
                    raise PermissionError("refused")
                if command != "MESSAGE" or headers.get("subscription") != sub:
                    continue
                if headers.get("browser") == "end":
                    break
                out.append(body)
        finally:
            self.sock.sendall(_frame("UNSUBSCRIBE", {"id": sub}))
        return out

    def close(self) -> None:
        try:
            self.sock.sendall(_frame("DISCONNECT", {}))
            self.sock.close()
        except OSError:
            return
