"""Streams and queues: Kinesis Data Streams, Firehose destinations, SQS dead-letter queues.

**Kinesis** (`DISCOVER` includes `kinesis`): `ListStreams`, then per stream
`ListShards` and, for each shard, `GetShardIterator` at `TRIM_HORIZON` and
at most a few `GetRecords` calls (`KINESIS_RECORDS_PER_SHARD` records). The
scanner is not a consumer: it keeps no lease, writes no checkpoint and
records no sequence number; each pass samples the oldest records the stream
still holds. Its reads share the shard's read limits (five calls and 2 MB a
second) with the stream's consumers, so it makes few calls per shard.

**Firehose** (`firehose`): `ListDeliveryStreams` and
`DescribeDeliveryStream`. A delivery stream's data lands in S3 (its
destination, or the backup bucket of a Redshift, OpenSearch, Splunk, HTTP or
Snowflake destination): each of those S3 locations is read by the S3 source,
so findings name the objects, and the bucket's own source leaves the prefix
to it. A Redshift or OpenSearch destination is read by its own adapter.

**SQS** (`sqs`): `ListQueues` and `GetQueueAttributes`. A queue some other
queue's redrive policy points at is a **dead-letter queue**; every other
queue is live traffic and is never read (`live_queue`). Reading DLQs is
opt-in (`SQS_DLQ_READ`): `ReceiveMessage` with `VisibilityTimeout=0`, so each
message is visible again at once, and never `DeleteMessage` or
`ChangeMessageVisibility`. A receive still raises the message's receive
count, so a DLQ with a redrive policy of its own is not read
(`redrive_would_change`): past its `maxReceiveCount` SQS would move the
message on. Receiving from a FIFO queue briefly holds its message group.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import hashlib
import json
import re
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import Any

from ..detect.analyzer import Detector
from ..discovery import Discovery, Store, decide, needs_tags, reason_for
from ..findings import Coverage, console_link, store_field_resource
from ..safety import error_name, is_kms_denial, log_event
from ..scan.item import looks_binary, scan_item_text
from .base import Budget, Context, FindingStore, SourceRun, class_findings
from .exports import drop_other_passes, merge
from .s3 import S3Source

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("kinesis", "firehose", "sqs")

GET_RECORDS_CALLS = 3  # per shard per pass: an empty first batch is common at TRIM_HORIZON
MAX_RECORD_BYTES = 1024 * 1024
# A prefix ends where Firehose's expressions begin (`!{timestamp:yyyy}`, `!{partitionKey...}`).
_EXPRESSION = re.compile(r"!?\{")


def _decode(data: bytes) -> str | None:
    """A record's or message's bytes as text: gunzipped when gzip (CloudWatch Logs
    subscriptions), None when binary."""
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)[:MAX_RECORD_BYTES]
        except (OSError, EOFError):
            return None
    if looks_binary(data[:4096]):
        return None
    return data[:MAX_RECORD_BYTES].decode("utf-8", errors="replace")


class _Sampled:
    """What the Kinesis and SQS sources share: one pass of reads merged into findings."""

    kind = ""

    def __init__(self, name: str, service: str, field: str, read_by: str, region: str) -> None:
        self.name = name
        self.region = region
        digest = hashlib.sha256(f"{service}|{name}".encode()).hexdigest()[:16]
        self.id = f"{service}:{digest}"
        self.target = name
        self.resource = store_field_resource(
            service=service, store=name, field=field, read_by=read_by
        )

    def _read(self, text: str, p: _Pass) -> None:
        item = scan_item_text("record.json", text, p.detector)
        cov = p.cov
        cov.scanned += 1
        cov.bytes_scanned += len(text)
        cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
        cov.test_values += item.test_values
        cov.suppressed += item.suppressed
        cov.redaction_markers += item.redaction_markers
        for f in class_findings(item.findings, self.resource, p.link, item.format, p.seen_at):
            merge(p.store, f"{self.id}\n{self.name}", f, p.pass_id)


@dataclass
class _Pass:
    """One source's pass: where its reads are counted and its findings go."""

    cov: Coverage
    detector: Detector
    store: FindingStore
    pass_id: str
    link: str
    seen_at: str


def _tags(raw: list[dict[str, Any]] | None) -> dict[str, str]:
    return {str(t.get("Key")): str(t.get("Value", "")) for t in raw or [] if t.get("Key")}


# ------------------------------------------------------------------ Kinesis


class KinesisAdapter:
    kind = "kinesis"

    def discover(self, ctx: Context, out: Discovery) -> None:
        kinesis = ctx.clients.client("kinesis")
        for page in kinesis.get_paginator("list_streams").paginate():
            for s in page.get("StreamSummaries", []):
                name = str(s["StreamName"])
                store = Store("kinesis", name)
                out.stores.append(store)
                state = str(s.get("StreamStatus") or "")
                if state not in ("ACTIVE", "UPDATING"):
                    store.skip("unsupported")
                    store.extra["state"] = state[:60]
                    continue
                tag_error: str | None = None
                if needs_tags(ctx.config, "kinesis"):
                    try:
                        r = kinesis.list_tags_for_stream(StreamName=name)
                        store.tags = _tags(r.get("Tags"))
                    except Exception as err:
                        tag_error = error_name(err)
                decide(store, ctx.config, tag_error)

    def source(self, ctx: Context, store: Store) -> KinesisSource:
        return KinesisSource(
            ctx.clients.client("kinesis"),
            name=store.name,
            region=ctx.region,
            records_per_shard=ctx.config.kinesis_records_per_shard,
            max_shards=ctx.config.kinesis_max_shards,
        )


class KinesisSource(_Sampled):
    """One stream: each shard sampled from TRIM_HORIZON; never checkpointed."""

    kind = "kinesis"

    def __init__(
        self,
        kinesis: Any,
        *,
        name: str,
        region: str,
        records_per_shard: int = 100,
        max_shards: int = 50,
    ) -> None:
        super().__init__(name, "kinesis", "records", "shard_sample", region)
        self.kinesis = kinesis
        self.records_per_shard = records_per_shard
        self.max_shards = max_shards

    def link(self) -> str:
        q = urllib.parse.quote(self.name, safe="")
        return console_link(self.region, f"kinesis/home?region={self.region}#/streams/details/{q}")

    def shards(self) -> list[str]:
        ids: list[str] = []
        args: dict[str, Any] = {"StreamName": self.name}
        while True:
            r = self.kinesis.list_shards(**args)
            ids.extend(str(s["ShardId"]) for s in r.get("Shards", []))
            token = r.get("NextToken")
            if not token or len(ids) >= self.max_shards:
                return sorted(ids)[: self.max_shards]
            args = {"NextToken": token}

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("kinesis", self.target)
        pass_id = str(cursor.get("passId") or secrets.token_hex(8))
        after: str | None = cursor.get("after")  # a shard id: which shard is next, never a position
        p = _Pass(cov, detector, store, pass_id, self.link(), now.isoformat())
        done = False
        try:
            shards = self.shards()
            cov.listed = len(shards)
            todo = [s for s in shards if after is None or s > after]
            cov.eligible = len(todo)
            done = True
            for shard in todo:
                if not budget.has(0):
                    done = False
                    break
                it = self.kinesis.get_shard_iterator(
                    StreamName=self.name, ShardId=shard, ShardIteratorType="TRIM_HORIZON"
                ).get("ShardIterator")
                read = 0
                for _ in range(GET_RECORDS_CALLS):
                    if not it or read >= self.records_per_shard:
                        break
                    r = self.kinesis.get_records(
                        ShardIterator=it, Limit=self.records_per_shard - read
                    )
                    for rec in r.get("Records", []):
                        read += 1
                        data = bytes(rec.get("Data") or b"")
                        budget.take(len(data))
                        text = _decode(data)
                        if text is None:
                            cov.skipped["binary"] = cov.skipped.get("binary", 0) + 1
                            continue
                        self._read(text, p)
                    if not r.get("MillisBehindLatest"):
                        break  # at the tip: the shard holds nothing more
                    it = r.get("NextShardIterator")
                cov.partial += int(read >= self.records_per_shard)
                after = shard
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if is_kms_denial(err):
                cov.kms_denied += 1
            done = False
            log_event("source.failed", source=self.target, error=cov.error)
        if done:
            cov.pass_complete = True
            gone = drop_other_passes(store, self.id, pass_id)
            if gone:
                log_event("finding.gone", source=self.target, count=gone)
            return SourceRun(cov, {}, None, {})
        if cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"passId": pass_id, "after": after}, None, {})


# ------------------------------------------------------------------ Firehose

DESTINATION = {
    "S3DestinationDescription": "S3",
    "ExtendedS3DestinationDescription": "S3",
    "RedshiftDestinationDescription": "Redshift",
    "ElasticsearchDestinationDescription": "OpenSearch",
    "AmazonopensearchserviceDestinationDescription": "OpenSearch",
    "AmazonOpenSearchServerlessDestinationDescription": "OpenSearch",
    "SplunkDestinationDescription": "Splunk",
    "HttpEndpointDestinationDescription": "HttpEndpoint",
    "SnowflakeDestinationDescription": "Snowflake",
    "IcebergDestinationDescription": "Iceberg",
}


def _prefix(p: Any) -> str:
    """The literal head of a Firehose prefix, before its first expression."""
    text = str(p or "")
    m = _EXPRESSION.search(text)
    return text[: m.start()] if m else text


def s3_locations(destination: dict[str, Any]) -> list[tuple[str, str]]:
    """Every (bucket, prefix) a destination writes to: its data, its errors, its backup."""
    found: set[tuple[str, str]] = set()

    def visit(v: Any) -> None:
        if isinstance(v, dict):
            arn = v.get("BucketARN")
            if isinstance(arn, str) and arn.startswith("arn:"):
                bucket = arn.rsplit(":", 1)[-1]
                found.add((bucket, _prefix(v.get("Prefix"))))
                if v.get("ErrorOutputPrefix"):
                    found.add((bucket, _prefix(v.get("ErrorOutputPrefix"))))
            for x in v.values():
                visit(x)
        elif isinstance(v, list):
            for x in v:
                visit(x)

    visit(destination)
    # A prefix inside another of the same bucket is read by the wider one.
    return sorted(
        (b, p)
        for b, p in found
        if not any(b == b2 and p != p2 and p.startswith(p2) for b2, p2 in found)
    )


class FirehoseAdapter:
    kind = "firehose"

    def discover(self, ctx: Context, out: Discovery) -> None:
        fh = ctx.clients.client("firehose")
        names: list[str] = []
        start: str | None = None
        while True:
            r = fh.list_delivery_streams(
                Limit=100, **({"ExclusiveStartDeliveryStreamName": start} if start else {})
            )
            batch = [str(n) for n in r.get("DeliveryStreamNames", [])]
            names.extend(batch)
            if not r.get("HasMoreDeliveryStreams") or not batch:
                break
            start = batch[-1]
        for name in names:
            store = Store("firehose", name)
            out.stores.append(store)
            try:
                d = fh.describe_delivery_stream(DeliveryStreamName=name)[
                    "DeliveryStreamDescription"
                ]
            except Exception as err:
                store.status = "error"
                store.error = error_name(err)
                store.reason = reason_for(store.error)
                continue
            kinds = sorted(
                {
                    DESTINATION[k]
                    for dest in d.get("Destinations", [])
                    for k in dest
                    if k in DESTINATION
                }
            )
            store.extra["destinations"] = kinds
            locations = sorted(
                {loc for dest in d.get("Destinations", []) for loc in s3_locations(dest)}
            )
            tag_error: str | None = None
            if needs_tags(ctx.config, "firehose"):
                try:
                    r = fh.list_tags_for_delivery_stream(DeliveryStreamName=name)
                    store.tags = _tags(r.get("Tags"))
                except Exception as err:
                    tag_error = error_name(err)
            decide(store, ctx.config, tag_error)
            if store.status != "pending":
                continue
            if not locations:
                store.skip("no_s3_destination")  # delivered elsewhere: read at the destination
                continue
            store.extra["s3Locations"] = [f"{b}/{p}" for b, p in locations]

    def source(self, ctx: Context, store: Store) -> list[S3Source]:
        c = ctx.config
        out = []
        for loc in store.extra.get("s3Locations") or []:
            bucket, _, prefix = str(loc).partition("/")
            out.append(
                S3Source(
                    ctx.clients.s3,
                    bucket=bucket,
                    prefix=prefix,
                    region=ctx.region,
                    sample_percent=store.sample_percent or c.sample_percent,
                    max_object_bytes=c.max_object_bytes,
                    max_inflated_bytes=c.max_inflated_bytes,
                    skew_seconds=c.s3_skew_seconds,
                    max_per_prefix=store.max_per_prefix
                    if store.max_per_prefix is not None
                    else c.s3_max_objects_per_prefix,
                    max_rows=c.columnar_max_rows,
                )
            )
        return out


# ------------------------------------------------------------------ SQS dead-letter queues


class SqsAdapter:
    kind = "sqs"

    def discover(self, ctx: Context, out: Discovery) -> None:
        sqs = ctx.clients.client("sqs")
        urls: list[str] = []
        for page in sqs.get_paginator("list_queues").paginate():
            urls.extend(str(u) for u in page.get("QueueUrls", []))
        attrs: dict[str, dict[str, Any]] = {}
        failed: dict[str, str] = {}
        for url in urls:
            try:
                attrs[url] = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"]).get(
                    "Attributes", {}
                )
            except Exception as err:
                failed[url] = error_name(err)
        dlqs: set[str] = set()
        for a in attrs.values():
            try:
                target = json.loads(a.get("RedrivePolicy") or "{}").get("deadLetterTargetArn")
            except ValueError:
                target = None
            if target:
                dlqs.add(str(target))
        for url in urls:
            name = url.rstrip("/").rsplit("/", 1)[-1]
            store = Store("sqs", name)
            out.stores.append(store)
            if url in failed:
                store.status = "error"
                store.error = failed[url]
                store.reason = reason_for(failed[url])
                continue
            a = attrs[url]
            messages = a.get("ApproximateNumberOfMessages")
            if messages is not None:
                store.extra["approximateMessages"] = int(messages)
            tag_error: str | None = None
            if needs_tags(ctx.config, "sqs"):
                try:
                    store.tags = {
                        str(k): str(v)
                        for k, v in (sqs.list_queue_tags(QueueUrl=url).get("Tags") or {}).items()
                    }
                except Exception as err:
                    tag_error = error_name(err)
            decide(store, ctx.config, tag_error)
            if store.status != "pending":
                continue
            if str(a.get("QueueArn")) not in dlqs:
                store.skip("live_queue")  # never read: a receive would reach live consumers
                continue
            store.extra["deadLetterQueue"] = True
            if not ctx.config.sqs_dlq_read:
                store.skip("read_not_configured")
                continue
            if a.get("RedrivePolicy"):
                store.skip("redrive_would_change")
                continue
            store.extra["queueUrl"] = url

    def source(self, ctx: Context, store: Store) -> SqsDlqSource | None:
        url = store.extra.get("queueUrl")
        if not url:
            return None
        return SqsDlqSource(
            ctx.clients.client("sqs"),
            name=store.name,
            url=str(url),
            region=ctx.region,
            max_messages=ctx.config.sqs_messages_per_queue,
        )


class SqsDlqSource(_Sampled):
    """One dead-letter queue: messages received and left in place (VisibilityTimeout=0)."""

    kind = "sqs"

    def __init__(
        self, sqs: Any, *, name: str, url: str, region: str, max_messages: int = 100
    ) -> None:
        super().__init__(name, "sqs", "messages", "receive", region)
        self.sqs = sqs
        self.url = url
        self.max_messages = max_messages

    def link(self) -> str:
        q = urllib.parse.quote(self.url, safe="")
        return console_link(self.region, f"sqs/v3/home?region={self.region}#/queues/{q}")

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("sqs", self.target)
        pass_id = secrets.token_hex(8)
        p = _Pass(cov, detector, store, pass_id, self.link(), now.isoformat())
        seen: set[str] = set()
        try:
            for _ in range(max(1, self.max_messages // 10) * 2):
                if len(seen) >= self.max_messages or not budget.has(0):
                    break
                r = self.sqs.receive_message(
                    QueueUrl=self.url,
                    MaxNumberOfMessages=10,
                    VisibilityTimeout=0,
                    WaitTimeSeconds=0,
                    MessageAttributeNames=["All"],
                )
                fresh = [m for m in r.get("Messages", []) if str(m.get("MessageId")) not in seen]
                if not fresh:
                    break  # empty, or only messages already read this pass
                for m in fresh:
                    seen.add(str(m.get("MessageId")))
                    cov.listed += 1
                    body = str(m.get("Body") or "")
                    budget.take(len(body))
                    self._read(body, p)
                    strings = {
                        k: v.get("StringValue")
                        for k, v in (m.get("MessageAttributes") or {}).items()
                        if v.get("StringValue")
                    }
                    if strings:
                        self._read(json.dumps(strings), p)
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if is_kms_denial(err):
                cov.kms_denied += 1
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, {}, None, {})
        cov.eligible = cov.listed
        cov.pass_complete = True
        gone = drop_other_passes(store, self.id, pass_id)
        if gone:
            log_event("finding.gone", source=self.target, count=gone)
        return SourceRun(cov, {}, None, {})
