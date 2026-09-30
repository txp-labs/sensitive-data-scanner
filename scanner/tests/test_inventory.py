"""S3 Inventory for large buckets (#67 part 4): a bucket's objects from its own inventory
report instead of a listing, a recommendation when it has none, and nothing ever
configured. Every value is made up."""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
import json
import urllib.parse
from typing import Any

from aws_fixtures import DATA, Env, config
from sensitive_data_scanner.sources import inventory
from synthetic import CARDS, SSN_A, dashed, printed

DEST = "example-inventory"
CONFIG_ID = "daily-all"


class WithInventory:
    """The moto client, with the inventory configurations a test gives (moto's own are not
    faithful), and every call on the data bucket counted."""

    def __init__(self, inner: Any, configs: list[dict[str, Any]]) -> None:
        self._inner = inner
        self.configs = configs
        self.calls: list[str] = []

    def list_bucket_inventory_configurations(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("list_bucket_inventory_configurations")
        return {"InventoryConfigurationList": self.configs, "IsTruncated": False}

    def list_objects_v2(self, **kw: Any) -> Any:
        if kw.get("Bucket") == DATA:
            self.calls.append("list_objects_v2")
        return self._inner.list_objects_v2(**kw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def configuration(fmt: str = "CSV", **extra: Any) -> dict[str, Any]:
    return {
        "Id": CONFIG_ID,
        "IsEnabled": True,
        "IncludedObjectVersions": "Current",
        "Schedule": {"Frequency": "Daily"},
        "Destination": {
            "S3BucketDestination": {
                "Bucket": f"arn:aws:s3:::{DEST}",
                "Format": fmt,
                "Prefix": "inv",
            }
        },
        "OptionalFields": ["Size", "LastModifiedDate", "ETag"],
        **extra,
    }


def publish(env: Env, created: dt.datetime, *, fmt: str = "CSV", files: int = 1) -> None:
    """A report of every object in the data bucket, as S3 Inventory writes one."""
    s3 = env.clients.s3
    listed = s3.list_objects_v2(Bucket=DATA).get("Contents", [])
    rows = [
        (
            DATA,
            urllib.parse.quote_plus(o["Key"], safe="/"),
            str(o["Size"]),
            o["LastModified"].strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            o["ETag"].strip('"'),
        )
        for o in listed
    ]
    folder = f"inv/{DATA}/{CONFIG_ID}/{created.strftime('%Y-%m-%dT%H-%MZ')}/"
    keys = []
    per = max(1, -(-len(rows) // files))
    for n in range(files):
        chunk = rows[n * per : (n + 1) * per]
        key = f"inv/{DATA}/{CONFIG_ID}/data/part-{created:%H%M}-{n}.{fmt.lower()}"
        if fmt == "CSV":
            buf = io.StringIO()
            csv.writer(buf, quoting=csv.QUOTE_ALL).writerows(chunk)
            body = gzip.compress(buf.getvalue().encode())
        else:
            import pyarrow as pa
            import pyarrow.parquet as pq

            table = pa.table(
                {
                    "bucket": [r[0] for r in chunk],
                    "key": [urllib.parse.unquote_plus(r[1]) for r in chunk],
                    "size": [int(r[2]) for r in chunk],
                    "last_modified_date": [
                        dt.datetime.fromisoformat(r[3].replace("Z", "+00:00")) for r in chunk
                    ],
                    "e_tag": [r[4] for r in chunk],
                }
            )
            out = io.BytesIO()
            pq.write_table(table, out)
            body = out.getvalue()
        s3.put_object(Bucket=DEST, Key=key, Body=body)
        keys.append(key)
    manifest = {
        "sourceBucket": DATA,
        "destinationBucket": f"arn:aws:s3:::{DEST}",
        "fileFormat": fmt,
        "fileSchema": "Bucket, Key, Size, LastModifiedDate, ETag",
        "creationTimestamp": str(int(created.timestamp() * 1000)),
        "files": [{"key": k, "size": 1, "MD5checksum": "0" * 32} for k in keys],
    }
    s3.put_object(Bucket=DEST, Key=folder + "manifest.json", Body=json.dumps(manifest).encode())


def setup(env: Env, configs: list[dict[str, Any]]) -> WithInventory:
    env.clients.s3.create_bucket(
        Bucket=DEST, CreateBucketConfiguration={"LocationConstraint": "us-west-2"}
    )
    wrapped = WithInventory(env.clients.s3, configs)
    env.clients.s3 = wrapped  # type: ignore[assignment]
    return wrapped


def data_cov(doc: dict[str, Any]) -> dict[str, Any]:
    return next(c for c in doc["coverage"] if c["kind"] == "s3" and c["target"] == f"{DATA}/")


def s3_store(doc: dict[str, Any]) -> dict[str, Any]:
    __import__("test_streams").valid(doc)
    return next(s for s in doc["discovery"]["stores"] if s["kind"] == "s3" and s["name"] == DATA)


def cfg(**kw: Any) -> Any:
    from sensitive_data_scanner.config import store_rules

    # Discovery for the run summary; the inventory's own bucket is not a store to read here.
    return config(
        s3_inventory_min_objects=kw.pop("s3_inventory_min_objects", 3),
        discover=frozenset({"s3"}),
        deny=store_rules(f"s3:{DEST}"),
        **kw,
    )


def test_a_large_bucket_is_read_from_its_inventory_report_not_listed(env: Env) -> None:
    for i in range(4):
        env.put(f"a/{i}.txt", f"note {i}")
    s3 = setup(env, [configuration()])
    t0 = dt.datetime.now(dt.UTC)
    first = env.run(cfg(), now=lambda: t0)
    assert first is not None and "list_objects_v2" in s3.calls  # the first pass lists
    # Written after the first pass; the report taken an hour later has it.
    env.put(f"b/new {CARDS['visa'][:4]}.txt", f"card {printed(CARDS['visa'])}")
    publish(env, t0 + dt.timedelta(hours=1))
    s3.calls.clear()
    second = env.run(cfg(), now=lambda: t0 + dt.timedelta(hours=2))
    assert second is not None
    assert "list_objects_v2" not in s3.calls  # the data bucket was not listed
    cov = data_cov(second)
    assert (cov["listed"], cov["scanned"], cov["passComplete"]) == (5, 1, True)
    assert [f["resource"]["key"] for f in second["findings"]] == [f"b/new {CARDS['visa'][:4]}.txt"]
    assert s3_store(second)["listedBy"] == "inventory"
    state = env.state()["cursors"][f"s3:{DATA}/"]
    # The report's own time (to the millisecond its manifest gives) is the new watermark.
    taken = int((t0 + dt.timedelta(hours=1)).timestamp() * 1000) / 1000
    assert state["watermark"] == dt.datetime.fromtimestamp(taken, dt.UTC).isoformat()
    # The same report again: nothing listed, nothing read, until the next one.
    s3.calls.clear()
    third = env.run(cfg(), now=lambda: t0 + dt.timedelta(hours=3))
    assert third is not None and "list_objects_v2" not in s3.calls
    assert data_cov(third)["scanned"] == 0
    assert {f["id"] for f in third["findings"]} == {f["id"] for f in second["findings"]}


def test_a_report_is_read_across_runs_from_where_the_budget_stopped(env: Env) -> None:
    for i in range(3):
        env.put(f"a/{i}.txt", f"note {i}")
    s3 = setup(env, [configuration()])
    t0 = dt.datetime.now(dt.UTC)
    assert env.run(cfg(), now=lambda: t0) is not None
    for i in range(6):
        env.put(f"c/{i}.txt", f"ssn {dashed(SSN_A)} {i}")
    publish(env, t0 + dt.timedelta(hours=1), files=3)
    s3.calls.clear()
    read = 0
    last: dict[str, Any] = {}
    for n in range(2, 8):
        doc = env.run(cfg(max_items_per_run=2), now=lambda n=n: t0 + dt.timedelta(hours=n))
        assert doc is not None and "list_objects_v2" not in s3.calls
        last = doc
        cov = data_cov(doc)
        read += cov["scanned"]
        if cov["passComplete"]:
            break
    assert read == 6
    assert len({f["resource"]["key"] for f in last["findings"]}) == 6


def test_parquet_reports_are_read_with_pyarrow(env: Env) -> None:
    for i in range(3):
        env.put(f"a/{i}.txt", f"note {i}")
    s3 = setup(env, [configuration("Parquet")])
    t0 = dt.datetime.now(dt.UTC)
    assert env.run(cfg(), now=lambda: t0) is not None
    env.put("d/card.txt", f"card {printed(CARDS['amex'])}")
    publish(env, t0 + dt.timedelta(hours=1), fmt="Parquet")
    s3.calls.clear()
    doc = env.run(cfg(), now=lambda: t0 + dt.timedelta(hours=2))
    assert doc is not None and "list_objects_v2" not in s3.calls
    assert [f["resource"]["key"] for f in doc["findings"]] == ["d/card.txt"]


def test_a_large_bucket_with_no_inventory_is_recommended_one_and_listed(env: Env) -> None:
    for i in range(4):
        env.put(f"a/{i}.txt", f"note {i}")
    s3 = setup(env, [])
    t0 = dt.datetime.now(dt.UTC)
    assert env.run(cfg(), now=lambda: t0) is not None
    s3.calls.clear()
    doc = env.run(cfg(), now=lambda: t0 + dt.timedelta(hours=1))
    assert doc is not None
    assert s3_store(doc)["recommendation"] == "s3_inventory"
    assert "list_objects_v2" in s3.calls  # listed, as before
    assert "put_bucket_inventory_configuration" not in s3.calls
    # A small bucket is not.
    small = env.run(cfg(s3_inventory_min_objects=100), now=lambda: t0 + dt.timedelta(hours=2))
    assert small is not None


def test_an_unusable_inventory_means_a_listing(env: Env) -> None:
    for i in range(4):
        env.put(f"a/{i}.txt", f"note {i}")
    no_dates = configuration(OptionalFields=["Size"])
    s3 = setup(env, [no_dates])
    t0 = dt.datetime.now(dt.UTC)
    assert env.run(cfg(), now=lambda: t0) is not None
    s3.calls.clear()
    doc = env.run(cfg(), now=lambda: t0 + dt.timedelta(hours=1))
    assert doc is not None and "list_objects_v2" in s3.calls
    assert "recommendation" not in s3_store(doc)  # configured, just not usable
    # A report older than a week and a day is not read either.
    s3.configs = [configuration()]
    publish(env, t0 - dt.timedelta(days=9))
    s3.calls.clear()
    assert env.run(cfg(), now=lambda: t0 + dt.timedelta(hours=2)) is not None
    assert "list_objects_v2" in s3.calls


def test_finding_the_report_reads_only() -> None:
    """The module calls reads only: listing configurations, listing and getting objects."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(inventory))
    called = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert {"list_bucket_inventory_configurations", "list_objects_v2", "get_object"} <= called
    assert not {c for c in called if c.startswith(("put_", "delete_", "create_"))}


def test_a_weekly_inventory_is_read_and_daily_is_recommended(env: Env) -> None:
    """A weekly report leaves changes unseen for up to a week: the run summary recommends a
    daily one (#67), on the pass that reads the report and while the bucket waits for the
    next; a daily inventory gets no recommendation."""
    for i in range(4):
        env.put(f"a/{i}.txt", f"note {i}")
    s3 = setup(env, [configuration(Schedule={"Frequency": "Weekly"})])
    t0 = dt.datetime.now(dt.UTC)
    first = env.run(cfg(), now=lambda: t0)
    assert first is not None and "recommendation" not in s3_store(first)  # listed, not known
    publish(env, t0 + dt.timedelta(hours=1))
    second = env.run(cfg(), now=lambda: t0 + dt.timedelta(hours=2))
    assert second is not None
    store = s3_store(second)
    assert (store["listedBy"], store["recommendation"]) == ("inventory", "s3_inventory_daily")
    idle = env.run(cfg(), now=lambda: t0 + dt.timedelta(hours=3))
    assert idle is not None and s3_store(idle)["recommendation"] == "s3_inventory_daily"
    # Made daily: the next report's pass names nothing.
    s3.configs = [configuration()]
    publish(env, t0 + dt.timedelta(hours=4))
    daily = env.run(cfg(), now=lambda: t0 + dt.timedelta(hours=5))
    assert daily is not None
    store = s3_store(daily)
    assert store["listedBy"] == "inventory" and "recommendation" not in store
