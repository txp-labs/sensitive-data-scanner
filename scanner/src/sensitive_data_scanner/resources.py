"""AWS resources and console links for findings: S3 objects, log events, DynamoDB items,
RDS columns, and a page in the account's own console.

The findings contract itself (ids, offsets, coverage, the document) is the
core's (`sensitive_data_core.findings`). Every name here is masked like an
object key, and a link survives only when no name it was built from was masked
(`sensitive_data_core.findings.Link`).
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from sensitive_data_core.findings import Link
from sensitive_data_core.safety import redact_digits


def s3_link(region: str, bucket: str, key: str, version_id: str | None) -> Link:
    """The object's page: it names the bucket and the key."""
    q = {"region": region, "bucketType": "general", "prefix": key}
    if version_id and version_id != "null":
        q["versionId"] = version_id
    return Link(
        f"https://{region}.console.aws.amazon.com/s3/object/{urllib.parse.quote(bucket)}?"
        + urllib.parse.urlencode(q),
        (bucket, key),
    )


def _cw_escape(s: str) -> str:
    # The CloudWatch console's own escaping inside its URL fragment.
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="").replace("%", "$")


def logs_link(region: str, group: str, stream: str, timestamp_ms: int) -> Link:
    """The event's page: it names the group and the stream, and the event's time."""
    frag = (
        f"logsV2:log-groups/log-group/{_cw_escape(group)}/log-events/{_cw_escape(stream)}"
        + _cw_escape(f"?start={timestamp_ms}&end={timestamp_ms + 1}")
    )
    return Link(
        f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#{frag}",
        (group, stream),
    )


def s3_resource(
    bucket: str,
    key: str,
    version_id: str | None,
    *,
    column: str | None = None,
    catalog: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """An S3 object version; for a table object, the column; for a catalog table, its name."""
    masked = redact_digits(key)
    masked_bucket = redact_digits(bucket)
    out: dict[str, Any] = {"type": "s3_object", "bucket": masked_bucket, "key": masked}
    out["versionId"] = version_id or "null"
    changed = masked != key or masked_bucket != bucket
    if column is not None:
        out["column"] = redact_digits(column)
        changed = changed or out["column"] != column
    if catalog is not None:
        out["catalog"] = {"database": redact_digits(catalog[0]), "table": redact_digits(catalog[1])}
        changed = changed or (out["catalog"]["database"], out["catalog"]["table"]) != catalog
    if changed:
        out["keyMasked"] = True
    return out


def log_resource(group: str, stream: str, timestamp_ms: int) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "log_event",
        "logGroup": redact_digits(group),
        "logStream": redact_digits(stream),
        "timestamp": timestamp_ms,
    }
    if out["logGroup"] != group or out["logStream"] != stream:
        out["nameMasked"] = True
    return out


def dynamodb_link(region: str, table: str) -> Link:
    """The table's item explorer. It names no key: the reviewer queries by the masked key."""
    return Link(
        f"https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}"
        f"#item-explorer?table={urllib.parse.quote(table, safe='')}",
        (table,),
    )


def dynamodb_resource(
    table: str,
    key: dict[str, str],
    key_hash: str,
    attribute_path: str,
    *,
    planted: bool = False,
) -> dict[str, Any]:
    """An item by its key hash, with the key's values masked like an S3 object key."""
    masked = {name: redact_digits(value) for name, value in sorted(key.items())}
    path = redact_digits(attribute_path)
    masked_table = redact_digits(table)
    out: dict[str, Any] = {
        "type": "dynamodb_item",
        "table": masked_table,
        "keyHash": key_hash,
        "key": masked,
        "attributePath": path,
    }
    if masked != dict(sorted(key.items())) or path != attribute_path or masked_table != table:
        out["keyMasked"] = True
    if planted:
        out["planted"] = True
    return out


def rds_link(region: str, identifier: str, db_type: str) -> Link:
    """The cluster's or instance's page in the RDS console. It names no table or column."""
    return Link(
        f"https://{region}.console.aws.amazon.com/rds/home?region={region}"
        f"#database:id={urllib.parse.quote(identifier, safe='')};"
        f"is-cluster={'true' if db_type == 'cluster' else 'false'}",
        (identifier,),
    )


def rds_resource(
    *,
    engine: str,
    identifier: str,
    db_type: str,
    database: str,
    table: str,
    column: str,
    read_by: str,
    snapshot_time: str | None = None,
) -> dict[str, Any]:
    """One column of one table of an RDS or Aurora database (`schema.table.column`)."""
    names = {
        "cluster": identifier,
        "database": database,
        "table": table,
        "column": column,
    }
    masked = {k: redact_digits(v) for k, v in names.items()}
    out: dict[str, Any] = {
        "type": "rds_column",
        "engine": engine,
        "dbType": db_type,
        **masked,
        "readBy": read_by,
    }
    if snapshot_time:
        # The time, not the snapshot's name: an automated snapshot is named after
        # the cluster, and the name would carry whatever the cluster's name does.
        out["snapshotTime"] = snapshot_time
    if masked != names:
        out["keyMasked"] = True
    return out


def console_link(region: str, path: str, names: tuple[str, ...] | None = None) -> str:
    """A page in the account's own AWS console (`path` after the host, already quoted).

    With `names`, the names the path was built from, it is a `Link` that survives
    masking elsewhere in the resource; without, it is dropped whenever anything is masked.
    """
    url = f"https://{region}.console.aws.amazon.com/{path}"
    return url if names is None else Link(url, names)
