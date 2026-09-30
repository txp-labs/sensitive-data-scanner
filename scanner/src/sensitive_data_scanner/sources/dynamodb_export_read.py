"""DynamoDB's read path for a table read by export: each data file fetched and inflated, and
each item's attributes read by the core's attribute reader.

This module is `adapter:dynamodb` (scripts/components.py): a change here rescans the objects
it read. Listing, discovery and configuration stay in `dynamodb_export.py`
(`listing:<kind>`), whose changes re-list and never re-read (#67).
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import zlib
from typing import TYPE_CHECKING, Any

from sensitive_data_core.adapter import FindingStore
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, finding_json
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.attributes import FORMAT, key_value, scan_attributes

from ..resources import dynamodb_resource

if TYPE_CHECKING:
    from .dynamodb_export import DynamoDBExportSource as _Self

READS = ("dynamodb",)


def _file_text(src: _Self, obj: dict[str, Any], cov: Coverage) -> str | None:
    """One export data file (`.json.gz`), fetched up to the byte cap and inflated up to
    the inflated cap; None when it cannot be (counted unreadable)."""
    args: dict[str, Any] = {"Bucket": src.bucket, "Key": obj["Key"]}
    if int(obj.get("Size", 0)) > src.max_object_bytes:
        args["Range"] = f"bytes=0-{src.max_object_bytes - 1}"
        cov.partial += 1
    try:
        data = src.s3.get_object(**args)["Body"].read()
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        text: str = d.decompress(data, src.max_inflated_bytes).decode("utf-8", "replace")
    except (zlib.error, OSError, EOFError, gzip.BadGzipFile) as err:
        cov.unreadable += 1
        log_event("item.unreadable", source=src.target, error=error_name(err))
        return None
    cov.bytes_scanned += len(data)
    return text


def _item(
    src: _Self,
    line: str,
    *,
    c: dict[str, Any],
    cov: Coverage,
    detector: Detector,
    store: FindingStore,
    salt: str,
    link: str,
    seen_at: str,
) -> None:
    try:
        doc = json.loads(line)
    except (ValueError, RecursionError):
        return
    if not isinstance(doc, dict):
        return
    if "Keys" in doc:
        # An incremental export's line: the item's keys and its new image, or no image
        # for an item deleted in the window.
        keys = doc.get("Keys") if isinstance(doc.get("Keys"), dict) else {}
        item = doc.get("NewImage")
        if not isinstance(item, dict):
            canonical = json.dumps(
                {n: key_value(v) for n, v in sorted((keys or {}).items())},
                separators=(",", ":"),
            )
            gone = hmac.new(salt.encode(), canonical.encode(), hashlib.sha256).hexdigest()
            store.remove_location(f"{src.id}\n{gone}")
            return
    else:
        item = doc.get("Item")
    if not isinstance(item, dict):
        return
    cov.eligible += 1
    key = {n: item[n] for n in c.get("keyNames") or [] if n in item}
    canonical = json.dumps({n: key_value(v) for n, v in sorted(key.items())}, separators=(",", ":"))
    key_hash = hmac.new(salt.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    try:
        result = scan_attributes(item, detector, src.rules)
    except Exception as err:  # one bad item must not stop the pass
        cov.unreadable += 1
        log_event("item.unreadable", source=src.target, error=error_name(err))
        return
    cov.scanned += 1
    cov.formats[FORMAT] = cov.formats.get(FORMAT, 0) + 1
    cov.redaction_markers += result.redaction_markers
    cov.test_values += result.test_values
    cov.suppressed += result.suppressed
    shown = {n: key_value(v) for n, v in key.items()}
    findings = []
    for path, found in sorted(result.by_path.items()):
        resource = dynamodb_resource(src.table, shown, key_hash, path)
        for cf in found.findings.values():
            f = finding_json(resource, link, FORMAT, cf, seen_at, facts=src.facts)
            f["_pass"] = c["passId"]
            f.update(c.get("rescan") or {})
            findings.append(f)
    store.replace_location(f"{src.id}\n{key_hash}", findings)
