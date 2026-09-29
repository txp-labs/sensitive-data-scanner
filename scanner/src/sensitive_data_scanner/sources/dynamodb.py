"""DynamoDB source: one table, read with a paginated Query or Scan. Read-only.

- **Query** when the target names a partition key value, optionally with a
  sort-key prefix (`begins_with`). **Scan** otherwise. The key names and
  types come from DescribeTable, so the configuration names values only.
- **Projection.** With `include` paths, the request asks only for their
  top-level attributes and the key; the paths then pick the leaves inside
  them. `exclude` paths are dropped after reading.
- **Rate limits.** A throttled request (ProvisionedThroughputExceeded,
  ThrottlingException, RequestLimitExceeded) is retried with exponential
  backoff and jitter, up to five times. Past that, the source stops, names
  the error, and the next run resumes at the same key.
- **Page cap and budget.** A run reads at most `max_pages` pages of
  `page_size` items, and stops early when its share of the run's budget is
  spent. The cursor keeps the last item read, and the next run resumes
  there, so a large table is covered over several runs.
- **A pass.** When the last page of a pass is read, findings for items the
  pass no longer found (deleted, or clean now) drop out.

A finding is one attribute path of one item: the table, a keyed hash of the
item's key, the key with anything that could be a card number or an SSN
masked (as S3 object keys are), and the path. Never a value. The key hash
is an HMAC under a random salt kept in the scanner's own state, so a short
key (a nine-digit number) cannot be recovered by hashing guesses.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import random
import secrets
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..config import DynamoTarget
from ..detect.analyzer import Detector
from ..findings import Coverage, dynamodb_link, dynamodb_resource, finding_json
from ..safety import error_name, log_event
from ..scan.attributes import FORMAT, AttributeRules, key_value, scan_attributes
from ..scan.paths import parse_path
from .base import Budget, FindingStore, SourceRun

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient

THROTTLED = frozenset(
    {
        "ProvisionedThroughputExceededException",
        "ThrottlingException",
        "RequestLimitExceeded",
        "Throttling",
    }
)
MAX_RETRIES = 5
BACKOFF_BASE_S = 0.25
BACKOFF_CAP_S = 8.0


def _rules(t: DynamoTarget) -> AttributeRules:
    return AttributeRules(
        include=tuple(parse_path(p) for p in t.include),
        exclude=tuple(parse_path(p) for p in t.exclude),
        keypad=tuple(parse_path(p) for p in t.keypad),
        prompts=tuple(parse_path(p) for p in t.prompts),
        planted=tuple(parse_path(p) for p in t.planted),
    )


class DynamoDBSource:
    kind = "dynamodb"

    def __init__(
        self,
        client: DynamoDBClient,
        *,
        target: DynamoTarget,
        region: str,
        page_size: int = 100,
        max_pages: int = 200,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client = client
        self.t = target
        self.region = region
        self.page_size = page_size
        self.max_pages = max_pages
        self.sleep = sleep
        self.rules = _rules(target)
        # The id names the read without its values: the partition and prefix go in hashed.
        basis = json.dumps([target.table, target.partition, target.sort_prefix])
        self.id = f"dynamodb:{target.table}:{hashlib.sha256(basis.encode()).hexdigest()[:12]}"
        self.target = target.table if target.partition is None else f"{target.table} (query)"

    def _call(self, op: str, budget: Budget, args: dict[str, Any]) -> dict[str, Any]:
        fn = getattr(self.client, op)
        attempt = 0
        while True:
            try:
                result: dict[str, Any] = fn(**args)
                return result
            except Exception as err:
                name = error_name(err)
                if name not in THROTTLED or attempt >= MAX_RETRIES or not budget.time_left():
                    raise
                log_event("source.throttled", source=self.target, error=name, attempt=attempt + 1)
                delay = min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2**attempt)
                self.sleep(delay / 2 + random.uniform(0, delay / 2))  # noqa: S311 - jitter only
                attempt += 1

    def _request(self, key_schema: dict[str, tuple[str, str]]) -> tuple[str, dict[str, Any]]:
        """The Query or Scan arguments, before pagination."""
        args: dict[str, Any] = {"TableName": self.t.table, "Limit": self.page_size}
        names: dict[str, str] = {}
        values: dict[str, Any] = {}
        tops = self.rules.top_level_names()
        if tops:
            wanted = list(dict.fromkeys([*(n for n, _ in key_schema.values()), *tops]))
            for i, n in enumerate(wanted):
                names[f"#p{i}"] = n
            args["ProjectionExpression"] = ", ".join(f"#p{i}" for i in range(len(wanted)))
        op = "scan"
        if self.t.partition is not None:
            op = "query"
            pk_name, pk_type = key_schema["HASH"]
            names["#pk"] = pk_name
            values[":pk"] = {pk_type: self.t.partition}
            cond = "#pk = :pk"
            if self.t.sort_prefix is not None:
                if "RANGE" not in key_schema:
                    raise ValueError("table has no sort key")
                names["#sk"] = key_schema["RANGE"][0]
                values[":sk"] = {"S": self.t.sort_prefix}
                cond += " AND begins_with(#sk, :sk)"
            args["KeyConditionExpression"] = cond
            args["ExpressionAttributeValues"] = values
        if names:
            args["ExpressionAttributeNames"] = names
        return op, args

    def _key_hash(self, salt: str, key: dict[str, Any]) -> str:
        canonical = json.dumps(
            {n: key_value(v) for n, v in sorted(key.items())}, separators=(",", ":")
        )
        return hmac.new(salt.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage("dynamodb", self.target)
        salt = cursor.get("keySalt") or secrets.token_hex(16)
        start_key = cursor.get("startKey") or None
        pass_id = cursor.get("passId") or secrets.token_hex(8)
        seen_at = now.isoformat()
        done = False
        pages = 0
        try:
            desc = self._call("describe_table", budget, {"TableName": self.t.table})["Table"]
            types = {a["AttributeName"]: a["AttributeType"] for a in desc["AttributeDefinitions"]}
            key_schema = {
                k["KeyType"]: (k["AttributeName"], types.get(k["AttributeName"], "S"))
                for k in desc["KeySchema"]
            }
            key_names = [n for n, _ in key_schema.values()]
            op, base = self._request(key_schema)
            while budget.time_left():
                if pages >= self.max_pages:
                    break
                args = dict(base)
                if start_key:
                    args["ExclusiveStartKey"] = start_key
                page = self._call(op, budget, args)
                pages += 1
                cov.listed += int(page.get("ScannedCount", len(page.get("Items", []))))
                cut = False
                for item in page.get("Items", []):
                    cov.eligible += 1
                    size = len(json.dumps(item, default=str).encode())
                    if not budget.has(size):
                        cut = True
                        break
                    budget.take(size)
                    key = {n: item[n] for n in key_names if n in item}
                    key_hash = self._key_hash(salt, key)
                    location = f"{self.id}\n{key_hash}"
                    try:
                        result = scan_attributes(item, detector, self.rules)
                    except Exception as err:  # one bad item must not stop the pass
                        cov.unreadable += 1
                        log_event("item.unreadable", source=self.target, error=error_name(err))
                        start_key = key
                        continue
                    cov.scanned += 1
                    cov.bytes_scanned += size
                    cov.formats[FORMAT] = cov.formats.get(FORMAT, 0) + 1
                    cov.redaction_markers += result.redaction_markers
                    cov.test_values += result.test_values
                    cov.suppressed += result.suppressed
                    shown = {n: key_value(v) for n, v in key.items()}
                    findings = []
                    for path, found in sorted(result.by_path.items()):
                        resource = dynamodb_resource(
                            self.t.table,
                            shown,
                            key_hash,
                            path,
                            planted=path in result.planted,
                        )
                        link = dynamodb_link(self.region, self.t.table)
                        for cf in found.findings.values():
                            f = finding_json(resource, link, FORMAT, cf, seen_at)
                            f["_pass"] = pass_id
                            findings.append(f)
                    store.replace_location(location, findings)
                    start_key = key
                if cut:
                    break
                start_key = page.get("LastEvaluatedKey") or None
                if start_key is None:
                    done = True
                    break
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
        if done and cov.error is None:
            cov.pass_complete = True
            gone = [
                k
                for k, v in store.items.items()
                if v.get("_location", "").startswith(f"{self.id}\n") and v.get("_pass") != pass_id
            ]
            for k in gone:
                del store.items[k]
            if gone:
                log_event("finding.gone", source=self.target, count=len(gone))
            return SourceRun(cov, {"keySalt": salt, "startKey": None, "passId": None})
        if cov.error is None:
            cov.backlog = True
        return SourceRun(cov, {"keySalt": salt, "startKey": start_key, "passId": pass_id})
