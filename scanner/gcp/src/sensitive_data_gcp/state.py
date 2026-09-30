"""The job's own state, in its own Cloud Storage bucket (`STATE_BUCKET`).

The same layout as the AWS scanner's results bucket:

- `findings/latest.json` and `findings/runs/<runId>.json`: the findings document;
- `state/scanner-state.json`: each source's cursor, the findings carried between
  runs, and the store the next run starts with (never read by a consumer);
- `state/lock.json`: one run at a time, created only if absent
  (`ifGenerationMatch=0`); a lock older than 20 minutes is stale;
- `state/index/`: the per-object index (#67, the core's `index`), keyed hashes only.

This bucket is the only thing the job writes to: its service account holds
Storage Object User on it and on nothing else (deploy/gcp).
"""

from __future__ import annotations

import datetime as _dt
import json
import urllib.parse
from typing import Any

from sensitive_data_core.safety import error_name

from .clients import STORAGE_API, UPLOAD_API, Rest

LOCK_STALE_SECONDS = 20 * 60
STATE = "state/scanner-state.json"
LOCK = "state/lock.json"
LATEST = "findings/latest.json"
RUNS = "findings/runs/"
INDEX = "state/index/"


class GcsState:
    """Reads and writes JSON in the job's own bucket, over the JSON API."""

    def __init__(self, rest: Rest, bucket: str) -> None:
        self.rest = rest
        self.bucket = bucket

    def __repr__(self) -> str:
        return "GcsState()"

    def _object(self, name: str) -> str:
        q = urllib.parse.quote
        return f"{STORAGE_API}/b/{q(self.bucket, safe='')}/o/{q(name, safe='')}"

    def get_json(self, name: str) -> Any:
        try:
            resp = self.rest.call("GET", self._object(name), params={"alt": "media"})
        except Exception as err:
            if error_name(err) == "NOT_FOUND":
                return None
            raise
        return json.loads(resp.content)

    def _upload(
        self, name: str, data: bytes, content_type: str = "application/json", **conditions: str
    ) -> None:
        q = urllib.parse.quote
        self.rest.call(
            "POST",
            f"{UPLOAD_API}/b/{q(self.bucket, safe='')}/o",
            params={"uploadType": "media", "name": name, **conditions},
            data=data,
            headers={"Content-Type": content_type},
        )

    # The object index's files (the core's `IndexBackend`, under `INDEX`).

    def get_bytes(self, name: str) -> bytes | None:
        try:
            resp = self.rest.call("GET", self._object(name), params={"alt": "media"})
        except Exception as err:
            if error_name(err) == "NOT_FOUND":
                return None
            raise
        data: bytes = resp.content
        return data

    def put_bytes(self, name: str, data: bytes) -> None:
        self._upload(name, data, "application/octet-stream")

    def delete(self, name: str) -> None:
        try:
            self.rest.call("DELETE", self._object(name))
        except Exception as err:
            if error_name(err) != "NOT_FOUND":
                raise

    def put_json(self, name: str, body: Any) -> None:
        self._upload(name, json.dumps(body, separators=(",", ":")).encode())

    def take_lock(self, run_id: str, now: _dt.datetime) -> bool:
        body = json.dumps({"runId": run_id}).encode()
        try:
            self._upload(LOCK, body, ifGenerationMatch="0")
            return True
        except Exception as err:
            if error_name(err) != "FAILED_PRECONDITION":
                raise
        meta = self.rest.get(self._object(LOCK), {"fields": "updated,generation"})
        updated = _dt.datetime.fromisoformat(str(meta.get("updated")).replace("Z", "+00:00"))
        if (now - updated).total_seconds() < LOCK_STALE_SECONDS:
            return False
        try:
            generation = str(meta.get("generation") or "")
            self.rest.call("DELETE", self._object(LOCK), params={"ifGenerationMatch": generation})
            self._upload(LOCK, body, ifGenerationMatch="0")
            return True
        except Exception:  # another run took it first
            return False

    def release_lock(self) -> None:
        self.rest.call("DELETE", self._object(LOCK))
