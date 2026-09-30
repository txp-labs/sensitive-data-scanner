"""The job's own state, in its own blob container (`STATE_CONTAINER_URL`).

The same layout as the AWS scanner's results bucket:

- `findings/latest.json` and `findings/runs/<runId>.json`: the findings document;
- `state/scanner-state.json`: each source's cursor, the findings carried between
  runs, and the store the next run starts with (never read by a consumer);
- `state/lock.json`: one run at a time (a lock older than 20 minutes is stale).

This container is the only thing the job writes to: its identity holds Storage
Blob Data Contributor on it and on nothing else (deploy/azure/main.bicep).
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any

from sensitive_data_core.safety import error_name

LOCK_STALE_SECONDS = 20 * 60
STATE = "state/scanner-state.json"
LOCK = "state/lock.json"
LATEST = "findings/latest.json"
RUNS = "findings/runs/"
_MISSING = frozenset({"BlobNotFound", "ResourceNotFoundError", "ContainerNotFound"})
_EXISTS = frozenset({"BlobAlreadyExists", "ResourceExistsError", "ConditionNotMet"})


class BlobState:
    """Reads and writes JSON in the job's own container (a `ContainerClient`)."""

    def __init__(self, container: Any) -> None:
        self.container = container

    def __repr__(self) -> str:
        return "BlobState()"

    def get_json(self, name: str) -> Any:
        try:
            data = self.container.download_blob(name).readall()
        except Exception as err:
            if error_name(err) in _MISSING:
                return None
            raise
        return json.loads(data)

    def put_json(self, name: str, body: Any) -> None:
        data = json.dumps(body, separators=(",", ":")).encode()
        self.container.upload_blob(name, data, overwrite=True)

    def take_lock(self, run_id: str, now: _dt.datetime) -> bool:
        body = json.dumps({"runId": run_id}).encode()
        try:
            self.container.upload_blob(LOCK, body, overwrite=False)
            return True
        except Exception as err:
            if error_name(err) not in _EXISTS:
                raise
        props = self.container.get_blob_client(LOCK).get_blob_properties()
        age = (now - props.last_modified).total_seconds()
        if age < LOCK_STALE_SECONDS:
            return False
        self.container.delete_blob(LOCK)
        try:
            self.container.upload_blob(LOCK, body, overwrite=False)
            return True
        except Exception:  # another run took it first
            return False

    def release_lock(self) -> None:
        self.container.delete_blob(LOCK)
