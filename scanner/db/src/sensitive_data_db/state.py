"""The databases runner's optional state (`STATE_LOCATION`): which database the next run
starts with, so the ones a run's budget does not reach are read on the next (#21).

Without it, each run samples afresh in the configured order, and a database the budget
never reaches is `deferred` every time. With it, the runner reads, before the run, and
writes, after it, a small JSON document:

    {"version": 1, "site": "dc-1", "rotation": "<the first database deferred>"}

It holds no value, no connection string and no finding: only the name the customer gave
a database. It can live in three places:

- **a local path** (`/state/sds-state.json`, or `file:///state/sds-state.json`), on a
  mounted volume, written atomically;
- **S3** (`s3://bucket/key`), with the `aws` extra's boto3 and the credentials the
  container is given (`s3:GetObject` and `s3:PutObject` on that key);
- **HTTPS** (`https://...`): read with a GET and written with a PUT, signed like the
  findings push (`X-SDS-Signature`, HMAC-SHA256 under `FINDINGS_HMAC_KEY`).

A state that cannot be read (missing, unreadable, another site's) is no state: the run
goes on from the start. One that cannot be written is logged by error name; the run's
findings still go out.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from sensitive_data_core.safety import error_name, log_event

from . import __version__
from .config import Secret, Settings
from .sinks import SIGNATURE_HEADER, sign

STATE_VERSION = 1
MAX_STATE_BYTES = 64 * 1024


class StateStore(Protocol):
    def load(self) -> dict[str, Any] | None: ...

    def save(self, state: dict[str, Any]) -> None: ...


def _parse(raw: bytes) -> dict[str, Any] | None:
    if len(raw) > MAX_STATE_BYTES:
        return None
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) and doc.get("version") == STATE_VERSION else None


def _body(state: dict[str, Any]) -> bytes:
    return json.dumps(state, separators=(",", ":"), sort_keys=True).encode()


class FileState:
    """A file on a mounted volume, replaced atomically."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def __repr__(self) -> str:
        return "FileState()"

    def load(self) -> dict[str, Any] | None:
        try:
            return _parse(self.path.read_bytes()[: MAX_STATE_BYTES + 1])
        except FileNotFoundError:
            return None

    def save(self, state: dict[str, Any]) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_bytes(_body(state))
        os.replace(tmp, self.path)


class S3State:
    """An object in S3 (the `aws` extra)."""

    def __init__(self, bucket: str, key: str, client: Any | None = None) -> None:
        self.bucket = bucket
        self.key = key
        self._client = client

    def __repr__(self) -> str:
        return "S3State()"

    def _s3(self) -> Any:
        if self._client is None:
            import boto3  # noqa: PLC0415 - the `aws` extra, only when S3 holds the state

            self._client = boto3.client("s3")
        return self._client

    def load(self) -> dict[str, Any] | None:
        try:
            body = self._s3().get_object(Bucket=self.bucket, Key=self.key)["Body"]
        except Exception as err:
            if error_name(err) in ("NoSuchKey", "404", "NotFound"):
                return None
            raise
        return _parse(body.read(MAX_STATE_BYTES + 1))

    def save(self, state: dict[str, Any]) -> None:
        self._s3().put_object(
            Bucket=self.bucket, Key=self.key, Body=_body(state), ContentType="application/json"
        )


class HttpsState:
    """A URL the customer serves: GET to read, a signed PUT to write."""

    def __init__(
        self,
        url: Secret,
        key: Secret,
        *,
        opener: Callable[..., Any] = urllib.request.urlopen,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._url = url
        self._key = key
        self._open = opener
        self._clock = clock

    def __repr__(self) -> str:
        return "HttpsState(***)"

    def load(self) -> dict[str, Any] | None:
        req = urllib.request.Request(self._url.reveal(), method="GET")  # noqa: S310 - https only
        try:
            with self._open(req, timeout=30) as resp:
                return _parse(resp.read(MAX_STATE_BYTES + 1))
        except Exception as err:
            if getattr(err, "code", None) == 404:
                return None
            raise

    def save(self, state: dict[str, Any]) -> None:
        body = _body(state)
        ts = str(int(self._clock()))
        req = urllib.request.Request(  # noqa: S310 - https only (config.py)
            self._url.reveal(),
            data=body,
            method="PUT",
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"sensitive-data-scanner-db/{__version__}",
                SIGNATURE_HEADER: sign(self._key.reveal().encode(), ts, body),
            },
        )
        with self._open(req, timeout=30):
            return


def state_for(settings: Settings) -> StateStore | None:
    """The state store `STATE_LOCATION` names, or None (each run samples afresh)."""
    loc = settings.state_location
    if loc is None:
        return None
    raw = loc.reveal()
    if raw.startswith("s3://"):
        bucket, _, key = raw.removeprefix("s3://").partition("/")
        return S3State(bucket, key)
    if raw.startswith("https://") and settings.hmac_key is not None:
        return HttpsState(loc, settings.hmac_key)
    return FileState(urllib.parse.urlsplit(raw).path if raw.startswith("file://") else raw)


def load_rotation(store: StateStore | None, site: str) -> str | None:
    """The database the previous run deferred first, if the state is this site's."""
    if store is None:
        return None
    try:
        state = store.load()
    except Exception as err:  # no state: the run goes on from the start
        log_event("source.failed", source="state", error=error_name(err))
        return None
    if not state or state.get("site") != site:
        return None
    rotation = state.get("rotation")
    return rotation if isinstance(rotation, str) else None


def save_rotation(store: StateStore | None, site: str, rotation: str | None) -> None:
    if store is None:
        return
    try:
        store.save({"version": STATE_VERSION, "site": site, "rotation": rotation})
    except Exception as err:  # the findings still go out; the next run starts from the top
        log_event("source.failed", source="state", error=error_name(err))
