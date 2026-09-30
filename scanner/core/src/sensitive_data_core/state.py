"""The state location a container runner keeps between runs (`STATE_LOCATION`).

A runner that is not a cloud's own job (the databases runner, the SaaS
scanner) keeps what the next run needs in one JSON document at a location the
customer names, in its own environment:

- **a local path** (`/state/sds-state.json`, or `file:///state/...`), on a
  mounted volume (EFS, Azure Files, a Cloud Storage volume, a Kubernetes
  persistent volume), replaced atomically;
- **S3** (`s3://bucket/key`), through a client the platform's package gives
  (the core imports no cloud SDK);
- **HTTPS** (`https://...`): read with a GET and written with a PUT, signed
  like the findings push (`X-SDS-Signature`, HMAC-SHA256 under the push key).

What goes in the document is the runner's own (a rotation, cursors, findings
carried between runs); never a value, a credential or a connection string. A
document that cannot be read, is too large, or is not JSON is no state: the run
starts afresh. Each class takes the size it may read (`max_bytes`).
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

from .index import FileBackend, HttpsBackend, S3Backend
from .push import SIGNATURE_HEADER, Revealable, sign
from .safety import error_name

MAX_STATE_BYTES = 64 * 1024 * 1024


class StateStore(Protocol):
    def load(self) -> dict[str, Any] | None: ...

    def save(self, state: dict[str, Any]) -> None: ...


def index_backend(store: StateStore) -> Any | None:
    """Where the per-object index (#67, `index.py`) lives beside a state location: the same
    place, with `.index/` after the state's own name (`/state/sds-state.json.index/`,
    `s3://bucket/key.index/`, `https://.../state.index/`). None for a store that has none."""
    make = getattr(store, "index_backend", None)
    return make() if callable(make) else None


def parse_state(raw: bytes, max_bytes: int) -> dict[str, Any] | None:
    """A state document, or None for one that is too large or is not a JSON object."""
    if len(raw) > max_bytes:
        return None
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def state_body(state: dict[str, Any]) -> bytes:
    return json.dumps(state, separators=(",", ":"), sort_keys=True).encode()


class FileState:
    """A file on a mounted volume, replaced atomically."""

    def __init__(self, path: str, *, max_bytes: int = MAX_STATE_BYTES) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes

    def __repr__(self) -> str:
        return "FileState()"

    def load(self) -> dict[str, Any] | None:
        try:
            return parse_state(self.path.read_bytes()[: self.max_bytes + 1], self.max_bytes)
        except FileNotFoundError:
            return None

    def save(self, state: dict[str, Any]) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_bytes(state_body(state))
        os.replace(tmp, self.path)

    def index_backend(self) -> Any:
        return FileBackend(str(self.path) + ".index")


class S3State:
    """An object in S3, through a client the platform's package makes (`client_factory`)."""

    def __init__(
        self,
        bucket: str,
        key: str,
        client: Any | None = None,
        *,
        client_factory: Callable[[], Any] | None = None,
        max_bytes: int = MAX_STATE_BYTES,
    ) -> None:
        self.bucket = bucket
        self.key = key
        self._client = client
        self._factory = client_factory
        self.max_bytes = max_bytes

    def __repr__(self) -> str:
        return "S3State()"

    def _s3(self) -> Any:
        if self._client is None:
            if self._factory is None:
                raise RuntimeError("no s3 client")
            self._client = self._factory()
        return self._client

    def load(self) -> dict[str, Any] | None:
        try:
            body = self._s3().get_object(Bucket=self.bucket, Key=self.key)["Body"]
        except Exception as err:
            if error_name(err) in ("NoSuchKey", "404", "NotFound"):
                return None
            raise
        return parse_state(body.read(self.max_bytes + 1), self.max_bytes)

    def save(self, state: dict[str, Any]) -> None:
        self._s3().put_object(
            Bucket=self.bucket,
            Key=self.key,
            Body=state_body(state),
            ContentType="application/json",
        )

    def index_backend(self) -> Any:
        return S3Backend(self.bucket, self.key + ".index/", client_factory=self._s3)


class HttpsState:
    """A URL the customer serves: GET to read, a signed PUT to write."""

    def __init__(
        self,
        url: Revealable,
        key: Revealable,
        *,
        user_agent: str = "sensitive-data-scanner",
        max_bytes: int = MAX_STATE_BYTES,
        opener: Callable[..., Any] = urllib.request.urlopen,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._url = url
        self._key = key
        self._agent = user_agent
        self.max_bytes = max_bytes
        self._open = opener
        self._clock = clock

    def __repr__(self) -> str:
        return "HttpsState(***)"

    def load(self) -> dict[str, Any] | None:
        req = urllib.request.Request(self._url.reveal(), method="GET")  # noqa: S310 - https only
        try:
            with self._open(req, timeout=60) as resp:
                return parse_state(resp.read(self.max_bytes + 1), self.max_bytes)
        except Exception as err:
            if getattr(err, "code", None) == 404:
                return None
            raise

    def save(self, state: dict[str, Any]) -> None:
        body = state_body(state)
        ts = str(int(self._clock()))
        req = urllib.request.Request(  # noqa: S310 - https only (each runner's settings)
            self._url.reveal(),
            data=body,
            method="PUT",
            headers={
                "Content-Type": "application/json",
                "User-Agent": self._agent,
                SIGNATURE_HEADER: sign(self._key.reveal().encode(), ts, body),
            },
        )
        with self._open(req, timeout=60):
            return

    def index_backend(self) -> Any:
        return HttpsBackend(
            self._url, self._key, user_agent=self._agent, opener=self._open, clock=self._clock
        )


def valid_location(raw: str) -> str | None:
    """The problem with a `STATE_LOCATION`, as a config code, or None when it is usable:
    an absolute path, a `file://` URL, `s3://bucket/key` or an `https://` URL."""
    t = raw.strip()
    if t.startswith("s3://"):
        bucket, _, key = t.removeprefix("s3://").partition("/")
        return None if bucket and key else "state_location"
    if t.startswith("https://"):
        return None if urllib.parse.urlsplit(t).hostname else "state_location"
    path = urllib.parse.urlsplit(t).path if t.startswith("file://") else t
    return None if path.startswith("/") else "state_location"


def state_location(
    location: Revealable,
    key: Revealable | None,
    *,
    user_agent: str,
    max_bytes: int = MAX_STATE_BYTES,
    s3_client: Callable[[], Any] | None = None,
) -> StateStore:
    """The store a (validated) `STATE_LOCATION` names. HTTPS needs the push's key."""
    raw = location.reveal()
    if raw.startswith("s3://"):
        bucket, _, name = raw.removeprefix("s3://").partition("/")
        return S3State(bucket, name, client_factory=s3_client, max_bytes=max_bytes)
    if raw.startswith("https://"):
        if key is None:
            raise ValueError("an https state needs the push key")
        return HttpsState(location, key, user_agent=user_agent, max_bytes=max_bytes)
    path = urllib.parse.urlsplit(raw).path if raw.startswith("file://") else raw
    return FileState(path, max_bytes=max_bytes)
