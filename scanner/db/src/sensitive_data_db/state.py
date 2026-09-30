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

The three locations are the core's (`sensitive_data_core.state`), held here to
64 KiB, the size of this document.

A state that cannot be read (missing, unreadable, another site's) is no state: the run
goes on from the start. One that cannot be written is logged by error name; the run's
findings still go out.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from sensitive_data_core import state as core_state
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.state import StateStore

from . import __version__
from .config import Secret, Settings

STATE_VERSION = 1
MAX_STATE_BYTES = 64 * 1024

__all__ = [
    "FileState",
    "HttpsState",
    "S3State",
    "StateStore",
    "load_rotation",
    "save_rotation",
    "state_for",
]


def _s3_client() -> Any:
    import boto3  # noqa: PLC0415 - the `aws` extra, only when S3 holds the state

    return boto3.client("s3")


class FileState(core_state.FileState):
    """A file on a mounted volume, replaced atomically (the core's, at 64 KiB)."""

    def __init__(self, path: str) -> None:
        super().__init__(path, max_bytes=MAX_STATE_BYTES)


class S3State(core_state.S3State):
    """An object in S3 (the `aws` extra's boto3)."""

    def __init__(self, bucket: str, key: str, client: Any | None = None) -> None:
        super().__init__(bucket, key, client, client_factory=_s3_client, max_bytes=MAX_STATE_BYTES)


class HttpsState(core_state.HttpsState):
    """A URL the customer serves: GET to read, a signed PUT to write."""

    def __init__(self, url: Secret, key: Secret, **kwargs: Any) -> None:
        kwargs.setdefault("user_agent", f"sensitive-data-scanner-db/{__version__}")
        kwargs.setdefault("max_bytes", MAX_STATE_BYTES)
        super().__init__(url, key, **kwargs)


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
    if not state or state.get("version") != STATE_VERSION or state.get("site") != site:
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
