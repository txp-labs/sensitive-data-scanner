"""Google Cloud's resources in findings: where a store is, masked, hashed and linked.

A store's full resource name (Cloud Asset Inventory's `name`, such as
`//storage.googleapis.com/<bucket>` or
`//bigquery.googleapis.com/projects/<project>/datasets/<dataset>/tables/<table>`)
names its project and the resource, any of which a customer may have named with
a number in it. So a finding and a run summary entry carry:

- `project`: the project id, masked like a key;
- `resourceNameHash`: the SHA-256 of the full resource name exactly as Cloud
  Asset Inventory gives it, so a consumer can match a finding to a resource it
  knows without the name being written (hash yours the same way:
  `printf %s "//storage.googleapis.com/<bucket>" | shasum -a 256`).

A `link` goes to the resource's page in the Google Cloud console. It is built
from the project and the resource's names, and dropped when any of them had to
be masked (the core's `Link`).
"""

from __future__ import annotations

import hashlib
import urllib.parse
from dataclasses import dataclass
from typing import Any

from sensitive_data_core.findings import Link
from sensitive_data_core.safety import redact_digits

CONSOLE = "https://console.cloud.google.com"


def resource_name_hash(full_name: str) -> str:
    """How a resource is named: the SHA-256 of its full resource name, as lower-case hex."""
    return hashlib.sha256(full_name.strip().encode()).hexdigest()


def gcp_fields(project: str, full_name: str) -> dict[str, Any]:
    """`project` and `resourceNameHash` for a finding or a store."""
    out: dict[str, Any] = {}
    if project:
        out["project"] = redact_digits(project)
    out["resourceNameHash"] = resource_name_hash(full_name)
    return out


def console_link(path: str, query: dict[str, str], *names: str) -> Link:
    """A page of the Google Cloud console: `path` (built from `names`) with `query`. The
    link carries every name it was built from, so masking any of them drops it."""
    text = urllib.parse.urlencode(query)
    return Link(f"{CONSOLE}/{path}?{text}", tuple(v for v in (*names, *query.values()) if v))


@dataclass
class Located:
    """A store's project and full resource name: what its findings name it by."""

    project: str
    full_name: str

    def fields(self) -> dict[str, Any]:
        return gcp_fields(self.project, self.full_name)

    def __repr__(self) -> str:
        return f"Located({redact_digits(self.project)!r})"


def gcs_object_resource(
    where: Located,
    bucket: str,
    name: str,
    generation: str | None,
    *,
    column: str | None = None,
) -> dict[str, Any]:
    """One Cloud Storage object (and, for a table file, one column of it), masked like an
    S3 object."""
    names = {"bucket": bucket, "object": name}
    if column is not None:
        names["column"] = column
    masked = {k: redact_digits(v) for k, v in names.items()}
    out: dict[str, Any] = {
        "type": "gcs_object",
        "bucket": masked["bucket"],
        "object": masked["object"],
        "generation": str(generation or "null"),
        **where.fields(),
    }
    if column is not None:
        out["column"] = masked["column"]
    if masked != names:
        out["keyMasked"] = True
    return out
