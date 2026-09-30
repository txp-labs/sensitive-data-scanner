"""Where the SaaS scanner's findings go: the core's signed HTTPS push, and a file.

- **HTTPS, signed** (`FINDINGS_HTTPS_URL`): the core's `push.HttpsSink`, each
  part of the document POSTed with `X-SDS-Signature` (docs/DATABASES.md,
  Verifying a push). This is how findings reach Mermera: only findings, never
  a value.
- **A file** (`FINDINGS_FILE`): the whole document, written atomically.

Neither the URL nor the key is logged.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sensitive_data_core.push import FindingsSink, HttpsSink

from . import __version__
from .config import Settings


class FileSink:
    """The whole document to a file on a mounted volume, replaced atomically."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def __repr__(self) -> str:
        return "FileSink()"

    def push(self, document: dict[str, Any]) -> int:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(document, indent=2) + "\n")
        os.replace(tmp, self.path)
        return 1


def sinks_for(settings: Settings) -> list[FindingsSink]:
    out: list[FindingsSink] = []
    if settings.https_url is not None and settings.hmac_key is not None:
        out.append(
            HttpsSink(
                settings.https_url,
                settings.hmac_key,
                user_agent=f"sensitive-data-scanner-saas/{__version__}",
            )
        )
    if settings.findings_file:
        out.append(FileSink(settings.findings_file))
    return out
