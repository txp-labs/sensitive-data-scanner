"""The no-values rule, in code: masking, the only logger, safe errors.

The scanner runs next to cardholder data, so its own output is held to the
rule its findings follow: counts, names and AWS error names only.

- `redact_digits` masks anything in a string that could be a card number or
  an SSN. Every string the scanner writes (object keys, stream names, error
  names) goes through it.
- `log_event` is the scanner's only way to write a log line: a fixed event
  name, and fields that are numbers, booleans or masked short strings. A test
  fails if any other module prints or logs.
- `error_name` gives an exception's class or AWS error code, never its
  message, which can quote a key or a value. `ScanError` carries only that.
"""

from __future__ import annotations

import json
import re
import sys
import time
from typing import Final

from .engine.rules import luhn_valid

_CARD_RE = re.compile(r"(?<![0-9])(?<![0-9][ -])[0-9](?:[ -]?[0-9]){12,18}(?![ -]?[0-9])")
_SSN_RE = re.compile(r"(?<![0-9])(?<![0-9][ -])[0-9]{3}([ -]?)[0-9]{2}\1[0-9]{4}(?![ -]?[0-9])")
_LONG_RUN = re.compile(r"[0-9]{13,}")


def _mask(m: re.Match[str]) -> str:
    return re.sub(r"[0-9]", "#", m[0])


def redact_digits(s: str) -> str:
    """Mask card-like runs (Luhn-valid, 13-19 digits), SSN-like runs and any run of 13+ digits."""
    s = _CARD_RE.sub(lambda m: _mask(m) if luhn_valid(re.sub(r"[ -]", "", m[0])) else m[0], s)
    s = _SSN_RE.sub(_mask, s)
    return _LONG_RUN.sub(_mask, s)


EVENTS: Final = frozenset(
    {
        "run.start",
        "run.locked",
        "run.done",
        "run.failed",
        "source.start",
        "source.done",
        "source.failed",
        "item.unreadable",
        "finding.gone",
        "state.reset",
        "events.sent",
        "events.failed",
    }
)

LogValue = int | float | bool | str | None
_MAX_VALUE = 200


def safe_fields(fields: dict[str, LogValue]) -> dict[str, LogValue]:
    out: dict[str, LogValue] = {}
    for k, v in fields.items():
        key = re.sub(r"[^A-Za-z0-9_]", "", k)[:40]
        if isinstance(v, str):
            out[key] = redact_digits(v)[:_MAX_VALUE]
        elif v is None or isinstance(v, bool | int | float):
            out[key] = v
        else:  # pragma: no cover - the type forbids it; defend anyway
            out[key] = type(v).__name__
    return out


def log_event(event: str, **fields: LogValue) -> None:
    """Write one JSON log line. The only place the scanner writes a log."""
    if event not in EVENTS:
        raise ValueError("unknown log event")
    line: dict[str, LogValue] = {
        "event": event,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    line.update(safe_fields(fields))
    sys.stdout.write(json.dumps(line, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def error_name(err: BaseException) -> str:
    """The AWS error code or the exception class: never the message."""
    code = None
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code")
    raw = str(code) if code else type(err).__name__
    return re.sub(r"[^A-Za-z0-9._:-]", "", raw)[:80] or "Error"


class ScanError(Exception):
    """A failure the scanner reports: an error name, never a message from below."""

    def __init__(self, name: str) -> None:
        self.error = re.sub(r"[^A-Za-z0-9._:-]", "", name)[:80] or "Error"
        super().__init__(f"scan failed: {self.error}")

    def __repr__(self) -> str:
        return f"ScanError({self.error!r})"
