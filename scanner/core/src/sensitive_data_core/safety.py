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
# A nine-digit run is masked whatever separator follows it: `orders-123456789-1`
# and `rds:db-123456789-2026-09-29` hide the SSN as well as `123456789.txt` does.
_SSN_RE = re.compile(r"(?<![0-9])[0-9]{3}([ -]?)[0-9]{2}\1[0-9]{4}(?![0-9])")
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
        "source.throttled",
        "state.reset",
        "events.sent",
        "events.failed",
        "discovery.done",
        "discovery.failed",
        "source.deferred",
        "source.refused",
        # The object index (#67): written, or not (the next run then decides without it).
        "index.saved",
        "index.failed",
        # How a store is listed changed: it is listed again from the start (#67).
        "source.relist",
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
    """The cloud's error code (AWS's `Error.Code`, Azure's `error_code`) or the exception
    class: never the message."""
    code = None
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code")
    if not code:
        azure = getattr(err, "error_code", None)
        code = azure if isinstance(azure, str) else None
    raw = str(code) if code else type(err).__name__
    return re.sub(r"[^A-Za-z0-9._:-]", "", raw)[:80] or "Error"


KMS_ERRORS: Final = frozenset(
    {
        "KMSAccessDeniedException",
        "KMSDisabledException",
        "KMSInvalidStateException",
        "KMSNotFoundException",
        "KMS.AccessDeniedException",
        "KMS.DisabledException",
        "KMS.KMSInvalidStateException",
        "KMS.NotFoundException",
        "KMS.UnrecognizedClientException",
    }
)


def is_kms_denial(err: BaseException) -> bool:
    """Whether an error is a KMS key the scanner may not use.

    S3 and DynamoDB report a missing `kms:Decrypt` as a plain AccessDenied whose
    message names KMS. The message is only looked at here, never kept or logged.
    """
    name = error_name(err)
    if name in KMS_ERRORS or name.startswith("KMS."):
        return True
    if name not in ("AccessDenied", "AccessDeniedException"):
        return False
    response = getattr(err, "response", None)
    message = ""
    if isinstance(response, dict):
        message = str((response.get("Error") or {}).get("Message") or "")
    return "kms" in message.lower()


class ScanError(Exception):
    """A failure the scanner reports: an error name, never a message from below."""

    def __init__(self, name: str) -> None:
        self.error = re.sub(r"[^A-Za-z0-9._:-]", "", name)[:80] or "Error"
        super().__init__(f"scan failed: {self.error}")

    def __repr__(self) -> str:
        return f"ScanError({self.error!r})"


class Secret:
    """A connection string, a URL with a token in it, or a key: never shown by repr or str."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)
