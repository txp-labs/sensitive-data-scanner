"""HTTPS to the vendors: one session, the vendors' rate limits honored, errors by name only.

Every vendor call goes through `Http.call`:

- **Rate limits.** A 429, or a 503 or 504, is retried after the vendor's
  `Retry-After` (seconds or an HTTP date), else after an exponential backoff.
  A wait longer than `max_wait`, or one that would pass the run's deadline,
  raises `Throttled` instead: the source stops where it is and resumes there
  next run (`throttled`). Each wait is logged as `source.throttled` with its
  seconds, nothing else.
- **Errors.** A failed call raises `SaasError`, whose `error_code` is the
  vendor's own code for it (Graph's `error.code`, Slack's `error`, Google's
  `status`), or `Http<status>`; never the vendor's message, which can quote a
  name, an address or content. A vendor's parser (`error_of`) may look at the
  message to tell two failures apart, and never keeps it.
- **Tokens** are added by each vendor's API (`graph.py`), only for that
  vendor's own host.

Tests give `Http` a stubbed session (any object with `request`).
"""

from __future__ import annotations

import email.utils
import re
import time
from collections.abc import Callable
from typing import Any

from sensitive_data_core.safety import log_event

from . import __version__

USER_AGENT = f"sensitive-data-scanner-saas/{__version__}"
TIMEOUT = 60
RETRIES = 5
RETRY_STATUSES = frozenset({429, 503, 504})


class SaasError(Exception):
    """A vendor call failed. `error_code` names why; the message is never kept."""

    error_code = "SaasError"
    status_code = 0

    def __init__(self, code: str, status: int = 0) -> None:
        clean = re.sub(r"[^A-Za-z0-9._:-]", "", code)[:80] or "SaasError"
        super().__init__(clean)
        self.error_code = clean
        self.status_code = status

    def __repr__(self) -> str:
        return f"SaasError({self.error_code!r})"


class Throttled(SaasError):
    """The vendor kept asking the scanner to wait, past what the run can give it."""

    def __init__(self) -> None:
        super().__init__("Throttled", 429)


def plain_error(resp: Any) -> SaasError:
    """A failed response named by its status only."""
    status = int(getattr(resp, "status_code", 0) or 0)
    return SaasError(f"Http{status}", status)


def retry_after(resp: Any, now: float) -> float | None:
    """The vendor's `Retry-After`, in seconds: a number, or an HTTP date."""
    headers = getattr(resp, "headers", None) or {}
    raw = None
    for k, v in dict(headers).items():
        if str(k).lower() == "retry-after":
            raw = str(v).strip()
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    return max(0.0, when.timestamp() - now)


class Http:
    """One session for every vendor call, with the rate limits honored."""

    def __init__(
        self,
        session: Any,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        max_wait: float = 120.0,
        timeout: float = TIMEOUT,
    ) -> None:
        self._session = session
        self._sleep = sleep
        self._clock = clock
        self._wall = wall
        self.max_wait = max_wait
        self._timeout = timeout
        # The run's deadline (the clock's time); a wait past it is `Throttled`.
        self.deadline: float | None = None
        self.throttled = 0

    def __repr__(self) -> str:
        return "Http()"

    def _wait(self, seconds: float) -> None:
        if seconds > self.max_wait or (
            self.deadline is not None and self._clock() + seconds >= self.deadline
        ):
            raise Throttled()
        self.throttled += 1
        log_event("source.throttled", seconds=round(seconds, 1))
        self._sleep(seconds)

    def call(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | list[tuple[str, str]] | None = None,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
        allow_redirects: bool = True,
        error_of: Callable[[Any], SaasError] = plain_error,
        retry_if: Callable[[Any], bool] | None = None,
        timeout: float | None = None,
    ) -> Any:
        """The response of one call, retried on the vendor's rate limits. Raises SaasError."""
        head = {"User-Agent": USER_AGENT, **(headers or {})}
        for attempt in range(RETRIES):
            resp = self._session.request(
                method,
                url,
                params=params,
                headers=head,
                data=data,
                json=json,
                timeout=timeout or self._timeout,
                allow_redirects=allow_redirects,
            )
            status = int(resp.status_code)
            limited = status in RETRY_STATUSES or (retry_if is not None and retry_if(resp))
            if status < 400 and not limited:
                return resp
            if limited or status >= 500:
                if attempt == RETRIES - 1:
                    if limited:
                        raise Throttled()
                    break
                wait = retry_after(resp, self._wall())
                self._wait(wait if wait is not None else float(2**attempt))
                continue
            break
        failed = error_of(resp)
        raise failed
