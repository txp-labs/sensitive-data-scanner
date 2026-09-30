"""`python -m sensitive_data_azure [scan|check]`: the Container Apps job's entry point.

- `scan` (the default): one run (runner.py), then exit. 0 when the findings
  reached every sink, 1 when the configuration is wrong, the run failed or a
  sink failed; 0 as well when another run holds the lock.
- `check`: discovery only. Lists every store and what a run would do with it,
  reads nothing and sends nothing. 0 when every listing worked, 2 when any
  kind could not be listed.

Nothing but the scanner's own JSON log lines is written: the Azure SDK's
logging and warnings are switched off, since its messages can quote a URL, a
resource name or a header.
"""

from __future__ import annotations

import logging
import sys
import warnings

from sensitive_data_core.safety import error_name, log_event

from .clients import Clients
from .config import ConfigError, read_settings
from .runner import discover, run_scan
from .sinks import sinks_for
from .sources.base import Context


def main(argv: list[str] | None = None, clients: Clients | None = None) -> int:
    logging.disable(logging.CRITICAL)
    warnings.simplefilter("ignore")
    args = sys.argv[1:] if argv is None else argv
    mode = args[0] if args else "scan"
    if mode not in ("scan", "check"):
        log_event("run.failed", error="usage")
        return 1
    try:
        settings = read_settings()
    except ConfigError as err:
        log_event("run.failed", error=err.code)
        return 1
    clients = clients or Clients()
    try:
        if mode == "check":
            found = discover(Context(settings, clients))
            return 2 if found.list_errors else 0
        _, failed = run_scan(settings, clients, sinks=sinks_for(settings, clients))
    except Exception as err:  # reported by name only
        log_event("run.failed", error=error_name(err))
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
