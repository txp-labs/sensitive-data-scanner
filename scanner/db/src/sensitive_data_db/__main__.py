"""`python -m sensitive_data_db [scan|check]`: the container's entry point.

- `scan` (the default): one run (runner.py), then exit. 0 when the findings
  reached every sink, 1 when the configuration is wrong or a sink failed.
- `check`: connect to each database and check its user, read nothing, send
  nothing. 0 when every database would be read, 2 when any would not.

Nothing but the scanner's own JSON log lines is written: the drivers' logging
and warnings are switched off, since a driver's message can quote a host, a
user or a statement.
"""

from __future__ import annotations

import logging
import sys
import warnings

from sensitive_data_core.safety import error_name, log_event

from .config import ConfigError, read_settings
from .runner import check_database, run
from .sinks import sinks_for


def main(argv: list[str] | None = None) -> int:
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
    try:
        if mode == "check":
            ready = 0
            for db in settings.databases:
                store, session = check_database(db, settings)
                if session is not None:
                    session.close()
                    ready += 1
                    log_event("source.done", source=store.name, kind=store.kind, scanned=0)
            return 0 if ready == len(settings.databases) else 2
        _, failed = run(settings, sinks_for(settings))
    except Exception as err:  # reported by name only
        log_event("run.failed", error=error_name(err))
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
