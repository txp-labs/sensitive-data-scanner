"""The standalone report: a findings document as one HTML page and one CSV file (#117).

Every run can write, next to its findings document, a page a person reads and a
spreadsheet a person filters, with no Mermera and no other tool:

- `report.html`: one self-contained file. Inline CSS, no script, no font, no
  image and no request of any kind (its Content-Security-Policy forbids them),
  readable offline, printable, light and dark. It shows what was scanned and
  what was not, and why (each gap with the setting that would read it), the
  findings by data type, by store and by location, the storage-class inventory
  and cost-to-scan estimate (schema 1.13), the scanner version, the run and the
  pointer to how its code was signed.
- `findings.csv`: one row per finding location: data type, severity, count,
  confidence, store, location, region, first and last seen.

**Never a value.** Both are made from the findings document alone, which holds
no value, and every string taken from it goes through `safety.redact_digits`
again on the way out, so a name that slipped past masking upstream would be
masked here too. `tests/test_no_leak.py` scans both outputs for every planted
card number and SSN, raw, HTML-escaped, entity-encoded and URL-encoded.

The core renders; each runner writes the files where its findings document
goes (AWS: `findings/report.html` and `findings/findings.csv` in the results
bucket). `report_files` is the one call a runner makes.
"""

from __future__ import annotations

import csv
import datetime as _dt
import html
import io
import re
from collections.abc import Iterable, Mapping
from typing import Any

from .safety import redact_digits

REPORT_HTML = "report.html"
FINDINGS_CSV = "findings.csv"
HTML_CONTENT_TYPE = "text/html; charset=utf-8"
CSV_CONTENT_TYPE = "text/csv; charset=utf-8"

REPO_URL = "https://github.com/txp-labs/sensitive-data-scanner"
# The early-access page for Mermera (REPORT_CTA). A placeholder until that page
# exists: Chris confirms the URL before the public launch (#117).
CTA_URL = "https://mermera.com"
CTA_TEXT = "Want this tracked, triaged and mapped to SOC 2 / PCI DSS controls?"
CTA_LINK_TEXT = "Join the Mermera early-access list"

# Where each release's signed Lambda zip and signing.json are (docs/RELEASING.md).
RELEASE_BUCKET_PREFIX = "txp-labs-sensitive-data-scanner"
RELEASE_REGIONS = (
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-2",
)

CLASS_LABELS = {
    "card": "Payment card number",
    "us_ssn": "US Social Security number",
    "us_itin": "US ITIN",
    "dob": "Date of birth",
    "cvv": "Card verification code",
    "pin": "PIN",
    "account_number": "Account number",
    "us_ssn_last4": "SSN, last four digits",
}
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}

# Why a store was not read, in a reader's words. Any other reason is shown as its code.
REASONS = {
    "denied": "left out by DISCOVER_DENY",
    "not_allowed": "not in DISCOVER_ALLOW",
    "self": "the scanner's own store",
    "too_large": "too large to read this way",
    "unsupported": "a kind of store the scanner does not read",
    "unsupported_format": "a format the scanner does not read",
    "kms_access": "the scanner may not use its KMS key",
    "access_denied": "access denied",
    "lake_formation": "governed by Lake Formation",
    "tags_unreadable": "its tags could not be read",
    "budget": "the run's budget ran out first; the next run starts here",
    "error": "an error",
    "export_not_configured": "reading it needs an export, which is not configured",
    "export_pending": "its export is still running",
    "export_failed": "its export failed",
    "no_snapshot": "it has no snapshot to read",
    "pitr_off": "point-in-time recovery is off",
    "read_not_configured": "reading this kind is opt-in, and it is off",
    "paused": "the cluster is paused",
    "no_grant": "the database user can see no table",
    "vpc_only": "reachable only inside a VPC",
    "no_snapshot_export": "no read-only snapshot export",
    "needs_task": "needs a task that is not built",
    "backup_copy": "a backup copy of another store",
    "archived": "archived",
    "live_queue": "a live queue: reading would take its messages",
    "redrive_would_change": "reading would change its redrive",
    "no_s3_destination": "it delivers nowhere the scanner reads",
    "in_memory": "held in memory only",
    "no_read_path": "no read-only way in",
    "network": "its network does not admit the scanner",
    "throttled": "the service asked the scanner to wait",
    "not_implemented": "the setting is on, and its reader is not built yet",
    "vendor_mode": "read by the vendor's own tool (SCAN_MODE)",
    "vendor_not_covered": "the vendor's tool does not cover it (SCAN_MODE)",
}
SKIPS = {
    "audio": "audio",
    "video": "video",
    "image": "images",
    "document": "documents the scanner cannot read",
    "archive": "archives nested too deep, or damaged",
    "binary": "binary files",
    "columnar": "Parquet, ORC or compressed Avro (the container image reads them)",
    "archive_tier": "blobs in the Archive tier",
    "billed_plan": "log tables billed per query",
    "private_log": "private audit logs",
    "encrypted": "encrypted or password-protected files",
    "too_large": "attachments over MAX_OBJECT_BYTES",
    "linked_item": "linked items another store reads",
    "archive_unsupported": "7z archives and unsupported zip methods",
    "pdf_image_only": "scanned PDFs with no text layer",
}

# The page's colors, light and dark. Every text color meets WCAG AA (4.5:1) on both
# backgrounds of its scheme; tests/test_report.py measures it from the rendered CSS.
PALETTE: dict[str, dict[str, str]] = {
    "light": {
        "bg": "#ffffff",
        "surface": "#f6f8fa",
        "fg": "#1f2328",
        "muted": "#59636e",
        "border": "#d1d9e0",
        "link": "#0550ae",
        "high": "#a40e26",
        "medium": "#7d4e00",
        "low": "#59636e",
        "ok": "#1a7f37",
    },
    "dark": {
        "bg": "#0d1117",
        "surface": "#161b22",
        "fg": "#e6edf3",
        "muted": "#9198a1",
        "border": "#3d444d",
        "link": "#4493f8",
        "high": "#ff7b72",
        "medium": "#d29922",
        "low": "#9198a1",
        "ok": "#3fb950",
    },
}
TEXT_COLORS = ("fg", "muted", "link", "high", "medium", "low", "ok")
BACKGROUNDS = ("bg", "surface")

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "base-uri 'none'; form-action 'none'"
)


# ------------------------------------------------------------------ safe text


def text(value: Any) -> str:
    """A string from the findings document, masked again (`redact_digits`)."""
    return redact_digits("" if value is None else str(value))


def esc(value: Any) -> str:
    """A string from the findings document, masked again and HTML-escaped."""
    return html.escape(text(value), quote=True)


def num(n: Any) -> str:
    """A count, with thousands separators (never a long digit run)."""
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return "0"


def size(n: Any) -> str:
    """Bytes, in binary units."""
    try:
        b = float(n)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if b < 1024 or unit == "TiB":
            return f"{b:,.0f} {unit}" if unit == "B" else f"{b:,.1f} {unit}"
        b /= 1024
    return f"{b:,.1f} TiB"  # pragma: no cover - the loop returns


def usd(n: Any) -> str:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "-"
    return f"${v:,.2f}" if v >= 0.01 or v == 0 else "under $0.01"


def when(value: Any) -> str:
    """An ISO time as `YYYY-MM-DD HH:MM UTC`; anything else masked as it is."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        t = _dt.datetime.fromtimestamp(value / 1000, _dt.UTC)  # a log event's ms
        return t.strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        t = _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return text(value)
    if t.tzinfo is not None:
        t = t.astimezone(_dt.UTC)
    return t.strftime("%Y-%m-%d %H:%M UTC")


def label(cls: str) -> str:
    return CLASS_LABELS.get(cls, cls.replace("_", " "))


def reason_text(reason: Any) -> str:
    r = str(reason or "")
    return REASONS.get(r, r.replace("_", " "))


# ------------------------------------------------------------------ where a finding is


def _join(*parts: Any, sep: str = " / ") -> str:
    return sep.join(str(p) for p in parts if p not in (None, ""))


def place(resource: Mapping[str, Any]) -> tuple[str, str, str]:
    """A finding's store kind, store and location within it, from its resource."""
    r = resource
    t = str(r.get("type", ""))
    inner = _join(r.get("archivePath"), r.get("archiveEntry"), sep=" > ")
    column = r.get("column")
    if t == "s3_object":
        cat = r.get("catalog") or {}
        kind = "glue_table" if cat else "s3"
        loc = _join(r.get("key"), inner, f"column {column}" if column else "", sep=" > ")
        return kind, str(r.get("bucket", "")), loc
    if t == "log_event":
        ts = r.get("timestamp")
        at = f"event at {when(ts)}" if isinstance(ts, int) else ""
        return "cloudwatch_logs", str(r.get("logGroup", "")), _join(r.get("logStream"), at)
    if t == "dynamodb_item":
        key = r.get("key")
        keys = (
            ", ".join(f"{k}={v}" for k, v in sorted(key.items()))
            if isinstance(key, Mapping)
            else key
        )
        return "dynamodb", str(r.get("table", "")), _join(keys, r.get("attributePath"))
    if t == "rds_column":
        loc = _join(r.get("database"), r.get("table"), r.get("column"), sep=".")
        return "rds", str(r.get("cluster", "")), loc
    if t == "store_field":
        loc = _join(r.get("database"), r.get("table"), r.get("field"), sep=".")
        return str(r.get("service", "")), str(r.get("store", "")), _join(loc, inner, sep=" > ")
    if t == "blob_object":
        loc = _join(r.get("blob"), inner, f"column {column}" if column else "", sep=" > ")
        return "azure_blob", _join(r.get("account"), r.get("container")), loc
    if t == "azure_file":
        loc = _join(r.get("path"), inner, f"column {column}" if column else "", sep=" > ")
        return "azure_files", _join(r.get("account"), r.get("share")), loc
    if t == "gcs_object":
        loc = _join(r.get("object"), inner, f"column {column}" if column else "", sep=" > ")
        return "gcs", str(r.get("bucket", "")), loc
    if t == "saas_item":
        store = r.get("container") or r.get("channel") or r.get("service")
        item = r.get("name") or r.get("itemId") or str(r.get("itemHash", ""))[:16]
        loc = _join(item, r.get("part"), inner, f"column {column}" if column else "", sep=" > ")
        return _join(r.get("vendor"), r.get("service"), sep=" "), str(store or ""), loc
    others = [f"{k}={v}" for k, v in sorted(r.items()) if k != "type" and isinstance(v, str)]
    return t, "", ", ".join(others)


def where(doc: Mapping[str, Any], resource: Mapping[str, Any]) -> str:
    """The region, subscription, project or site a finding is in."""
    return text(
        doc.get("region")
        or resource.get("subscription")
        or resource.get("project")
        or resource.get("vendor")
        or doc.get("site")
        or ""
    )


# ------------------------------------------------------------------ the CSV

CSV_COLUMNS = (
    "finding_id",
    "data_type",
    "severity",
    "count",
    "occurrences",
    "confidence",
    "store_kind",
    "store",
    "location",
    "region",
    "first_seen",
    "last_seen",
    "at_rest_encryption",
    "source",
    "console_link",
)
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: Any) -> str:
    """A CSV cell: masked, and never read as a formula by a spreadsheet."""
    s = text(value)
    return "'" + s if s.startswith(_FORMULA) else s


_ID = re.compile(r"^[0-9a-f]{32}$")
_URL = re.compile(r"^https://[A-Za-z0-9.-]+/[!-~]*$")


def _id(value: Any) -> str:
    """A finding id: a hash, kept as it is (masking would change it); anything else masked."""
    s = str(value or "")
    return s if _ID.match(s) else text(s)


def _link(value: Any) -> str:
    """A finding's console link as the findings document has it (`findings.link_for` drops
    any link built from a masked name), when it is an https URL; else nothing."""
    s = str(value or "")
    return s if _URL.match(s) and '"' not in s and "<" not in s else ""


def findings_csv(doc: Mapping[str, Any]) -> str:
    """One row per finding location in the document. No values."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for f in _ranked(doc.get("findings") or []):
        res = f.get("resource") or {}
        kind, store, loc = place(res)
        w.writerow(
            [
                _id(f.get("id")),
                _cell(f.get("class")),
                _cell(f.get("severity")),
                int(f.get("count") or 0),
                int(f.get("occurrences") or 0),
                _cell(f.get("confidence")),
                _cell(kind),
                _cell(store),
                _cell(loc),
                _cell(where(doc, res)),
                _cell(f.get("firstSeenAt")),
                _cell(f.get("lastSeenAt")),
                _cell(f.get("atRestEncryption", "")),
                _cell(f.get("source", "scanner")),
                _link(f.get("link")),
            ]
        )
    return out.getvalue()


def _ranked(findings: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_RANK.get(str(f.get("severity")), 3),
            -int(f.get("count") or 0),
            str(f.get("id", "")),
        ),
    )


# ------------------------------------------------------------------ the HTML


def _css() -> str:
    def block(scheme: str) -> str:
        return "".join(f"--{k}:{v};" for k, v in PALETTE[scheme].items())

    return (
        f":root{{color-scheme:light dark;{block('light')}}}"
        f"@media (prefers-color-scheme: dark){{:root{{{block('dark')}}}}}"
        "*{box-sizing:border-box}"
        "body{margin:0;background:var(--bg);color:var(--fg);"
        "font:15px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}"
        "main,header,footer{max-width:72rem;margin:0 auto;padding:0 1rem}"
        "header{padding-top:1.5rem}"
        "h1{font-size:1.75rem;margin:0 0 .25rem}"
        "h2{font-size:1.3rem;margin:2rem 0 .5rem;padding-top:.5rem;"
        "border-top:1px solid var(--border)}"
        "h3{font-size:1.05rem;margin:1.25rem 0 .5rem}"
        "p{margin:.5rem 0}"
        "a{color:var(--link)}"
        "a:focus-visible{outline:2px solid var(--link);outline-offset:2px}"
        ".muted{color:var(--muted)}"
        ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));"
        "gap:.75rem;margin:1rem 0;padding:0;list-style:none}"
        ".cards li{background:var(--surface);border:1px solid var(--border);"
        "border-radius:6px;padding:.75rem}"
        ".cards .n{display:block;font-size:1.5rem;font-weight:600}"
        ".table{overflow-x:auto;margin:.5rem 0 1rem}"
        "table{border-collapse:collapse;width:100%;font-size:.9rem}"
        "caption{text-align:left;font-weight:600;padding:.25rem 0;color:var(--fg)}"
        "th,td{border:1px solid var(--border);padding:.35rem .5rem;text-align:left;"
        "vertical-align:top}"
        "thead th{background:var(--surface)}"
        "td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}"
        "td.loc{overflow-wrap:anywhere;min-width:8rem}"
        ".sev{font-weight:600}"
        ".sev-high{color:var(--high)}.sev-medium{color:var(--medium)}"
        ".sev-low{color:var(--low)}.ok{color:var(--ok)}"
        "code{font-size:.9em}"
        "footer{margin-top:2.5rem;padding-bottom:2rem;border-top:1px solid var(--border)}"
        ".cta{background:var(--surface);border:1px solid var(--border);border-radius:6px;"
        "padding:.75rem 1rem;margin:1rem 0}"
        f"@media print{{:root{{{block('light')}}}"
        "body{font-size:11px}.table{overflow:visible}a{color:var(--fg)}"
        "tr,li{break-inside:avoid}h2{break-after:avoid}}"
    )


def _table(
    caption: str,
    head: list[tuple[str, bool]],
    rows: Iterable[list[str]],
    *,
    empty: str = "None.",
) -> str:
    """A table. `head`: (header text, numeric); cells are already escaped HTML."""
    body = list(rows)
    if not body:
        return f'<p class="muted">{caption}: {empty}</p>'
    ths = "".join(f'<th scope="col"{' class="n"' if n else ""}>{h}</th>' for h, n in head)
    trs = []
    for row in body:
        cells = []
        for i, c in enumerate(row):
            numeric = head[i][1] if i < len(head) else False
            cls = ' class="n"' if numeric else (' class="loc"' if isinstance(c, _Loc) else "")
            cells.append(f"<td{cls}>{c}</td>")
        trs.append("<tr>" + "".join(cells) + "</tr>")
    return (
        f'<div class="table"><table><caption>{caption}</caption>'
        f"<thead><tr>{ths}</tr></thead><tbody>{''.join(trs)}</tbody></table></div>"
    )


class _Loc(str):
    """A cell that may hold a long name: it breaks anywhere."""


def _loc(s: str) -> str:
    return _Loc(s)


def _sev(severity: Any) -> str:
    s = text(severity)
    return f'<span class="sev sev-{html.escape(s)}">{html.escape(s.capitalize())}</span>'


def _code(value: Any) -> str:
    return f"<code>{esc(value)}</code>" if value else ""


def _stores(doc: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return list((doc.get("discovery") or {}).get("stores") or [])


def _coverage(doc: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return list(doc.get("coverage") or [])


def _sum(rows: Iterable[Mapping[str, Any]], key: str) -> int:
    return sum(int(r.get(key) or 0) for r in rows)


def _scope(doc: Mapping[str, Any]) -> str:
    if doc.get("account"):
        return f"AWS account {esc(doc.get('account'))}, {esc(doc.get('region'))}"
    platform = {"azure": "Azure", "gcp": "Google Cloud", "saas": "SaaS", "database": "Databases"}
    p = platform.get(str(doc.get("platform") or ""), esc(doc.get("platform") or ""))
    return f"{p}, site {esc(doc.get('site'))}" if doc.get("site") else p


def _summary(doc: Mapping[str, Any]) -> str:
    cov = _coverage(doc)
    disc = doc.get("discovery") or {}
    stores_total = disc.get("storesTotal", len(cov))
    by_status = disc.get("byStatus") or {}
    scanned_stores = by_status.get("scanned", len(cov) if not disc else 0)
    not_read = sum(int(v) for k, v in by_status.items() if k != "scanned")
    totals = doc.get("totals") or {}
    values = sum(int(v) for v in totals.values())
    cards = [
        (num(doc.get("findingsTotal", 0)), "locations with sensitive data"),
        (num(values), "distinct values found (never shown)"),
        (num(stores_total), "stores in scope"),
        (num(scanned_stores), "stores read"),
        (num(not_read), "stores not read, with the reason"),
        (num(_sum(cov, "scanned")), "items read"),
        (size(_sum(cov, "bytesScanned")), "read"),
    ]
    lis = "".join(f'<li><span class="n">{n}</span>{t}</li>' for n, t in cards)
    return f'<ul class="cards" aria-label="Summary">{lis}</ul>'


def _gaps(cov: list[Mapping[str, Any]]) -> list[list[str]]:
    rows: list[list[str]] = []
    skipped: dict[str, int] = {}
    for c in cov:
        for k, v in (c.get("skipped") or {}).items():
            skipped[k] = skipped.get(k, 0) + int(v)
    for k, v in sorted(skipped.items()):
        rows.append([esc(SKIPS.get(k, k.replace("_", " "))), num(v), _code(k)])
    for key, what in (
        ("unreadable", "could not be read (an error, or deleted mid-run)"),
        ("kmsDenied", "not read: the scanner may not use their KMS key"),
        ("partial", "read only in part (the head of a large item)"),
        ("sampledOut", "left out by sampling (stated, never silent)"),
    ):
        n = _sum(cov, key)
        if n:
            rows.append([esc(what), num(n), ""])
    for key, what in (
        ("notAllowed", "listed and not allowed"),
        ("archived", "in a storage class with no read-only way in"),
    ):
        agg: dict[str, int] = {}
        for c in cov:
            for k, v in (c.get(key) or {}).items():
                agg[k] = agg.get(k, 0) + int(v)
        for k, v in sorted(agg.items()):
            rows.append([esc(f"{what}: {k.replace('_', ' ')}"), num(v), _code(k)])
    return rows


def _scanned(doc: Mapping[str, Any]) -> str:
    cov = _coverage(doc)
    disc = doc.get("discovery") or {}
    parts = []
    by_kind: dict[str, dict[str, int]] = {}
    for c in cov:
        k = by_kind.setdefault(str(c.get("kind", "")), {"n": 0, "l": 0, "s": 0, "b": 0, "bl": 0})
        k["n"] += 1
        k["l"] += int(c.get("listed") or 0)
        k["s"] += int(c.get("scanned") or 0)
        k["b"] += int(c.get("bytesScanned") or 0)
        k["bl"] += 1 if c.get("backlog") else 0
    parts.append(
        _table(
            "Read this run, by kind of store",
            [
                ("Kind", False),
                ("Sources", True),
                ("Listed", True),
                ("Read", True),
                ("Bytes read", True),
                ("More to read next run", True),
            ],
            (
                [esc(k), num(v["n"]), num(v["l"]), num(v["s"]), size(v["b"]), num(v["bl"])]
                for k, v in sorted(by_kind.items())
            ),
            empty="nothing was read",
        )
    )
    if disc:
        statuses = disc.get("byStatus") or {}
        parts.append(
            _table(
                "Stores by status",
                [("Status", False), ("Stores", True)],
                ([esc(k), num(v)] for k, v in sorted(statuses.items())),
            )
        )
        if disc.get("storesTruncated"):
            parts.append(
                f'<p class="muted">The run summary lists {num(len(_stores(doc)))} of '
                f"{num(disc.get('storesTotal'))} stores, those not read first.</p>"
            )
        errors = disc.get("listErrors") or {}
        if errors:
            parts.append(
                _table(
                    "Listings that failed",
                    [("Kind", False), ("Error", False)],
                    ([esc(k), _code(v)] for k, v in sorted(errors.items())),
                )
            )
    parts.append(
        _table(
            "Items listed and not read, by why",
            [("What", False), ("Items", True), ("Code", False)],
            _gaps(cov),
            empty="every item listed was read",
        )
    )
    return "".join(parts)


def _not_read(doc: Mapping[str, Any]) -> str:
    rows = []
    for s in _stores(doc):
        gaps = s.get("gaps") or {}
        if s.get("status") == "scanned" and not gaps and not s.get("toggle"):
            continue
        detail = ", ".join(f"{k} {num(v)}" for k, v in sorted(gaps.items()))
        why = reason_text(s.get("reason")) if s.get("reason") else "read, with gaps"
        rows.append(
            [
                esc(s.get("kind")),
                _loc(esc(s.get("name"))),
                esc(s.get("status")),
                esc(why) + (f' <span class="muted">({esc(detail)})</span>' if detail else ""),
                _code(s.get("toggle")) or '<span class="muted">-</span>',
            ]
        )
    if not (doc.get("discovery") or {}):
        return (
            '<p class="muted">Discovery was off (<code>DISCOVER</code>), so only the stores '
            "named in the configuration were read; turn it on to list every store.</p>"
        )
    return _table(
        "Stores not read, or read with gaps",
        [
            ("Kind", False),
            ("Store", False),
            ("Status", False),
            ("Why", False),
            ("Setting that would read it", False),
        ],
        rows,
        empty="every store in scope was read",
    )


def _changed(doc: Mapping[str, Any]) -> str:
    """(1.14, #139) What the scanner changed in the tenant: the Slack channels it joined.
    Nothing at all when it changed nothing, the one case before 1.14."""
    rows = []
    for s in _stores(doc):
        joined = s.get("joinedByScanner")
        if not isinstance(joined, dict):
            continue
        rows.append(
            [
                _loc(esc(s.get("name"))),
                _code(joined.get("channelId")),
                esc(joined.get("action")),
                esc(joined.get("joinedAt")),
            ]
        )
    if not rows:
        return ""
    return (
        '<h2 id="changed">What the scanner changed</h2>'
        "<p>With <code>SLACK_JOIN_PUBLIC_CHANNELS</code> on, the scanner joined these public "
        "Slack channels before reading them. It posted nothing; Slack shows each join to "
        "the channel's members and records it in its audit logs.</p>"
        + _table(
            "Slack channels joined by the scanner",
            [("Channel", False), ("Channel id", False), ("Change", False), ("When", False)],
            rows,
        )
    )


def _by_type(doc: Mapping[str, Any]) -> str:
    findings = list(doc.get("findings") or [])
    totals = doc.get("totals") or {}
    by: dict[str, dict[str, int]] = {}
    sev: dict[str, str] = {}
    for f in findings:
        c = str(f.get("class", ""))
        b = by.setdefault(c, {"loc": 0, "occ": 0})
        b["loc"] += 1
        b["occ"] += int(f.get("occurrences") or 0)
        sev[c] = str(f.get("severity", ""))
    classes = sorted(
        set(by) | set(totals), key=lambda c: (_SEVERITY_RANK.get(sev.get(c, ""), 3), c)
    )
    return _table(
        "Findings by data type",
        [
            ("Data type", False),
            ("Severity", False),
            ("Locations", True),
            ("Distinct values", True),
            ("Occurrences", True),
        ],
        (
            [
                f"{esc(label(c))} {_code(c)}",
                _sev(sev.get(c, "")) if c in sev else "",
                num(by.get(c, {}).get("loc", 0)),
                num(totals.get(c, 0)),
                num(by.get(c, {}).get("occ", 0)),
            ]
            for c in classes
        ),
        empty="no sensitive data was found",
    )


def _by_store(doc: Mapping[str, Any]) -> str:
    agg: dict[tuple[str, str], dict[str, Any]] = {}
    for f in doc.get("findings") or []:
        kind, store, _ = place(f.get("resource") or {})
        a = agg.setdefault((kind, store), {"loc": 0, "values": 0, "classes": set()})
        a["loc"] += 1
        a["values"] += int(f.get("count") or 0)
        a["classes"].add(str(f.get("class", "")))
    ranked = sorted(agg.items(), key=lambda kv: (-kv[1]["values"], kv[0]))
    return _table(
        "Findings by store",
        [
            ("Kind", False),
            ("Store", False),
            ("Data types", False),
            ("Locations", True),
            ("Values", True),
        ],
        (
            [
                esc(k),
                _loc(esc(s)),
                esc(", ".join(label(c) for c in sorted(a["classes"]))),
                num(a["loc"]),
                num(a["values"]),
            ]
            for (k, s), a in ranked
        ),
        empty="no sensitive data was found",
    )


def _findings(doc: Mapping[str, Any]) -> str:
    findings = _ranked(doc.get("findings") or [])
    rows = []
    for f in findings:
        res = f.get("resource") or {}
        kind, store, loc = place(res)
        link = _link(f.get("link"))
        open_ = (
            f'<a href="{html.escape(link, quote=True)}" rel="noreferrer noopener">console</a>'
            if link
            else ""
        )
        rows.append(
            [
                _sev(f.get("severity")),
                esc(label(str(f.get("class", "")))),
                esc(kind),
                _loc(esc(store)),
                _loc(esc(loc)),
                num(f.get("count")),
                esc(f.get("confidence")),
                esc(f.get("atRestEncryption", "")),
                esc(when(f.get("firstSeenAt"))),
                esc(when(f.get("lastSeenAt"))),
                open_,
            ]
        )
    note = ""
    if doc.get("findingsTruncated"):
        note = (
            f'<p class="muted">The findings document holds the {num(len(findings))} most '
            f"severe and largest of {num(doc.get('findingsTotal'))} findings; so do this "
            "page and findings.csv.</p>"
        )
    return note + _table(
        "Every finding, most severe first",
        [
            ("Severity", False),
            ("Data type", False),
            ("Kind", False),
            ("Store", False),
            ("Location", False),
            ("Values", True),
            ("Confidence", False),
            ("Encryption at rest", False),
            ("First seen", False),
            ("Last seen", False),
            ("Open", False),
        ],
        rows,
        empty="no sensitive data was found",
    )


def _storage(doc: Mapping[str, Any]) -> str:
    rows = []
    total = 0.0
    for s in _stores(doc):
        classes = s.get("storageClasses") or {}
        est = s.get("costEstimate") or {}
        for cls, c in sorted(classes.items()):
            by_class = est.get("byClass") or {}
            rows.append(
                [
                    esc(s.get("kind")),
                    _loc(esc(s.get("name"))),
                    esc(cls),
                    num(c.get("objects")),
                    size(c.get("bytes")),
                    '<span class="ok">yes</span>'
                    if c.get("read")
                    else esc("no: " + reason_text(c.get("reason"))),
                    _code(c.get("toggle")),
                    usd(by_class[cls]) if cls in by_class else '<span class="muted">-</span>',
                ]
            )
        if est:
            total += float(est.get("estimatedToScanUsd") or 0)
    if not rows:
        return (
            '<p class="muted">No object store reported a storage-class inventory this run '
            "(it is taken from a complete listing pass).</p>"
        )
    lead = (
        f"<p>Reading every object once in the classes read now would cost about "
        f"<strong>{usd(total)}</strong> in retrieval and request fees, on your own bill "
        "(list prices, per the dated table in the scanner; Standard classes have no "
        'retrieval fee). <a href="'
        f'{REPO_URL}/blob/main/docs/COST.md#reading-cold-storage-classes">How it is '
        "estimated</a>.</p>"
    )
    return lead + _table(
        "Objects by storage class",
        [
            ("Kind", False),
            ("Store", False),
            ("Class", False),
            ("Objects", True),
            ("Size", True),
            ("Read", False),
            ("Setting", False),
            ("Cost to read once", True),
        ],
        rows,
    )


def _settings(doc: Mapping[str, Any]) -> str:
    src = doc.get("settingsSource") or {}
    if not src:
        return ""
    rows = [
        [
            _code(k),
            esc(v.get("value")),
            esc(v.get("source")),
            esc(f"needs {v.get('parameter')}" if v.get("gate") else ""),
        ]
        for k, v in sorted(src.items())
        if isinstance(v, Mapping)
    ]
    return '<h2 id="settings">Settings this run used</h2>' + _table(
        "Settings and where each came from",
        [("Setting", False), ("Value", False), ("From", False), ("Note", False)],
        rows,
    )


def _provenance(doc: Mapping[str, Any]) -> str:
    version = text(doc.get("scannerVersion"))
    v = html.escape(version)
    region = str(doc.get("region") or "")
    rows = [
        ("Scanner version", f"<code>{v}</code>"),
        ("Detection spec", f"<code>{esc(doc.get('specVersion'))}</code>"),
        (
            "Findings schema",
            f"<code>{esc(doc.get('schema'))}</code> {esc(doc.get('schemaVersion'))}",
        ),
        ("Run", f"<code>{esc(doc.get('runId'))}</code>"),
        ("Started", esc(when(doc.get("startedAt")))),
        ("Finished", esc(when(doc.get("finishedAt")))),
        ("Scope", _scope(doc)),
    ]
    mode = doc.get("scanMode") or {}
    if mode:
        rows.append(("Mode", esc(", ".join(f"{k}: {m}" for k, m in sorted(mode.items())))))
    dl = "".join(f'<tr><th scope="row">{k}</th><td>{d}</td></tr>' for k, d in rows)
    release = f"{REPO_URL}/releases/tag/v{html.escape(version, quote=True)}"
    verify = f"{REPO_URL}/blob/main/docs/RELEASING.md#verifying-a-release"
    signing = ""
    if region in RELEASE_REGIONS and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        url = (
            f"https://{RELEASE_BUCKET_PREFIX}-{region}.s3.{region}.amazonaws.com/"
            f"releases/{version}/signing.json"
        )
        signing = (
            f' The Lambda zip for {esc(region)} was signed with AWS Signer: <a href="{url}">'
            f"releases/{v}/signing.json</a> names the signing profile version your "
            "function's code signing configuration can enforce."
        )
    return (
        '<div class="table"><table><caption>This run</caption>'
        f"<tbody>{dl}</tbody></table></div>"
        f'<p>The code: <a href="{release}">release v{v}</a>. Every image is signed with '
        f'cosign and carries a signed SBOM; <a href="{verify}">how to verify a release</a>.'
        f"{signing}</p>"
    )


def report_html(doc: Mapping[str, Any], *, cta: bool = True) -> str:
    """The findings document as one self-contained, printable HTML page. No values."""
    title = f"Sensitive data report: {_scope(doc)}"
    cta_html = (
        f'<aside class="cta" aria-label="Mermera"><p>{CTA_TEXT} '
        f'<a href="{CTA_URL}">{CTA_LINK_TEXT}</a>.</p></aside>'
        if cta
        else ""
    )
    body = (
        "<header>"
        "<h1>Sensitive data report</h1>"
        f'<p class="muted">{_scope(doc)}. Run <code>{esc(doc.get("runId"))}</code>, '
        f"finished {esc(when(doc.get('finishedAt')))}, scanner "
        f"{esc(doc.get('scannerVersion'))}.</p>"
        "<p>Where card numbers, Social Security numbers and other sensitive data were "
        "found: the store, the location, the kind and how many. <strong>Findings only: "
        "this report never shows a value.</strong></p>"
        "</header><main>"
        '<h2 id="summary">Summary</h2>'
        f"{_summary(doc)}"
        '<h2 id="scanned">What was scanned</h2>'
        f"{_scanned(doc)}"
        '<h2 id="not-read">What was not read, and why</h2>'
        "<p>A store or item left unread is listed with its reason and, where a setting "
        "decides it, the setting that would read it "
        f'(<a href="{REPO_URL}/blob/main/docs/limitations.md">every setting and its '
        "default</a>).</p>"
        f"{_not_read(doc)}"
        f"{_changed(doc)}"
        '<h2 id="by-type">Findings by data type</h2>'
        f"{_by_type(doc)}"
        '<h2 id="by-store">Findings by store</h2>'
        f"{_by_store(doc)}"
        '<h2 id="findings">Findings by location</h2>'
        "<p>The same rows are in <code>findings.csv</code>, next to this page. "
        "A console link opens the location in your own account, with your own access.</p>"
        f"{_findings(doc)}"
        '<h2 id="storage">Storage classes and the cost to scan</h2>'
        f"{_storage(doc)}"
        f"{_settings(doc)}"
        '<h2 id="about">About this run</h2>'
        f"{_provenance(doc)}"
        "</main><footer>"
        f"{cta_html}"
        '<p class="muted">Made by <a href="'
        f'{REPO_URL}">sensitive-data-scanner</a>, open source under the Apache License '
        "2.0, provided as is, without warranty. It ran in your own environment, read-only; "
        f'nothing left it but findings. Feedback: <a href="{REPO_URL}/issues">GitHub '
        "issues</a>.</p>"
        "</footer>"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">'
        '<meta name="referrer" content="no-referrer">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        f"<title>{title}</title><style>{_css()}</style></head>"
        f"<body>{body}</body></html>\n"
    )


def report_files(doc: Mapping[str, Any], *, cta: bool = True) -> list[tuple[str, bytes, str]]:
    """The files a runner writes next to its findings document: (name, bytes, content type)."""
    return [
        (REPORT_HTML, report_html(doc, cta=cta).encode(), HTML_CONTENT_TYPE),
        (FINDINGS_CSV, findings_csv(doc).encode(), CSV_CONTENT_TYPE),
    ]
