"""Tables to per-column findings: Parquet, ORC, Avro, and CSV or JSON lines read by a catalog.

A table is read in batches of rows. Each column's cells are read with the
column's own name as context (not the other columns': a `customer_id`
column must not suppress the card number next to it), and a finding names
the column; its offsets carry the exact cell as `/<row>/<column>`.

- **Scalar cells** (text, integers, decimals, dates, text stored as bytes)
  of one column in one batch are read together, one cell per line, as a
  CSV column is. A detection that would cross two cells is dropped.
- **Nested cells** (structs, lists, maps) are read leaf by leaf, like JSON.
- Floats, booleans, times and binary that is not text are not read: a card
  number stored as a float has lost its digits.

Parquet and ORC need pyarrow, which the container image carries and the
Lambda zip does not; `pyarrow_available()` says which build this is. Avro is
read by `avro.py`. Values exist only in memory while a batch is scanned.
"""

from __future__ import annotations

import bisect
import csv
import datetime as _dt
import decimal
import io
import itertools
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import IO, Any

from ..detect.analyzer import Analysis, Detector
from ..detect.enhancer import humanize
from ..engine.conversation import utf16_index
from ..findings import Offset
from .avro import AvroReader
from .item import _HAS_CANDIDATE, REDACTION_MARKER, ItemResult, _Collector, _json_leaves

COLUMNAR_EXT = {"parquet": "parquet", "parq": "parquet", "orc": "orc", "avro": "avro"}
MAGIC = ((b"PAR1", "parquet"), (b"ORC", "orc"), (b"Obj\x01", "avro"))
BATCH_ROWS = 500
MAX_CELL_CHARS = 4096
MAX_COLUMNS = 2000


def pyarrow_available() -> bool:
    try:
        import pyarrow  # noqa: PLC0415 - optional: the container image only
        import pyarrow.orc  # noqa: PLC0415
        import pyarrow.parquet  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def columnar_kind(key: str) -> str | None:
    """`parquet`, `orc` or `avro` by the key's extension (`x.snappy.parquet`, `x.gz.parquet`)."""
    base = key.rsplit("/", 1)[-1].lower()
    if "." not in base:
        return None
    return COLUMNAR_EXT.get(base.rsplit(".", 1)[1])


def sniff(head: bytes) -> str | None:
    """A columnar format by its magic bytes, for keys with no extension (Spark `part-00000`)."""
    for magic, kind in MAGIC:
        if head.startswith(magic):
            return kind
    return None


def needs_pyarrow(kind: str) -> bool:
    return kind in ("parquet", "orc")


@dataclass
class TableResult:
    """Findings per column for one table object."""

    format: str
    by_column: dict[str, ItemResult] = field(default_factory=dict)
    rows: int = 0
    partial: bool = False
    redaction_markers: int = 0
    test_values: int = 0
    suppressed: int = 0
    # (1.10, #67) Set when the table was read again though unchanged: what its findings say
    # about why (`rescanReason`, `rescanClasses`).
    rescan: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        # Column names come from the account and may hold a value: counts only.
        classes = sorted({c for r in self.by_column.values() for c in r.findings})
        return (
            f"TableResult(format={self.format!r}, columns={len(self.by_column)}, "
            f"classes={classes!r}, rows={self.rows}, partial={self.partial})"
        )


def _cell_text(v: Any) -> str | None:
    if v is None or isinstance(v, bool | float):
        return None
    if isinstance(v, str):
        return v[:MAX_CELL_CHARS]
    if isinstance(v, int | decimal.Decimal):
        return str(v)
    if isinstance(v, _dt.datetime):
        return v.isoformat()
    if isinstance(v, _dt.date):
        return v.isoformat()
    if isinstance(v, bytes | bytearray | memoryview):
        try:
            text = bytes(v[:MAX_CELL_CHARS]).decode("utf-8")
        except UnicodeDecodeError:
            return None
        return text if text.isprintable() else None
    return None


def _pointer_escape(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")


class TableScanner:
    """Collects per-column findings over the batches of one table object."""

    def __init__(self, fmt: str, detector: Detector) -> None:
        self.result = TableResult(fmt)
        self.detector = detector
        self.collectors: dict[str, _Collector] = {}

    def _collector(self, column: str) -> _Collector:
        return self.collectors.setdefault(column, _Collector(self.result.format))

    def batch(self, columns: list[str], values: dict[str, list[Any]], first_row: int) -> None:
        columns = columns[:MAX_COLUMNS]
        n = 0
        for col in columns:
            cells = values.get(col) or []
            n = max(n, len(cells))
            self._column(col, cells, first_row)
        self.result.rows = max(self.result.rows, first_row + n)

    def _column(self, col: str, cells: list[Any], first_row: int) -> None:
        context = [humanize(col)]
        texts: list[str] = []
        rows: list[int] = []
        starts: list[int] = []
        pos = 0
        for i, v in enumerate(cells):
            if isinstance(v, dict | list | tuple):
                self._nested(col, v, first_row + i)
                continue
            text = _cell_text(v)
            if text is None:
                continue
            self.result.redaction_markers += len(REDACTION_MARKER.findall(text))
            if not _HAS_CANDIDATE.search(text):
                continue
            starts.append(pos)
            texts.append(text)
            rows.append(first_row + i)
            pos += len(text) + 1
        if not texts:
            return
        chunk = "\n".join(texts)
        analysis = self.detector.analyze_text(chunk, context)
        self.result.test_values += analysis.test_values
        self.result.suppressed += analysis.suppressed
        kept = []
        for d in analysis.detections:
            cells_of = {bisect.bisect_right(starts, sp.start) - 1 for sp in d.spans}
            if len(cells_of) != 1:
                continue
            k = cells_of.pop()
            if all(sp.end <= starts[k] + len(texts[k]) for sp in d.spans):
                kept.append((d, k))
        if not kept:
            return
        by_cell = {id(d): k for d, k in kept}

        def offsets(d: Any) -> list[Offset]:
            k = by_cell[id(d)]
            text = texts[k]
            pointer = f"/{rows[k]}/{_pointer_escape(col)}"
            return [
                Offset(
                    utf16_index(text, sp.start - starts[k]),
                    utf16_index(text, sp.end - starts[k]),
                    pointer,
                )
                for sp in d.spans
            ]

        self._collector(col).add(Analysis([d for d, _ in kept]), offsets)

    def _nested(self, col: str, v: Any, row: int) -> None:
        collector = self._collector(col)
        before = (collector.result.test_values, collector.result.suppressed)
        doc = json.loads(json.dumps(v, default=_json_default))
        _json_leaves(collector, self.detector, doc, f"/{row}/{_pointer_escape(col)}")
        self.result.test_values += collector.result.test_values - before[0]
        self.result.suppressed += collector.result.suppressed - before[1]
        collector.result.test_values, collector.result.suppressed = before
        collector.result.format = self.result.format

    def finish(self) -> TableResult:
        for col, c in self.collectors.items():
            self.result.redaction_markers += c.result.redaction_markers
            c.result.redaction_markers = 0
            if c.result.findings:
                self.result.by_column[col] = c.result
        return self.result


def _json_default(v: Any) -> Any:
    text = _cell_text(v)
    return text if text is not None else None


def _batches_of(
    rows: Iterable[dict[str, Any]], columns: list[str]
) -> Iterator[dict[str, list[Any]]]:
    batch: dict[str, list[Any]] = {c: [] for c in columns}
    n = 0
    for r in rows:
        for c in columns:
            batch[c].append(r.get(c) if isinstance(r, dict) else None)
        n += 1
        if n == BATCH_ROWS:
            yield batch
            batch = {c: [] for c in columns}
            n = 0
    if n:
        yield batch


def scan_rows(
    fmt: str,
    columns: list[str],
    rows: Iterable[dict[str, Any]],
    detector: Detector,
    max_rows: int,
) -> TableResult:
    """Rows as dicts (Avro records, catalog CSV or JSON lines), up to `max_rows`."""
    scanner = TableScanner(fmt, detector)
    first = 0
    it = iter(rows)
    for batch in _batches_of(itertools.islice(it, max_rows), columns):
        scanner.batch(columns, batch, first)
        first += len(next(iter(batch.values()), []))
    if first >= max_rows and next(it, None) is not None:
        scanner.result.partial = True
    return scanner.finish()


def scan_parquet(f: IO[bytes], detector: Detector, max_rows: int) -> TableResult:
    import pyarrow.parquet as pq  # noqa: PLC0415 - optional: the container image only

    pf = pq.ParquetFile(f, pre_buffer=False)
    scanner = TableScanner("parquet", detector)
    columns = list(pf.schema_arrow.names)
    first = 0
    # One row group at a time: a reader that iterates batches may fetch every
    # row group up front, which would read the whole file.
    for i in range(pf.num_row_groups):
        group = pf.read_row_group(i)
        for start in range(0, group.num_rows, BATCH_ROWS):
            take = group.slice(start, min(BATCH_ROWS, max(0, max_rows - first)))
            scanner.batch(columns, take.to_pydict(), first)
            first += take.num_rows
            if first >= max_rows:
                break
        if first >= max_rows:
            break
    scanner.result.partial = pf.metadata.num_rows > first
    return scanner.finish()


def scan_orc(f: IO[bytes], detector: Detector, max_rows: int) -> TableResult:
    from pyarrow import orc  # noqa: PLC0415 - optional: the container image only

    of = orc.ORCFile(f)
    scanner = TableScanner("orc", detector)
    columns = list(of.schema.names)
    first = 0
    for i in range(of.nstripes):
        stripe = of.read_stripe(i)
        for start in range(0, stripe.num_rows, BATCH_ROWS):
            take = stripe.slice(start, min(BATCH_ROWS, max(0, max_rows - first)))
            scanner.batch(columns, take.to_pydict(), first)
            first += take.num_rows
            if first >= max_rows:
                break
        if first >= max_rows:
            break
    scanner.result.partial = of.nrows > first
    return scanner.finish()


def scan_avro(
    f: IO[bytes], detector: Detector, max_rows: int, pyarrow_codecs: bool = True
) -> TableResult:
    reader = AvroReader(f, pyarrow_codecs=pyarrow_codecs)
    fields = reader.fields
    records = (r if isinstance(r, dict) else {"value": r} for r in reader)
    return scan_rows("avro", fields, records, detector, max_rows)


def scan_table(
    kind: str, f: IO[bytes], detector: Detector, max_rows: int, pyarrow_ok: bool = True
) -> TableResult:
    if kind == "parquet":
        return scan_parquet(f, detector, max_rows)
    if kind == "orc":
        return scan_orc(f, detector, max_rows)
    return scan_avro(f, detector, max_rows, pyarrow_codecs=pyarrow_ok)


def csv_rows(
    text: str, columns: list[str], delimiter: str = ",", skip_header: int = 0
) -> Iterator[dict[str, Any]]:
    """A catalog's CSV (no header needed): each row mapped to the catalog's columns."""
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    for i, row in enumerate(reader):
        if i < skip_header:
            continue
        yield dict(zip(columns, row, strict=False))


def json_rows(text: str) -> tuple[list[str], list[dict[str, Any]]]:
    """JSON lines (or one JSON array) as rows; the columns are the top-level keys seen."""
    rows: list[dict[str, Any]] = []
    t = text.strip()
    if t.startswith("["):
        try:
            data = json.loads(t)
        except ValueError:
            data = []
        rows = [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
    else:
        for raw in text.splitlines():
            line = raw.strip()
            if not line.startswith("{"):
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict):
                rows.append(r)
    columns = list(dict.fromkeys(k for r in rows for k in r))
    return columns, rows


def zstd_text(data: bytes, limit: int) -> bytes:
    """A zstd stream, inflated up to `limit` bytes (pyarrow)."""
    import pyarrow as pa  # noqa: PLC0415 - optional: the container image only

    stream = pa.CompressedInputStream(pa.BufferReader(data), "zstd")
    out: bytes = stream.read(limit)
    return out
