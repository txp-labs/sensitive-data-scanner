"""A large object with many findings is read in time linear in its size (#77).

Two costs were quadratic: `utf16_index` counted astral characters in Python over the
whole prefix for every offset, and Presidio's de-duplication compares every result with
every other. A 5.6 MB log with 14,000 findings took 33 s, and a 20 MiB object (the
default `MAX_OBJECT_BYTES`) would take minutes, past a run's time limit. Every value is
made up.
"""

from __future__ import annotations

import datetime as dt
import time

import pytest

import bench_corpus as bc
from sensitive_data_core.detect import analyzer
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.conversation import utf16_index
from sensitive_data_core.scan.item import scan_item_text

DET = Detector(now=dt.date(2026, 9, 29))


def _key(text: str) -> list[tuple[str, str, str, int, int]]:
    a = DET.analyze_text(text)
    return [(d.cls, d.via, d.confidence, d.spans[0].start, d.spans[-1].end) for d in a.detections]


def test_chunked_reading_finds_exactly_what_one_pass_finds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    g = bc.Gen(7)
    text = bc.app_log(g, 300) + bc.access_log(g, 100) + bc.ticket_json(g, 8)
    assert len(text) < analyzer.CHUNK_CHARS
    whole = _key(text)
    assert len(whole) > 50
    monkeypatch.setattr(analyzer, "CHUNK_CHARS", 997)
    assert _key(text) == whole


def test_utf16_offsets_count_astral_characters_before_the_index() -> None:
    text = "a\U0001f44db\U0001f44dc"
    assert [utf16_index(text, i) for i in range(len(text) + 1)] == [0, 1, 3, 4, 6, 7]
    assert utf16_index("plain ascii", 5) == 5
    assert utf16_index("café 1", 5) == 5


def test_a_large_log_with_many_findings_reads_in_linear_time() -> None:
    g = bc.Gen(11)
    small = bc.app_log(g, 4_000)
    large = small * 8
    t0 = time.perf_counter()
    scan_item_text("a.log", small, DET)
    t1 = time.perf_counter()
    item = scan_item_text("b.log", large, DET)
    t2 = time.perf_counter()
    assert sum(f.occurrences for f in item.findings.values()) > 5000
    # Eight times the text: well under the 64x a quadratic read would take.
    assert (t2 - t1) < 20 * max(t1 - t0, 0.05)
