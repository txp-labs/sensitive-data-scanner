"""The accuracy benchmark: precision, recall and F1 per class and confidence.

Two runners read the corpus (`bench_corpus.py`):

- **objects**: every document through the full reader path, as a bucket's object is
  read: `read_object` (sniffing, archives, PDF, Office, Parquet, JSON, CSV, text, the
  transcript parsers) and `record`, which writes the findings. Counts come from the
  findings' `confidenceCounts`, exactly what a consumer sees.
- **conversation**: every conversation in the corpus, as its parser reads it, through
  the spec's conversation engine (`classify`) directly: what Stugum's call engine, which
  implements the same spec, would see.

**Scoring.** Per document and class, the detected occurrences are matched to the truth
by count: `tp = min(truth, detected)`, `fp = detected - tp`, `fn = truth - tp`. At a
confidence threshold, only detections at that confidence or above count (`low` is
every detection; `high` only the high ones). A miss and a false positive of one class in
one document cancel under this scoring, so the hard-negative documents, which hold no
positives, are what name the false-positive sources.

    uv run python tests/bench_score.py            # print the report
    uv run python tests/bench_score.py --check    # fail on a regression past the baseline
    uv run python tests/bench_score.py --update   # write the baseline (after a real change)

The baseline is `benchmark/baseline.json` at the repository root. `--check` fails when
any class's precision, recall or F1, at any threshold, in either runner, drops more
than `TOLERANCE` below it, or when any output holds a value from the corpus.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bench_corpus import NOW, SPEC, Doc, build_corpus
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.conversation import classify
from sensitive_data_core.findings import Coverage
from sensitive_data_core.scan.objects import read_object, record

BASELINE = Path(__file__).resolve().parents[2] / "benchmark" / "baseline.json"
TOLERANCE = 0.01
LEVELS = ("low", "medium", "high")
RANK = {"low": 0, "medium": 1, "high": 2}
CLASSES = ("card", "us_ssn", "us_itin", "dob", "cvv", "pin", "account_number", "us_ssn_last4")
# The classes stored text can hold without a prompt; the others are found only after one.
STORED_CLASSES = ("card", "us_ssn", "us_itin", "dob")


@dataclass
class Tally:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def add(self, truth: int, found: int) -> None:
        hit = min(truth, found)
        self.tp += hit
        self.fp += found - hit
        self.fn += truth - hit

    def scores(self) -> dict[str, float | int]:
        p = self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0
        r = self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
                "tp": self.tp, "fp": self.fp, "fn": self.fn}  # fmt: skip


@dataclass
class RunnerResult:
    # class -> level -> tally
    tallies: dict[str, dict[str, Tally]] = field(
        default_factory=lambda: {c: {lv: Tally() for lv in LEVELS} for c in CLASSES}
    )
    # (class, category) -> false positives / misses at the lowest threshold
    fp_sources: Counter[tuple[str, str]] = field(default_factory=Counter)
    fn_sources: Counter[tuple[str, str]] = field(default_factory=Counter)
    docs: int = 0
    leaks: list[str] = field(default_factory=list)

    def score(self, doc: Doc, found: Counter[tuple[str, str]]) -> None:
        self.docs += 1
        for cls in CLASSES:
            truth = doc.truth.get(cls, 0)
            for level in LEVELS:
                n = sum(
                    v for (c, conf), v in found.items() if c == cls and RANK[conf] >= RANK[level]
                )
                self.tallies[cls][level].add(truth, n)
                if level == "low":
                    hit = min(truth, n)
                    if n - hit:
                        self.fp_sources[(cls, doc.category)] += n - hit
                    if truth - hit:
                        self.fn_sources[(cls, doc.category)] += truth - hit

    def as_json(self) -> dict[str, Any]:
        return {
            cls: {lv: self.tallies[cls][lv].scores() for lv in LEVELS}
            for cls in CLASSES
            if any(self.tallies[cls]["low"].scores()[k] for k in ("tp", "fp", "fn"))
        }


def _leaks(doc: Doc, blob: str) -> list[str]:
    return [f"{doc.name}: a planted value" for v in doc.values if v in blob]


def _resource(name: str) -> Callable[[str | None], dict[str, Any]]:
    def resource(column: str | None) -> dict[str, Any]:
        return {"key": name, "column": column or ""}

    return resource


def run_objects(docs: list[Doc], detector: Detector) -> RunnerResult:
    out = RunnerResult()
    for doc in docs:
        data = doc.data

        def fetch(start: int, end: int, data: bytes = data) -> bytes:
            return data[start : end + 1]

        got = read_object(
            doc.name,
            len(data),
            fetch,
            detector,
            max_object_bytes=64 * 1024**2,
            max_inflated_bytes=256 * 1024**2,
            max_rows=1_000_000,
            columnar=True,
        )
        cov = Coverage("s3", "benchmark")
        findings = record(
            got,
            cov,
            resource_for=_resource(doc.name),
            link=None,
            seen_at="2026-09-29T00:00:00Z",
        )
        found: Counter[tuple[str, str]] = Counter()
        for f in findings or []:
            for conf, n in f["confidenceCounts"].items():
                found[(f["class"], conf)] += n
        blob = json.dumps(findings) + json.dumps(cov.as_json()) + repr(got)
        out.leaks += _leaks(doc, blob)
        out.score(doc, found)
    return out


def run_conversations(docs: list[Doc]) -> RunnerResult:
    out = RunnerResult()
    for doc in docs:
        if not doc.conversations:
            continue
        found: Counter[tuple[str, str]] = Counter()
        for turns in doc.conversations:
            result = classify(SPEC, turns, NOW)
            for m in result.matches:
                found[(m.cls, m.confidence)] += 1
            out.leaks += _leaks(doc, repr(result.matches) + repr(result.excluded))
        out.score(doc, found)
    return out


def run() -> dict[str, RunnerResult]:
    docs = build_corpus()
    detector = Detector(now=NOW)
    return {"objects": run_objects(docs, detector), "conversation": run_conversations(docs)}


def baseline_json(results: dict[str, RunnerResult]) -> dict[str, Any]:
    return {
        "note": "Written by tests/bench_score.py --update. Do not edit by hand.",
        "specVersion": SPEC.spec_version,
        "tolerance": TOLERANCE,
        "runners": {name: r.as_json() for name, r in results.items()},
    }


def regressions(current: dict[str, Any], base: dict[str, Any]) -> list[str]:
    out = []
    for runner, classes in base["runners"].items():
        for cls, levels in classes.items():
            for level, scores in levels.items():
                now = current["runners"].get(runner, {}).get(cls, {}).get(level)
                for metric in ("precision", "recall", "f1"):
                    was = float(scores[metric])
                    got = float(now[metric]) if now else 0.0
                    if got < was - TOLERANCE:
                        out.append(f"{runner} {cls} @{level} {metric}: {was:.3f} -> {got:.3f}")
    return out


def report(results: dict[str, RunnerResult]) -> str:
    lines = []
    for name, r in results.items():
        lines.append(f"### Runner: {name} ({r.docs} documents)\n")
        lines.append("| Class | Threshold | Precision | Recall | F1 | TP | FP | FN |")
        lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
        for cls, levels in r.as_json().items():
            for level in LEVELS:
                s = levels[level]
                lines.append(
                    f"| `{cls}` | {level} | {s['precision']:.3f} | {s['recall']:.3f} | "
                    f"{s['f1']:.3f} | {s['tp']} | {s['fp']} | {s['fn']} |"
                )
        lines.append("")
        if r.fp_sources:
            lines.append("False positives by document category (every confidence):\n")
            for (cls, cat), n in r.fp_sources.most_common():
                lines.append(f"- `{cls}` in `{cat}`: {n}")
            lines.append("")
        if r.fn_sources:
            lines.append("Misses by document category:\n")
            for (cls, cat), n in r.fn_sources.most_common():
                lines.append(f"- `{cls}` in `{cat}`: {n}")
            lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    ap.add_argument("--check", action="store_true", help="fail on a regression")
    ap.add_argument("--update", action="store_true", help="write the baseline")
    args = ap.parse_args(argv)
    t0 = time.monotonic()
    results = run()
    elapsed = time.monotonic() - t0
    current = baseline_json(results)
    print(report(results))  # noqa: T201
    print(f"Benchmark ran in {elapsed:.1f}s.")  # noqa: T201
    leaks = [x for r in results.values() for x in r.leaks]
    if leaks:
        print("VALUES LEAKED into outputs:", *sorted(set(leaks)), sep="\n  ")  # noqa: T201
        return 1
    if args.update:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print(f"Baseline written to {BASELINE}.")  # noqa: T201
        return 0
    if args.check:
        base = json.loads(BASELINE.read_text())
        bad = regressions(current, base)
        if bad:
            print("Accuracy regressed past the baseline (tolerance {TOLERANCE}):")  # noqa: T201
            print(*bad, sep="\n")  # noqa: T201
            return 1
        better = regressions(base, current)
        if better:
            print("Better than the baseline; run --update and commit it:")  # noqa: T201
            print(*better, sep="\n")  # noqa: T201
        print("No regression against the baseline.")  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
