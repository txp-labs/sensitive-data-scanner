"""Sharing one run's budget among many sources: a work-conserving round robin (#94).

The first whole-account run in a real account had about 750 sources: 451 Lambda
functions' variables, 276 log groups, a few tables and buckets. An even share of
what was left, once per source, gave every source about a second and 26 items,
so a large store advanced a page a run (the biggest table read 34 items a run),
and a first pass of the account would take many daily runs.

Now the run's items, bytes and time are served in rounds, in rotation order:

- **A slice** is an even share of what is left among the sources still to be
  served this round, but never less than `1 / MIN_SLICE_PARTS` of the run's
  items, bytes and time (and never more than is left). A large store gets a
  meaningful slice even when hundreds of stores are waiting.
- **Unused time goes back.** A small store finishes in a fraction of its slice,
  and the rest stays in the pool: every slice is cut from what is left.
- **Rounds.** A source that spent its whole slice and still has more to read
  (`backlog`, no error, no note) is served again in the next round, with the
  others still behind, until the run's budget is spent or nothing is left.
- **The remainder is carried forward.** The next run starts at the first
  source this run never reached; when every source was reached, at the first
  one still behind.

A source served more than once in a run gives one coverage for the run (its
counts summed, its state the last call's) and its last cursor.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .adapter import Budget, SourceRun
from .findings import Coverage
from .safety import log_event

# A slice is at least this fraction of the run's items, bytes and time: about 16 s,
# 400 items and 40 MB of a Lambda run with the defaults.
MIN_SLICE_PARTS = 50
# A bound on rounds: a round serves at least one source with a whole slice, so a run's
# rounds are few; this only stops a source that keeps asking without spending.
MAX_ROUNDS = 10_000

# Coverage fields that are the state of the source after its last call, not counts.
_LAST = frozenset(
    {"kind", "target", "sample_percent", "pass_complete", "backlog", "error", "rescan_backlog"}
)


def merge_coverage(a: Coverage, b: Coverage) -> Coverage:
    """Two calls of one source in one run as one coverage: counts summed (by key for the
    maps), its state (pass complete, backlog, error, what is still owed) the last call's."""
    out: dict[str, Any] = {}
    for f in dataclasses.fields(Coverage):
        x, y = getattr(a, f.name), getattr(b, f.name)
        if f.name in _LAST:
            out[f.name] = y
        elif f.name == "relisted":
            out[f.name] = bool(x) or bool(y)
        elif f.name == "indexed":
            out[f.name] = y if y is not None else x
        elif isinstance(x, dict):
            summed = dict(x)
            for k, v in y.items():
                summed[k] = summed.get(k, 0) + v
            out[f.name] = summed
        else:
            out[f.name] = x + y
    return Coverage(**out)


def merge_runs(a: SourceRun, b: SourceRun) -> SourceRun:
    return SourceRun(
        merge_coverage(a.coverage, b.coverage), b.cursor, b.note, {**a.extra, **b.extra}
    )


def slice_of(budget: Budget, ways: int, floor: tuple[int, int, float]) -> Budget:
    """One source's slice: an even share of what is left among `ways` sources, at least
    `floor` (items, bytes, seconds), never more than is left."""
    n = max(1, ways)
    now = budget.clock()
    items = max(0, budget.max_items - budget.items)
    nbytes = max(0, budget.max_bytes - budget.bytes)
    seconds = max(0.0, budget.deadline - now)
    return Budget(
        max(1, min(items, max(floor[0], items // n))),
        max(1, min(nbytes, max(floor[1], nbytes // n))),
        now + min(seconds, max(floor[2], seconds / n)),
        budget.clock,
    )


@dataclass
class Schedule:
    """What the run served: each source's result, in the order first served."""

    results: dict[str, SourceRun] = field(default_factory=dict)
    # The first source never reached (`deferred`, reason `budget`); None when all were.
    deferred: str | None = None
    # Where the next run starts: `deferred`, else the first source still behind.
    rotation: str | None = None
    rounds: int = 0
    served: int = 0  # calls made, over every round


def _more(result: SourceRun, share: Budget) -> bool:
    """Whether a source should be served again this run: it stopped on its slice with more
    to read. A source that stopped for any other reason (its own page cap, an export still
    running, throttling, an error) waits for the next run."""
    cov = result.coverage
    return (
        cov.backlog
        and cov.error is None
        and result.note is None
        and not cov.pass_complete
        and (share.exhausted() or share.bytes >= share.max_bytes * 0.9)
    )


def run_sources(
    sources: Sequence[Any],
    budget: Budget,
    serve: Callable[[Any, Budget], SourceRun],
    *,
    caps: Mapping[str, Budget] | None = None,
    parts: int = MIN_SLICE_PARTS,
) -> Schedule:
    """Serve `sources` (each with `id`, `kind` and `target`) in rounds from `budget`; see the
    module docstring. `serve(source, slice)` runs one source on its slice and returns what
    it read. `caps` are budgets by kind (a cap on log events, table items, objects; one cap
    may serve several kinds), each shared among its sources the same way. Each slice is
    absorbed into the budget (and its kind's cap) after the call."""
    caps = caps or {}
    out = Schedule()
    clock = budget.clock
    seconds = max(0.0, budget.deadline - clock())
    parts = max(1, parts)

    def floor(b: Budget, total_seconds: float) -> tuple[int, int, float]:
        return (max(1, b.max_items // parts), max(1, b.max_bytes // parts), total_seconds / parts)

    run_floor = floor(budget, seconds)
    cap_floors = {k: floor(c, seconds) for k, c in caps.items()}
    queue = list(sources)
    reached: set[str] = set()
    while queue and out.rounds < MAX_ROUNDS:
        out.rounds += 1
        again: list[Any] = []
        # The sources left this round under each cap (one cap may cover several kinds).
        by_cap: dict[int, int] = {}
        for s in queue:
            c = caps.get(s.kind)
            if c is not None:
                by_cap[id(c)] = by_cap.get(id(c), 0) + 1
        for i, source in enumerate(queue):
            cap = caps.get(source.kind)
            ways_cap = by_cap.get(id(cap), 1)
            if cap is not None:
                by_cap[id(cap)] = max(0, ways_cap - 1)
            if budget.exhausted() or (cap is not None and cap.exhausted()):
                if source.id not in reached:
                    out.deferred = out.deferred or source.id
                    log_event("source.deferred", source=source.target, kind=source.kind)
                elif out.rotation is None:
                    out.rotation = source.id  # still behind: the next run starts here
                continue
            share = slice_of(budget, len(queue) - i, run_floor)
            if cap is not None:
                share.max_items = min(
                    share.max_items, slice_of(cap, ways_cap, cap_floors[source.kind]).max_items
                )
            reached.add(source.id)
            result = serve(source, share)
            out.served += 1
            budget.absorb(share)
            if cap is not None:
                cap.absorb(share)
            prev = out.results.get(source.id)
            out.results[source.id] = result if prev is None else merge_runs(prev, result)
            if _more(result, share):
                again.append(source)
        queue = again
        if queue and budget.exhausted():
            out.rotation = out.rotation or queue[0].id
            break
    out.rotation = out.deferred or out.rotation
    return out
