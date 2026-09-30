"""The run's budget over many stores (#94): a work-conserving round robin.

The first whole-account run in a real account had about 750 sources. An even share
per source gave a large store about a second and a few dozen items a run. These tests
run a made-up estate like it (hundreds of tiny stores, a few large ones) on a fake
clock: every item read costs time, and nothing sleeps.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sensitive_data_core.adapter import Budget, SourceRun
from sensitive_data_core.coverage import Store, summary
from sensitive_data_core.findings import Coverage
from sensitive_data_core.schedule import MIN_SLICE_PARTS, merge_coverage, run_sources

SECONDS_PER_ITEM = 0.02  # 20,000 items take 400 s: items bind first, unless said
RUN_SECONDS = 600.0
RUN_ITEMS = 20_000


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


@dataclass
class Fake:
    """A store of `size` items, read one at a time from where the last call stopped. With
    `page_cap`, it reads at most that many a call (a source's own per-run cap)."""

    id: str
    kind: str
    size: int
    clock: Clock
    done: int = 0
    calls: int = 0
    page_cap: int | None = None

    @property
    def target(self) -> str:
        return self.id

    def run(self, budget: Budget) -> SourceRun:
        self.calls += 1
        cov = Coverage(self.kind, self.id)
        read = 0
        while self.done < self.size and budget.has(1):
            if self.page_cap is not None and read >= self.page_cap:
                break
            budget.take(1)
            self.clock.t += SECONDS_PER_ITEM
            self.done += 1
            read += 1
            cov.scanned += 1
            cov.listed += 1
        cov.pass_complete = self.done >= self.size
        cov.backlog = not cov.pass_complete
        return SourceRun(cov, {"done": self.done})


def estate(
    clock: Clock, *, tiny: int = 700, large: int = 3, large_size: int = 100_000
) -> list[Fake]:
    """Large stores first in rotation order, then the tiny ones (the order a real run
    met them in: log groups and tables before 451 Lambda functions)."""
    out = [Fake(f"big-{i}", "dynamodb", large_size, clock) for i in range(large)]
    out += [Fake(f"tiny-{i:03d}", "lambda_env", 1, clock) for i in range(tiny)]
    return out


def serve(source: Fake, share: Budget) -> SourceRun:
    return source.run(share)


def old_even_share(sources: list[Fake], budget: Budget) -> None:
    """The scheduler before #94: once through, an even share of what is left each."""
    for i, s in enumerate(sources):
        if budget.exhausted():
            continue
        share = budget.share(len(sources) - i)
        s.run(share)
        budget.absorb(share)


def test_many_tiny_stores_and_a_few_large_ones() -> None:
    clock = Clock()
    sources = estate(clock)
    budget = Budget(RUN_ITEMS, 10**12, RUN_SECONDS, clock)
    got = run_sources(sources, budget, serve)
    tiny = [s for s in sources if s.kind == "lambda_env"]
    big = [s for s in sources if s.kind == "dynamodb"]
    # Small stores finish, in one call each.
    assert all(s.done == 1 and s.calls == 1 for s in tiny)
    assert all(got.results[s.id].coverage.pass_complete for s in tiny)
    # Their unused time went back to the pool: the run spent its budget, no more.
    assert budget.exhausted()
    assert budget.items <= RUN_ITEMS
    assert clock.t <= RUN_SECONDS + SECONDS_PER_ITEM
    # Large stores got meaningful slices: together, everything the tiny ones left.
    assert all(s.done >= RUN_ITEMS // MIN_SLICE_PARTS for s in big)
    assert sum(s.done for s in big) >= RUN_ITEMS - len(tiny) - 2 * len(big)
    # And about even shares of it, served in rounds.
    assert max(s.done for s in big) - min(s.done for s in big) <= RUN_ITEMS // MIN_SLICE_PARTS
    assert got.rounds > 1
    # One coverage per source for the run, whatever the rounds.
    big0 = got.results["big-0"].coverage
    assert big0.scanned == sources[0].done and big0.backlog and not big0.pass_complete
    assert got.deferred is None
    assert got.rotation in {s.id for s in big}


def test_the_old_even_share_starved_the_large_stores() -> None:
    """The same estate on the scheduler it replaces: what the real run saw."""
    clock = Clock()
    sources = estate(clock)
    old_even_share(sources, Budget(RUN_ITEMS, 10**12, RUN_SECONDS, clock))
    big = [s for s in sources if s.kind == "dynamodb"]
    assert max(s.done for s in big) < 50  # a few dozen items a run
    clock2 = Clock()
    sources2 = estate(clock2)
    run_sources(sources2, Budget(RUN_ITEMS, 10**12, RUN_SECONDS, clock2), serve)
    assert min(s.done for s in sources2 if s.kind == "dynamodb") > 50 * max(s.done for s in big)


def test_the_time_budget_alone_is_served_the_same_way() -> None:
    """Items to spare, time short: the slices are cut in seconds."""
    clock = Clock()
    sources = estate(clock)
    budget = Budget(10**9, 10**12, RUN_SECONDS, clock)
    run_sources(sources, budget, serve)
    big = [s for s in sources if s.kind == "dynamodb"]
    per_slice = RUN_SECONDS / MIN_SLICE_PARTS / SECONDS_PER_ITEM
    assert all(s.done >= per_slice for s in big)
    assert all(s.done == 1 for s in sources if s.kind == "lambda_env")
    assert RUN_SECONDS <= clock.t <= RUN_SECONDS + SECONDS_PER_ITEM


def test_what_one_run_cannot_reach_the_next_run_starts_with() -> None:
    """Many large stores: each gets a minimum slice; those past the budget are deferred,
    and the next run starts at the first of them."""
    clock = Clock()
    sources = [Fake(f"big-{i:03d}", "cloudwatch_logs", 10**6, clock) for i in range(120)]
    got = run_sources(sources, Budget(RUN_ITEMS, 10**12, RUN_SECONDS, clock), serve)
    reached = [s for s in sources if s.calls]
    assert MIN_SLICE_PARTS - 1 <= len(reached) <= MIN_SLICE_PARTS + 1
    assert all(s.done >= RUN_ITEMS // MIN_SLICE_PARTS - 1 for s in reached[:-1])
    first_missed = sources[len(reached)].id
    assert got.deferred == first_missed and got.rotation == first_missed


def test_a_source_that_stops_on_its_own_cap_waits_for_the_next_run() -> None:
    """Not re-served in the same run: its page cap is per run (DynamoDB's `max_pages`)."""
    clock = Clock()
    capped = Fake("capped", "dynamodb", 10**6, clock, page_cap=10)
    got = run_sources([capped], Budget(RUN_ITEMS, 10**12, RUN_SECONDS, clock), serve)
    assert capped.calls == 1 and capped.done == 10
    assert got.results["capped"].coverage.backlog


def test_a_cap_shared_by_several_kinds() -> None:
    """Azure and Google Cloud cap objects across every object kind with one budget."""
    clock = Clock()
    a = Fake("a", "blob", 10**6, clock)
    b = Fake("b", "files", 10**6, clock)
    c = Fake("c", "cosmos", 10**6, clock)
    objects = Budget(1_000, 10**12, RUN_SECONDS, clock)
    run_sources(
        [a, b, c],
        Budget(RUN_ITEMS, 10**12, RUN_SECONDS, clock),
        serve,
        caps={"blob": objects, "files": objects},
    )
    assert a.done + b.done <= 1_000
    assert abs(a.done - b.done) <= 1_000 // MIN_SLICE_PARTS
    assert c.done >= RUN_ITEMS - 1_000 - 2  # the cap's leftover goes to the uncapped kind


def test_one_coverage_per_source_for_the_run() -> None:
    a = Coverage("s3", "b", listed=3, scanned=2, bytes_scanned=10, formats={"json": 2})
    a.skipped = {"too_large": 1}
    a.backlog = True
    b = Coverage("s3", "b", listed=4, scanned=4, bytes_scanned=5, formats={"json": 1, "csv": 3})
    b.pass_complete, b.relisted, b.indexed, b.rescan_backlog = True, False, 7, 0
    m = merge_coverage(a, b)
    assert (m.listed, m.scanned, m.bytes_scanned) == (7, 6, 15)
    assert m.formats == {"json": 3, "csv": 3}
    assert m.skipped == {"too_large": 1}
    assert m.pass_complete and not m.backlog  # the state is the last call's
    assert m.indexed == 7


def test_the_run_summary_shows_the_backlog_by_kind() -> None:
    stores = [
        Store("cloudwatch_logs", "a"),
        Store("cloudwatch_logs", "b"),
        Store("dynamodb", "t"),
        Store("lambda_env", "f"),
        Store("s3", "not-reached"),
    ]
    for s in stores:
        s.status = "scanned"
    stores[0].backlog = True
    stores[1].backlog = True
    stores[2].backlog = True
    stores[4].status, stores[4].reason = "deferred", "budget"
    got: dict[str, Any] = summary(stores, {})
    assert got["backlogByKind"] == {"cloudwatch_logs": 2, "dynamodb": 1, "s3": 1}
    for s in stores:
        s.backlog = False
    stores[4].status, stores[4].reason = "scanned", None
    assert summary(stores, {})["backlogByKind"] == {}
