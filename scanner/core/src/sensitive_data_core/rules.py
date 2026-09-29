"""Allow, deny and sampling rules for discovered stores: the same on every platform.

A rule is a name glob or a tag, optionally for one kind of store
(`s3:prod-*`, `tag:scan=false`, `postgresql:tag:team=data*`). Each platform
names its kinds (`aliases`); the settings keep their names everywhere
(`DISCOVER_ALLOW`, `DISCOVER_DENY`, `DISCOVER_SAMPLING`).
"""

from __future__ import annotations

import fnmatch
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass


def _list(v: str | None) -> list[str]:
    return [s.strip() for s in (v or "").split(",") if s.strip()]


@dataclass(frozen=True)
class StoreRule:
    """One allow or deny rule: a name glob, or a tag, optionally for one kind of store.

    `s3:prod-*`, `logs:/aws/lambda/*`, `dynamodb:orders`, `*-archive` (any kind),
    `tag:scan=false`, `tag:pii` (any value), `s3:tag:team=data*`.
    """

    kind: str | None = None
    name: str | None = None
    tag_key: str | None = None
    tag_value: str | None = None

    @property
    def needs_tags(self) -> bool:
        return self.tag_key is not None

    def matches(self, kind: str, name: str, tags: dict[str, str] | None) -> bool:
        if self.kind is not None and self.kind != kind:
            return False
        if self.name is not None:
            return fnmatch.fnmatchcase(name, self.name)
        if self.tag_key is None or tags is None or self.tag_key not in tags:
            return False
        return self.tag_value is None or fnmatch.fnmatchcase(tags[self.tag_key], self.tag_value)


def parse_rule(text: str, aliases: Mapping[str, str]) -> StoreRule:
    """One rule; `aliases` maps a platform's kind prefixes (`s3`, `logs`, ...) to its kinds."""
    t = text.strip()
    kind: str | None = None
    head, sep, rest = t.partition(":")
    if sep and head.lower() in aliases:
        kind = aliases[head.lower()]
        t = rest
    elif sep and head == "*":
        t = rest
    if t.startswith("tag:"):
        key, eq, value = t[4:].partition("=")
        if not key:
            raise ValueError("discovery rule: a tag rule needs a key")
        return StoreRule(kind=kind, tag_key=key, tag_value=value if eq else None)
    if not t:
        raise ValueError("discovery rule: empty pattern")
    return StoreRule(kind=kind, name=t)


def store_rules(raw: str | None, aliases: Mapping[str, str]) -> tuple[StoreRule, ...]:
    """`DISCOVER_ALLOW` / `DISCOVER_DENY`: comma-separated rules (StoreRule)."""
    return tuple(parse_rule(r, aliases) for r in _list(raw))


@dataclass(frozen=True)
class SamplingRule:
    """Per-store sampling: the first rule whose `match` fits a store sets its sampling."""

    match: StoreRule
    sample_percent: int | None = None
    max_objects_per_prefix: int | None = None


_SAMPLING_FIELDS = frozenset({"match", "samplePercent", "maxObjectsPerPrefix"})


def sampling_rules(raw: str | None, aliases: Mapping[str, str]) -> tuple[SamplingRule, ...]:
    """`DISCOVER_SAMPLING`: a JSON list of `{"match", "samplePercent", "maxObjectsPerPrefix"}`."""
    if not raw or not raw.strip():
        return ()
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("DISCOVER_SAMPLING is not valid JSON") from None
    if not isinstance(data, list):
        raise ValueError("DISCOVER_SAMPLING must be a JSON list")
    out = []
    for r in data:
        if not isinstance(r, dict) or set(r) - _SAMPLING_FIELDS or "match" not in r:
            raise ValueError("DISCOVER_SAMPLING: each entry needs match, and nothing unknown")
        if not isinstance(r["match"], str):
            raise ValueError("DISCOVER_SAMPLING: match must be a string")
        pct = r.get("samplePercent")
        per = r.get("maxObjectsPerPrefix")
        if pct is not None and (not isinstance(pct, int) or not 1 <= pct <= 100):
            raise ValueError("DISCOVER_SAMPLING: samplePercent must be 1-100")
        if per is not None and (not isinstance(per, int) or per < 0):
            raise ValueError("DISCOVER_SAMPLING: maxObjectsPerPrefix must be 0 or more")
        out.append(SamplingRule(parse_rule(r["match"], aliases), pct, per))
    return tuple(out)


def sampling_for(
    rules: Sequence[SamplingRule], kind: str, name: str, tags: dict[str, str] | None
) -> tuple[int | None, int | None]:
    """(samplePercent, maxObjectsPerPrefix) from the first matching sampling rule."""
    for r in rules:
        if r.match.matches(kind, name, tags):
            return r.sample_percent, r.max_objects_per_prefix
    return None, None
