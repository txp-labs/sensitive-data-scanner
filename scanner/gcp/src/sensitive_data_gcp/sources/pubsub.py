"""Pub/Sub: topics, reported as coverage only. Reading needs a subscription, which is a write.

**Discovery** (`DISCOVER` includes `pubsub`): Cloud Asset Inventory lists every
topic in scope; each project's subscriptions (`pubsub.subscriptions.list`,
Pub/Sub Viewer) say which topics are **dead-letter topics** (a subscription's
`deadLetterPolicy` names them). A store is one topic, `project/topic`.

**Why nothing is read.** A topic's messages can only be read through a
subscription: `pull` on a subscription that already exists changes what its
own consumer receives (a message pulled and not acknowledged is redelivered
later, with its delivery attempt counted; one acknowledged is gone), and
creating a subscription (`pubsub.subscriptions.create`) is a write the
scanner does not hold. So:

- a dead-letter topic is `needs_subscription` (`deadLetterQueue: true`): the
  place failed messages, and their payloads, pile up;
- any other topic is `live_queue`: its messages belong to its consumers.

docs/GCP.md describes the opt-in reader for dead-letter topics, designed and
not built: a subscription of the scanner's own, created by the deployment on
each named dead-letter topic, which only the scanner pulls from.

**Encryption (1.5):** the topic's Cloud KMS key (`kmsKeyName`), hashed, else
Google's own keys (`service_managed`).
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from sensitive_data_core.coverage import Discovery, Store, apply_rules
from sensitive_data_core.safety import error_name, log_event

from ..clients import PUBSUB_API
from ..resources import Located
from .base import Context, kms_facts, labels

KIND = "pubsub"
ASSET_TYPE = "pubsub.googleapis.com/Topic"


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


class PubSubAdapter:
    kind = KIND

    def discover(self, ctx: Context, out: Discovery) -> None:
        topics: list[tuple[str, str, dict[str, Any]]] = []
        for row in ctx.search(ASSET_TYPE):
            parts = str(row.get("name") or "").split("/")
            try:
                project = parts[parts.index("projects") + 1]
                topic = parts[parts.index("topics") + 1]
            except (ValueError, IndexError):
                continue
            topics.append((project, topic, row))
        dead: set[str] = set()
        unknown: set[str] = set()
        for project in sorted({p for p, _, _ in topics}):
            try:
                url = f"{PUBSUB_API}/projects/{_q(project)}/subscriptions"
                for page, _ in ctx.rest.pages(url, "subscriptions", {"pageSize": "1000"}):
                    for sub in page:
                        policy = sub.get("deadLetterPolicy") if isinstance(sub, dict) else None
                        if isinstance(policy, dict) and policy.get("deadLetterTopic"):
                            dead.add(str(policy["deadLetterTopic"]))
            except Exception as err:  # which topics are dead-letter topics stays unknown
                unknown.add(project)
                log_event("discovery.failed", kind=KIND, error=error_name(err))
        for project, topic, row in topics:
            where = Located(project, str(row.get("name") or ""))
            store = Store(KIND, f"{project}/{topic}", tags=labels(row))
            store.extra.update(where.fields())
            keys = [str(k) for k in row.get("kmsKeys") or [] if k]
            store.facts = kms_facts(keys[0] if keys else None)
            out.stores.append(store)
            if not apply_rules(store, ctx.settings.allow, ctx.settings.deny):
                continue
            if f"projects/{project}/topics/{topic}" in dead:
                store.extra["deadLetterQueue"] = True
                store.skip("needs_subscription")  # a subscription is a write; never made
            elif project in unknown:
                store.skip("needs_subscription")
            else:
                store.skip("live_queue")

    def source(self, ctx: Context, store: Store) -> None:
        return None
