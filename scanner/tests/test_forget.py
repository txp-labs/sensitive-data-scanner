"""A source dropped from a run and added back later (#67): its carried findings leave the
state, and its cursor and object index go with them, so when it returns its store is read as
a new one's and its real findings come back. Were its index kept, its unchanged objects would
be skipped as already read and their findings lost for good. Every value is made up."""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any

from aws_fixtures import DATA, RESULTS, Env, config
from sensitive_data_core.index import (
    FORGET_KEY,
    Indexes,
    MemoryBackend,
    ObjectPass,
    forget_absent,
)
from test_rescans import OBJECTS, gets, seeded

SALT = "0" * 32


def _indexed(backend: MemoryBackend, source_id: str, keys: int = 3) -> Indexes:
    """An index for `source_id` with `keys` rows, saved to `backend`."""
    idx = Indexes(backend, SALT)
    op = ObjectPass(idx, source_id, "s3")
    for i in range(keys):
        op.record(f"k{i}", marker=f"m{i}")
    idx.save()
    return Indexes(backend, SALT)


def _files_of(backend: MemoryBackend, idx: Indexes, source_id: str) -> list[str]:
    name = idx.name_of(source_id)
    return sorted(k for k in backend.files if k.startswith(name + "/"))


# ------------------------------------------------------------------ the rule


def test_an_absent_source_loses_its_cursor_and_index_and_a_present_one_keeps_them() -> None:
    backend = MemoryBackend()
    _indexed(backend, "s3:gone/")
    idx = _indexed(backend, "s3:kept/")
    assert _files_of(backend, idx, "s3:gone/") and _files_of(backend, idx, "s3:kept/")
    cursors: dict[str, Any] = {"s3:gone/": {"passComplete": True}, "s3:kept/": {"at": 1}}
    carried = [{"_location": "s3:gone/\nk0"}, {"_location": "s3:kept/\nk1"}]
    left = forget_absent(cursors, carried, {"s3:kept/"}, idx)
    assert left == []
    assert cursors == {"s3:kept/": {"at": 1}}
    assert _files_of(backend, idx, "s3:gone/") == []
    assert _files_of(backend, idx, "s3:kept/")
    # Back again: no row, so an object is read as new, not skipped.
    back = ObjectPass(Indexes(backend, SALT), "s3:gone/", "s3")
    assert back.index is not None and back.index.rows == 0
    assert back.decide("k0", changed=True, marker="m0").read


def test_a_source_known_only_by_its_findings_is_forgotten_too() -> None:
    """A source with findings carried and no cursor (the databases runner keeps none)."""
    backend = MemoryBackend()
    idx = _indexed(backend, "postgresql:app")
    assert forget_absent({}, [{"_location": "postgresql:app\nhr.people"}], set(), idx) == []
    assert _files_of(backend, idx, "postgresql:app") == []


class _NoDelete(MemoryBackend):
    """A state location that grants writes but not deletes."""

    def delete(self, name: str) -> None:
        raise PermissionError("AccessDenied")


class _ReadOnly(_NoDelete):
    def put_bytes(self, name: str, data: bytes) -> None:
        if name.endswith("meta.json") and data == b"{}":
            raise PermissionError("AccessDenied")
        super().put_bytes(name, data)


def test_without_delete_the_index_is_emptied_and_without_writes_it_is_retried() -> None:
    backend = _NoDelete()
    idx = _indexed(backend, "s3:gone/")
    assert forget_absent({}, [{"_location": "s3:gone/\nk0"}], set(), idx) == []
    # The meta is overwritten: no index, so the next pass starts a fresh one.
    fresh = ObjectPass(Indexes(backend, SALT), "s3:gone/", "s3")
    assert fresh.index is not None and fresh.index.rows == 0 and fresh.index.fresh

    stuck = _ReadOnly()
    idx = _indexed(stuck, "s3:gone/")
    cursors: dict[str, Any] = {"s3:gone/": {}}
    left = forget_absent(cursors, [], set(), idx)
    assert left == ["s3:gone/"] and cursors == {}
    # The next run tries again first, even with the source back (and its cursor dropped).
    fixed = MemoryBackend()
    fixed.files = dict(stuck.files)
    cursors = {"s3:gone/": {"at": 2}}
    assert forget_absent(cursors, [], {"s3:gone/"}, Indexes(fixed, SALT), left) == []
    assert cursors == {}
    assert _files_of(fixed, idx, "s3:gone/") == []


def test_without_an_index_only_the_cursor_goes() -> None:
    cursors: dict[str, Any] = {"s3:gone/": {}}
    assert forget_absent(cursors, [], set(), None, ["s3:other/"]) == []
    assert cursors == {}


# ------------------------------------------------------------------ S3, end to end


def test_an_s3_prefix_dropped_for_a_run_reports_its_findings_when_it_returns(env: Env) -> None:
    first = seeded(env)
    assert first["findings"]
    ids = {f["id"] for f in first["findings"]}
    source = f"s3:{DATA}/"
    assert source in env.state()["cursors"]

    # One run without it: its findings leave, and so do its cursor and its index.
    other = env.run(config(s3_targets=[(DATA, "zzz/")]))
    assert other is not None and other["findings"] == []
    state = env.state()
    assert source not in state["cursors"] and FORGET_KEY not in state
    stored = env.clients.s3.list_objects_v2(Bucket=RESULTS, Prefix="state/index/")
    name = Indexes(MemoryBackend(), state["indexSalt"]).name_of(source)
    assert not [o for o in stored.get("Contents", []) if o["Key"].startswith(f"state/index/{name}")]

    # Back: every object is read again, and its real findings return.
    read_keys = gets(env)
    back = env.run(config())
    assert back is not None
    assert {f["id"] for f in back["findings"]} == ids
    assert set(read_keys) >= {k for k in OBJECTS if k.endswith((".txt", ".pdf", ".docx"))}
    # And the run after skips them again, as usual.
    read_keys.clear()
    again = env.run(config())
    assert again is not None and {f["id"] for f in again["findings"]} == ids
    assert read_keys == []


# ------------------------------------------------------------------ SharePoint, end to end


def test_a_sharepoint_site_dropped_for_a_run_reports_its_findings_when_it_returns(
    tmp_path: Path,
) -> None:
    from saas_fakes import HOST
    from saas_fakes import settings as m365_settings
    from sensitive_data_core.state import FileState
    from test_saas_m365 import files_tenant, scan

    m = files_tenant()
    state = FileState(str(tmp_path / "state.json"))
    finance = m365_settings(tmp_path, M365_SITES=f"{HOST}:/sites/finance", DISCOVER="sharepoint")
    legal = m365_settings(tmp_path, M365_SITES=f"{HOST}:/sites/legal", DISCOVER="sharepoint")
    first = scan(m, finance, state=state)
    items = {f["resource"]["itemId"] for f in first["findings"]}
    assert items == {"x1", "x4"}
    assert scan(m, finance, state=state)["findings"]  # unchanged, carried
    assert scan(m, legal, state=state)["findings"] == []
    back = scan(m, finance, state=state)
    assert {f["resource"]["itemId"] for f in back["findings"]} == items
    assert {f["id"] for f in back["findings"]} == {f["id"] for f in first["findings"]}


# ------------------------------------------------------------------ databases, end to end


def test_a_database_dropped_for_a_run_reports_its_findings_when_it_returns(
    tmp_path: Path,
) -> None:
    from db_fakes import Driver
    from sensitive_data_db.config import read_settings
    from sensitive_data_db.runner import run
    from sensitive_data_db.state import FileState
    from test_db_runner import DETECTOR, NOW, Sink, env, pg_db

    db = pg_db()
    counters = {("public", "people"): 5, ("hr", "empty"): 0}
    markers = [
        {"table_schema": s, "table_name": t, "n_tup_ins": n} for (s, t), n in counters.items()
    ]
    db.catalog.insert(0, (re.compile("pg_stat_user_tables"), markers))
    where = str(tmp_path / "state.json")

    def once(day: int, **urls: str) -> tuple[dict[str, Any], list[str]]:
        e = env(**urls)
        e["STATE_LOCATION"] = where
        driver = Driver(db)
        doc, failed = run(
            read_settings(e),
            [Sink()],
            drivers={"postgresql": driver},
            detector=DETECTOR,
            now=lambda: NOW + dt.timedelta(days=day),
            state=FileState(where),
        )
        assert failed == 0
        return doc, [s for s in driver.statements() if s.startswith("SELECT * FROM")]

    app = "postgresql://ro@db.internal/app"
    first, _ = once(0, app=app)
    assert first["findings"]
    once(1, app=app)  # the markers are recorded
    _, sampled = once(2, app=app)
    assert sampled == []  # unchanged: skipped, findings carried
    other, _ = once(3, crm="postgresql://ro@db.internal/crm")
    assert all(f["resource"]["store"] == "crm" for f in other["findings"])
    back, sampled = once(4, app=app)
    assert 'SELECT * FROM "public"."people" LIMIT 1000' in sampled
    assert {f["id"] for f in back["findings"]} == {f["id"] for f in first["findings"]}
