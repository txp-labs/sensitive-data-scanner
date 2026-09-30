"""Duplicate skipping (#67 part 5): an object whose bytes are those of an object already read
(the same content fingerprint), under a name of the same kind, read with components that are
still current, is not read again; its findings are the original's as its own, each naming
the original's (`duplicateOf`). Every value is made up."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aws_fixtures import DATA, Env, config
from sensitive_data_core.scan.sniff import name_kind
from synthetic import CARDS, SSN_A, dashed, printed
from test_rescans import bumped, gets, s3_coverage, use

ROSTER = f"name,ssn,card\nA,{dashed(SSN_A)},{CARDS['visa']}\n".encode()


def heads(env: Env) -> list[str]:
    keys: list[str] = []

    def count(params: dict[str, Any], **_: Any) -> None:
        if params.get("Bucket") == DATA:
            keys.append(params["Key"])

    env.clients.s3.meta.events.register("provide-client-params.s3.HeadObject", count)
    return keys


def by_key(doc: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for f in doc["findings"]:
        out.setdefault(f["resource"]["key"], []).append(f)
    return out


def test_a_copy_is_not_read_and_its_findings_name_the_originals(env: Env) -> None:
    env.put("hr/roster.csv", ROSTER)
    env.put("shared/roster-copy.csv", ROSTER)  # the same bytes, a name of the same kind
    env.put("shared/roster.txt", ROSTER)  # the same bytes, read differently: not a copy
    read, headed = gets(env), heads(env)
    doc = env.run(config())
    assert doc is not None
    __import__("test_streams").valid(doc)
    assert "shared/roster-copy.csv" not in read and "shared/roster-copy.csv" in headed
    assert {"hr/roster.csv", "shared/roster.txt"} <= set(read)
    cov = s3_coverage(doc)
    assert cov["duplicates"] == 1 and cov["scanned"] == 2
    found = by_key(doc)
    original = {f["class"]: f for f in found["hr/roster.csv"]}
    copies = found["shared/roster-copy.csv"]
    assert {f["class"] for f in copies} == set(original)
    for f in copies:
        o = original[f["class"]]
        assert f["duplicateOf"] == o["id"] and f["id"] != o["id"]
        assert f["resource"]["key"] == "shared/roster-copy.csv"
        assert f["resource"]["versionId"] not in (None, "")
        assert (f["count"], f["occurrences"], f["offsets"]) == (
            o["count"],
            o["occurrences"],
            o["offsets"],
        )
        assert f["atRestEncryption"] == o["atRestEncryption"]
    assert not any("duplicateOf" in f for f in found["shared/roster.txt"])
    # The next run reads neither again.
    read.clear()
    assert env.run(config()) is not None and read == []


def test_a_copy_of_a_clean_object_holds_nothing_and_is_not_read(env: Env) -> None:
    env.put("a/notes.txt", b"nothing to see here")
    env.put("b/notes.txt", b"nothing to see here")
    read = gets(env)
    doc = env.run(config())
    assert doc is not None
    assert read == ["a/notes.txt"] and s3_coverage(doc)["duplicates"] == 1
    assert doc["findings"] == []


def test_a_stale_original_is_no_original(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.put("hr/roster.csv", ROSTER)
    assert env.run(config(rescan_percent=0)) is not None
    use(monkeypatch, bumped("reader:text"))
    env.put("shared/roster-copy.csv", ROSTER)  # a copy made after the reader changed
    read = gets(env)
    doc = env.run(config(rescan_percent=0))
    assert doc is not None
    # The copy is new and its original is stale (and not rescanned, with rescans off): the
    # copy is read, not copied from what the old reader found.
    assert read == ["shared/roster-copy.csv"]
    assert not any("duplicateOf" in f for f in doc["findings"])


def test_bytes_read_whole_are_a_fingerprint_for_a_later_copy(env: Env) -> None:
    """A multipart upload's ETag says nothing of its bytes; read whole, their MD5 does, so a
    later single-part copy is known by its ETag."""
    s3 = env.clients.s3
    up = s3.create_multipart_upload(Bucket=DATA, Key="big/export.csv")
    part = s3.upload_part(
        Bucket=DATA, Key="big/export.csv", UploadId=up["UploadId"], PartNumber=1, Body=ROSTER
    )
    s3.complete_multipart_upload(
        Bucket=DATA,
        Key="big/export.csv",
        UploadId=up["UploadId"],
        MultipartUpload={"Parts": [{"ETag": part["ETag"], "PartNumber": 1}]},
    )
    assert "-" in s3.head_object(Bucket=DATA, Key="big/export.csv")["ETag"]
    assert env.run(config()) is not None
    env.put("big/export-copy.csv", ROSTER)
    read = gets(env)
    doc = env.run(config())
    assert doc is not None
    assert "big/export-copy.csv" not in read
    assert all(f.get("duplicateOf") for f in by_key(doc)["big/export-copy.csv"])


def test_name_kinds_are_known_extensions_only() -> None:
    assert name_kind("a/b/roster.csv") == "csv"
    assert name_kind("x.csv.gz") == "csv.gz"
    assert name_kind(f"x.{SSN_A}") == "?"  # never a value
    assert name_kind("README") == ""
    assert name_kind("photo.JPG") == "jpg"


def test_copies_are_skipped_on_azure_gcs_and_sharepoint(tmp_path: Path) -> None:
    from azure_fakes import Blob
    from gcp_fakes import Obj
    from saas_fakes import HOST, Item
    from saas_fakes import settings as m365_settings
    from sensitive_data_core.state import FileState
    from test_azure_blob import run as azure_run
    from test_azure_blob import tenant
    from test_gcp_gcs import cloud
    from test_gcp_gcs import run as gcp_run
    from test_saas_m365 import files_tenant, scan

    t = tenant()
    raw = t.container("contosolake", "curated")
    raw.blobs["a/roster.csv"] = Blob(ROSTER, md5=True)
    raw.blobs["b/roster.csv"] = Blob(ROSTER, md5=True)
    c = cloud()
    lake = c.bucket("acme-lake")
    lake.objects["a/roster.csv"] = Obj(ROSTER, md5=True)
    lake.objects["b/roster.csv"] = Obj(ROSTER, md5=True)
    m = files_tenant()
    m.drives["d-lib"].add(Item("r1", "roster.csv", ROSTER, sha1=True))
    m.drives["d-lib"].add(Item("r2", "roster.csv", ROSTER, sha1=True))
    state = FileState(str(tmp_path / "state.json"))
    s = m365_settings(tmp_path, M365_SITES=f"{HOST}:/sites/finance", DISCOVER="sharepoint")
    before = len(raw.downloads)
    docs = [azure_run(t), gcp_run(c), scan(m, s, state=state)]
    assert len({d[0] for d in raw.downloads[before:] if d[0].endswith("roster.csv")}) == 1
    for doc in docs:
        copies = [f for f in doc["findings"] if f.get("duplicateOf")]
        assert copies, doc.get("platform")
        originals = {f["id"] for f in doc["findings"] if not f.get("duplicateOf")}
        assert all(f["duplicateOf"] in originals for f in copies)
        assert sum(cv.get("duplicates", 0) for cv in doc["coverage"]) == 1
    sp = [f for f in docs[2]["findings"] if f.get("duplicateOf")]
    assert {f["resource"]["itemId"] for f in sp} == {"r2"}
    assert printed(CARDS["visa"]) not in str(docs)
