"""Word, Excel and PowerPoint files in AWS: S3 objects, CodeCommit files and ECR layer files
are read as their text by the core's Office reader (`scan/office.py`), the one the Azure,
Google Cloud and SaaS scanners use, within the same byte and inflate caps.

S3 is moto's; CodeCommit and ECR answer through botocore's Stubber and a fake layer
download. Every value is made up.
"""

from __future__ import annotations

import io
import json
import random
import zipfile
from typing import IO, Any

from botocore.stub import ANY

from aws_fixtures import DATA, Env, config
from office_fixtures import OLE, docx, pptx, with_dtd, xlsx
from synthetic import CARDS, SSN_A, SSN_B, dashed, printed
from test_default_on import blob, repo
from test_images_archives import layer
from test_streams import stubs, valid


def by_key(doc: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for f in doc["findings"]:
        out.setdefault(f["resource"]["key"], {})[f["class"]] = f
    return out


def padded_docx(paragraphs: list[str], pad: int) -> bytes:
    """A document with a large incompressible part after its text, so its zip directory
    sits `pad` bytes past the body."""
    buf = io.BytesIO(docx(paragraphs))
    with zipfile.ZipFile(buf, "a", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/media/image1.png", random.Random(7).randbytes(pad))  # noqa: S311
    return buf.getvalue()


# ------------------------------------------------------------------ S3


def test_s3_reads_word_excel_and_powerpoint_as_text(env: Env) -> None:
    env.put("hr/letter.docx", docx(["Dear customer,", f"card {printed(CARDS['visa'])}"]))
    env.put("hr/roster.xlsx", xlsx([["name", "ssn"], ["A", dashed(SSN_A)]]))
    env.put("sales/deck.pptx", pptx(["Q3 plan", f"test card {CARDS['amex']}"]))
    env.put("hr/clean.docx", docx(["Nothing sensitive. Order 12345 shipped."]))
    env.put("legal/protected.docx", OLE)  # rights-managed: an OLE container, not a zip
    env.put("legal/broken.xlsx", b"PK\x03\x04 not really a zip")
    env.put("legal/entity.docx", with_dtd())  # a DTD is never parsed
    env.put("legal/scan.pdf", b"%PDF-1.7 made up")
    env.put("legal/old.doc", b"\xd0\xcf\x11\xe0 made up")
    doc = env.run(config())
    assert doc is not None
    valid(doc)
    found = by_key(doc)
    assert set(found) == {"hr/letter.docx", "hr/roster.xlsx", "sales/deck.pptx"}
    assert set(found["hr/letter.docx"]) == {"card"}
    assert set(found["hr/roster.xlsx"]) == {"us_ssn"}
    assert set(found["sales/deck.pptx"]) == {"card"}
    letter = found["hr/letter.docx"]["card"]
    assert letter["format"] == "docx"
    assert found["hr/roster.xlsx"]["us_ssn"]["format"] == "xlsx"
    assert found["sales/deck.pptx"]["card"]["format"] == "pptx"
    # One object version per finding, pinned across the ranged GETs, and its deep link.
    version = env.clients.s3.head_object(Bucket=DATA, Key="hr/letter.docx")["VersionId"]
    assert letter["resource"]["versionId"] == version
    assert f"versionId={version}" in letter["link"]
    cov = doc["coverage"][0]
    assert cov["formats"] == {"docx": 3, "xlsx": 1, "pptx": 1}
    assert cov["scanned"] == 5  # the three with findings, the clean one, the one with a DTD
    assert cov["skipped"] == {"encrypted": 1, "document": 3}  # broken, the PDF, the old .doc
    assert cov["unreadable"] == 0


def test_s3_office_reads_stay_within_the_byte_and_inflate_caps(env: Env) -> None:
    # The whole file is 64 KiB and more: with a 16 KiB cap its zip cannot be read.
    env.put("big/report.docx", padded_docx([f"card {printed(CARDS['visa'])}"], 64 * 1024))
    doc = env.run(config(max_object_bytes=16 * 1024))
    assert doc is not None
    cov = doc["coverage"][0]
    assert cov["skipped"] == {"document": 1}
    assert cov["partial"] == 1
    assert cov["bytesScanned"] == 0
    assert doc["findings"] == []


def test_s3_office_text_past_the_inflate_cap_is_partial(env: Env) -> None:
    rows = [["name", "card"]] + [["A", CARDS["visa"]] for _ in range(200)]
    env.put("big/cards.xlsx", xlsx(rows))
    doc = env.run(config(max_inflated_bytes=2048))
    assert doc is not None
    cov = doc["coverage"][0]
    assert cov["partial"] == 1
    # The shared strings fit, the sheet does not: read in part, and counted as read.
    assert cov["formats"] == {"xlsx": 1}


# ------------------------------------------------------------------ CodeCommit


def test_codecommit_reads_office_files(env: Env) -> None:
    s = stubs(env, "codecommit")
    cc = s["codecommit"]
    repo(cc)
    cc.add_response(
        "get_branch",
        {"branch": {"branchName": "main", "commitId": "c1"}},
        {"repositoryName": "payments", "branchName": "main"},
    )
    paths = ["docs/runbook.docx", "fixtures/users.xlsx", "docs/locked.docx", "docs/scan.pdf"]
    cc.add_response(
        "get_folder",
        {
            "commitId": "c1",
            "folderPath": "/",
            "files": [{"absolutePath": p, "relativePath": p, "blobId": "b"} for p in paths],
        },
        {"repositoryName": "payments", "commitSpecifier": "c1", "folderPath": "/"},
    )
    files = {
        "docs/runbook.docx": docx(["Use the test card", f"{printed(CARDS['discover'])}"]),
        "fixtures/users.xlsx": xlsx([["name", "ssn"], ["A", dashed(SSN_B)]]),
        "docs/locked.docx": OLE,
    }
    from sensitive_data_core.scan.objects import sample_point

    for path in sorted(files, key=lambda p: (sample_point(p), p)):
        blob(cc, "c1", path, files[path])
    doc = env.run(config(s3_targets=[], discover=frozenset({"codecommit"})))
    assert doc is not None
    valid(doc)
    cc.assert_no_pending_responses()
    found = {(f["resource"]["field"], f["class"]): f for f in doc["findings"]}
    assert set(found) == {("docs/runbook.docx", "card"), ("fixtures/users.xlsx", "us_ssn")}
    assert found[("docs/runbook.docx", "card")]["format"] == "docx"
    assert found[("fixtures/users.xlsx", "us_ssn")]["format"] == "xlsx"
    cov = next(c for c in doc["coverage"] if c["kind"] == "codecommit")
    assert (cov["listed"], cov["eligible"], cov["scanned"]) == (4, 3, 2)
    assert cov["skipped"] == {"document": 1, "encrypted": 1}
    assert cov["formats"] == {"docx": 1, "xlsx": 1}


# ------------------------------------------------------------------ ECR


def test_ecr_layers_read_office_files(env: Env) -> None:
    s = stubs(env, "ecr")
    ecr = s["ecr"]
    ecr.add_response(
        "describe_repositories",
        {"repositories": [{"repositoryName": "checkout", "repositoryArn": "arn:aws:ecr:x:1:r/c"}]},
    )
    digest = "sha256:" + "d" * 64
    ecr.add_response("describe_images", {"imageDetails": [{"imageDigest": digest}]})
    manifest = {
        "layers": [{"digest": digest, "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]
    }
    ecr.add_response(
        "batch_get_image",
        {"images": [{"imageManifest": json.dumps(manifest)}]},
        {"repositoryName": "checkout", "imageIds": ANY, "acceptedMediaTypes": ANY},
    )
    ecr.add_response("get_download_url_for_layer", {"downloadUrl": "https://layers.example/d"})
    big = padded_docx([f"card {printed(CARDS['jcb'])}"], 64 * 1024)
    data = layer(
        {
            "app/seed.xlsx": xlsx([["name", "card"], ["A", CARDS["mastercard"]]]),
            "app/notes.pptx": pptx([f"ssn {dashed(SSN_A)}"]),
            "app/locked.docx": OLE,
            "app/big.docx": big,  # its zip directory is past the 16 KiB cap
        }
    )

    def fetch(url: str, max_bytes: int) -> IO[bytes]:
        return io.BytesIO(data)

    env.clients.services["layer-fetch"] = fetch
    doc = env.run(
        config(
            s3_targets=[],
            discover=frozenset({"ecr"}),
            ecr_read=True,
            max_object_bytes=16 * 1024,
        )
    )
    assert doc is not None
    valid(doc)
    ecr.assert_no_pending_responses()
    found = {(f["resource"]["field"], f["class"]): f for f in doc["findings"]}
    assert set(found) == {("app/seed.xlsx", "card"), ("app/notes.pptx", "us_ssn")}
    assert found[("app/seed.xlsx", "card")]["format"] == "xlsx"
    assert found[("app/notes.pptx", "us_ssn")]["format"] == "pptx"
    cov = next(c for c in doc["coverage"] if c["kind"] == "ecr")
    assert cov["scanned"] == 2
    assert cov["skipped"] == {"encrypted": 1, "document": 1}
    assert cov["partial"] == 1  # the large document, cut at the cap
