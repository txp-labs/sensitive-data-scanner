"""Archives and PDFs for the tests, made with the standard library and pypdf (#65). Every
value is made up."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile

JPEG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + bytes(range(256)) * 64
)
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256)) * 8
SEVEN_Z = b"7z\xbc\xaf'\x1c\x00\x04" + b"\x00" * 64


def zip_of(entries: dict[str, bytes], method: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        for name, body in entries.items():
            z.writestr(name, body)
    return buf.getvalue()


def encrypted(data: bytes, only: str | None = None) -> bytes:
    """A zip whose entries (or only the one named `only`) say they are encrypted: the flag
    bit 0 set in the local and the central headers, as a password-protected zip has it."""
    out = bytearray(data)
    for sig, name_len_at, flag_at, header in (
        (b"PK\x03\x04", 26, 6, 30),
        (b"PK\x01\x02", 28, 8, 46),
    ):
        i = out.find(sig)
        while i >= 0:
            n = int.from_bytes(out[i + name_len_at : i + name_len_at + 2], "little")
            name = bytes(out[i + header : i + header + n]).decode()
            if only is None or name == only:
                out[i + flag_at] |= 0x1
            i = out.find(sig, i + 4)
    return bytes(out)


def tar_of(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, body in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            t.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def tar_gz(entries: dict[str, bytes]) -> bytes:
    return gzip.compress(tar_of(entries), mtime=0)


def tar_bz2(entries: dict[str, bytes]) -> bytes:
    return bz2.compress(tar_of(entries))


def xz(data: bytes) -> bytes:
    return lzma.compress(data)


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def pdf(lines: list[str], *, info: dict[str, str] | None = None, text: bool = True) -> bytes:
    """A one-page PDF whose text layer holds `lines` (none with `text=False`: a scan)."""
    body = "BT /F1 12 Tf 72 720 Td " + " ".join(f"({_escape(x)}) Tj 0 -16 Td" for x in lines)
    stream = (body + " ET").encode() if text else b"q 10 0 0 10 72 720 cm Q"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    if info:
        fields = " ".join(f"/{k} ({_escape(v)})" for k, v in info.items())
        objs.append(f"<< {fields} >>".encode())
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, o in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    trailer = b"<< /Size %d /Root 1 0 R" % (len(objs) + 1)
    if info:
        trailer += b" /Info %d 0 R" % len(objs)
    out += b"trailer\n" + trailer + b" >>\nstartxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def locked_pdf(data: bytes, *, user: str, owner: str = "owner-made-up") -> bytes:
    """The PDF encrypted (RC4, which pypdf runs without a cipher library)."""
    from pypdf import PdfReader, PdfWriter

    w = PdfWriter(clone_from=PdfReader(io.BytesIO(data)))
    w.encrypt(user_password=user, owner_password=owner, algorithm="RC4-128")
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def planted() -> dict[str, bytes]:
    """Objects that hold values in their bytes, in their archive entries' names and in a
    PDF's document information: for the no-leak suite. The names are the objects' keys."""
    from office_fixtures import docx
    from synthetic import CARDS, SSN_A, SSN_B, dashed, printed

    inner = zip_of({f"deep/{CARDS['mir']}-{SSN_A}.txt": f"ssn {dashed(SSN_A)}".encode()})
    return {
        f"archives/{SSN_A}.zip": zip_of(
            {
                f"hr/{CARDS['amex']}/{SSN_B}.csv": f"name,card\nA,{CARDS['jcb']}\n".encode(),
                f"nested/{dashed(SSN_B)}.zip": inner,
                f"{CARDS['visa']}.jpg": docx([f"card {printed(CARDS['discover'])}"]),
            }
        ),
        f"archives/{CARDS['unionpay']}.tar.gz": tar_gz(
            {f"etc/{SSN_B}/app.env": f"CARD={CARDS['mastercard']}\n".encode()}
        ),
        "docs/report.pdf": pdf(
            [f"card {printed(CARDS['amex'])}"],
            info={"Title": f"card {CARDS['amex']}", "Author": dashed(SSN_B), "Subject": SSN_A},
        ),
        f"docs/{SSN_A}.jpg": docx([f"ssn {dashed(SSN_B)}"]),
    }


def assert_read_by_content(findings: list[dict[str, object]]) -> None:
    """What `planted` holds was read: archive entries (named, masked), a PDF, a disguise."""
    resources = [f["resource"] for f in findings]
    assert any(isinstance(r, dict) and r.get("archivePathMasked") for r in resources)
    assert any(f["format"] == "pdf" for f in findings)
    assert any(f.get("disguised") for f in findings)
