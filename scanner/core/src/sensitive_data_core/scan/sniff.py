"""What an object is, by its first bytes, and what its name says it is (#65).

A name is a claim anyone can change: a Word document renamed `notes.fff` or
`photo.jpg` is still a Word document. The readers (`scan/objects.py`) route
every object by what its bytes are (`sniff`), and compare that with what its
name claims (`declared`); when the two disagree (`disguised`) the object is
read by content and its findings say so, without a value.

Kinds, by magic bytes:

- `zip` (`PK\\x03\\x04`; Word, Excel and PowerPoint are told apart when the zip
  is opened, by `[Content_Types].xml` and `word/`, `xl/` or `ppt/`: `office_layout`);
- `ole` (`D0 CF 11 E0`: the older binary Office formats, or a rights-managed
  Open XML file); `pdf` (`%PDF-`);
- the compressed streams `gzip`, `bzip2`, `xz`, `zstd`; the archives `tar`
  (`ustar` at 257) and `7z`;
- `parquet`, `orc`, `avro`; a Parquet file under modular encryption (`PARE`)
  is `parquet_encrypted`; a Redis snapshot is `rdb`;
- `image`, `audio` and `video` by their containers' magic;
- executables and other binary with a NUL byte are `binary`;
- the rest is `text` when enough of it decodes as printable UTF-8, else
  `binary`.

Nothing here keeps a byte it was given; a kind is one of a closed set of names.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

SNIFF_BYTES = 8192

KINDS = frozenset(
    {
        "text",
        "zip",
        "docx",
        "xlsx",
        "pptx",
        "ole",
        "pdf",
        "gzip",
        "bzip2",
        "xz",
        "zstd",
        "tar",
        "7z",
        "parquet",
        "parquet_encrypted",
        "orc",
        "avro",
        "rdb",
        "image",
        "audio",
        "video",
        "binary",
    }
)
# What a name can claim beyond the kinds: an extension this module does not know.
UNKNOWN = "unknown"

MEDIA = frozenset({"image", "audio", "video"})
OFFICE = frozenset({"docx", "xlsx", "pptx"})
STREAMS = frozenset({"gzip", "bzip2", "xz", "zstd"})
ARCHIVES = frozenset({"zip", "tar", "7z"})

_EXT: dict[str, str] = {
    **dict.fromkeys(["docx", "docm", "dotx", "dotm"], "docx"),
    **dict.fromkeys(["xlsx", "xlsm", "xltx", "xltm"], "xlsx"),
    **dict.fromkeys(["pptx", "pptm", "potx", "ppsx"], "pptx"),
    **dict.fromkeys(
        ["zip", "jar", "war", "ear", "apk", "aar", "whl", "nupkg", "epub", "odt", "ods", "odp"],
        "zip",
    ),
    **dict.fromkeys(["doc", "dot", "xls", "xlt", "ppt", "pot", "pps", "msg", "msi"], "ole"),
    "pdf": "pdf",
    **dict.fromkeys(["gz", "tgz", "gzip"], "gzip"),
    **dict.fromkeys(["bz2", "tbz", "tbz2"], "bzip2"),
    **dict.fromkeys(["xz", "txz"], "xz"),
    **dict.fromkeys(["zst", "zstd", "tzst"], "zstd"),
    "tar": "tar",
    "7z": "7z",
    **dict.fromkeys(["parquet", "parq"], "parquet"),
    "orc": "orc",
    "avro": "avro",
    "rdb": "rdb",
    **dict.fromkeys(
        ["png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp", "heic", "heif", "ico"],
        "image",
    ),
    **dict.fromkeys(["wav", "mp3", "ogg", "oga", "opus", "flac", "m4a", "aac", "amr"], "audio"),
    **dict.fromkeys(["webm", "mp4", "m4v", "mov", "mkv", "avi", "3gp"], "video"),
    **dict.fromkeys(
        ["bin", "exe", "dll", "so", "dylib", "o", "a", "class", "pyc", "wasm"], "binary"
    ),
    **dict.fromkeys(
        [
            "txt", "text", "log", "csv", "tsv", "psv", "json", "jsonl", "ndjson", "xml", "html",
            "htm", "md", "rst", "yaml", "yml", "toml", "ini", "cfg", "conf", "env", "properties",
            "sql", "eml", "ics", "vcf", "srt", "vtt", "tf", "hcl", "py", "js", "mjs", "cjs",
            "ts", "tsx", "jsx", "java", "kt", "go", "rb", "php", "cs", "c", "h", "cpp", "hpp",
            "rs", "swift", "scala", "sh", "bash", "zsh", "ps1", "bat", "r", "pl", "lua", "out",
            "err", "trace", "dat", "data",
        ],
        "text",
    ),
}  # fmt: skip

_BZ2_BLOCK = (b"1AY&SY", b"\x17rE8P\x90")
_FTYP_AUDIO = frozenset({b"M4A ", b"M4B ", b"M4P ", b"F4A ", b"F4B "})
_FTYP_IMAGE = frozenset({b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"avif", b"avis"})
_PRINTABLE = re.compile("[\t\n\r\x20-\x7e\u00a0-\uffff]")
TEXT_RATIO = 0.85


def extension(name: str) -> str:
    base = name.rsplit("/", 1)[-1].lower()
    return base.rsplit(".", 1)[1] if "." in base.strip(".") else ""


def declared(name: str) -> str | None:
    """What the name's extension claims: one of `KINDS`, `unknown` for an extension this
    module does not know, or None for a name with no extension (it claims nothing)."""
    ext = extension(name)
    if not ext:
        return None
    return _EXT.get(ext, UNKNOWN)


def _media(head: bytes) -> str | None:
    if head.startswith(b"\x89PNG\r\n\x1a\n") or head.startswith(b"\xff\xd8\xff"):
        return "image"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image"
    if head[:4] in (b"II*\x00", b"MM\x00*") or head.startswith(b"\x00\x00\x01\x00\x01\x00"):
        return "image"
    if head[:2] == b"BM" and len(head) >= 14 and head[6:10] == b"\x00\x00\x00\x00":
        return "image"
    if head[:4] == b"RIFF" and len(head) >= 12:
        form = head[8:12]
        if form == b"WEBP":
            return "image"
        if form == b"WAVE":
            return "audio"
        if form == b"AVI ":
            return "video"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in _FTYP_IMAGE:
            return "image"
        return "audio" if brand in _FTYP_AUDIO else "video"
    if head.startswith(b"\x1aE\xdf\xa3"):
        return "video"  # Matroska, WebM
    if head[:4] in (b"OggS", b"fLaC") or head.startswith(b"ID3") or head.startswith(b"#!AMR"):
        return "audio"
    if len(head) >= 2 and head[0] == 0xFF and head[1] in (0xFB, 0xF3, 0xF2, 0xF1, 0xF9):
        return "audio"  # an MP3 frame or an AAC ADTS header
    return None


def looks_text(head: bytes) -> bool:
    """No NUL, and at least `TEXT_RATIO` of the characters printable once decoded as UTF-8."""
    if not head:
        return True
    if b"\x00" in head:
        return False
    text = head.decode("utf-8", errors="replace")
    if len(head) >= SNIFF_BYTES and text.endswith("�"):
        text = text.rstrip("�")  # a character cut by the sniff window
    if not text:
        return True
    printable = len(_PRINTABLE.findall(text)) - text.count("�")
    return printable / len(text) >= TEXT_RATIO


def sniff(head: bytes) -> str:
    """The kind the first bytes (up to `SNIFF_BYTES`) say the object is. A zip is `zip`
    here: whether it is Word, Excel or PowerPoint is decided when it is opened."""
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"(\xb5/\xfd"):
        return "zstd"
    if head.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head[:3] == b"BZh" and head[3:4].isdigit() and head[4:10] in _BZ2_BLOCK:
        return "bzip2"
    if head[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"PAR1"):
        return "parquet"
    if head.startswith(b"PARE"):
        return "parquet_encrypted"
    if head.startswith(b"Obj\x01"):
        return "avro"
    if head.startswith(b"ORC") and not looks_text(head):
        return "orc"
    if head.startswith(b"REDIS") and head[5:9].isdigit():
        return "rdb"
    media = _media(head)
    if media is not None:
        return media
    return "text" if looks_text(head) else "binary"


def office_layout(names: Iterable[str]) -> str | None:
    """`docx`, `xlsx` or `pptx` when a zip's entries are an Office Open XML package, else None."""
    seen = set(names)
    if "[Content_Types].xml" not in seen:
        return None
    for prefix, kind in (("word/", "docx"), ("xl/", "xlsx"), ("ppt/", "pptx")):
        if any(n.startswith(prefix) for n in seen):
            return kind
    return None


def compatible(claim: str | None, detected: str) -> bool:
    """Whether what the name claims fits what the bytes are (so the object is not disguised).

    A name with no extension claims nothing; content this module cannot name (`binary`)
    contradicts nothing. A zip may be an Office file, and a Word, Excel or PowerPoint name
    may hold a rights-managed file (an OLE container); audio and video share containers."""
    if claim is None or detected in ("binary", claim):
        return True
    if claim == "zip" and detected in OFFICE:
        return True
    if claim in OFFICE and detected == "ole":
        return True
    if claim == "parquet" and detected == "parquet_encrypted":
        return True
    if claim == UNKNOWN and detected == "text":
        return True
    return claim in ("audio", "video") and detected in ("audio", "video")
