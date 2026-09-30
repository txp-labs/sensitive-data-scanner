"""The accuracy benchmark's corpus: realistic, made-up documents with ground-truth labels.

Every document is built from a seed by `build_corpus`, the same bytes on every run, and
every value in it is made up: card numbers are random bodies with a computed Luhn check
digit (never a published test number, which the spec sets apart), SSNs and ITINs are
random structurally valid numbers (never a sample number), and every name is obviously
fake ("Testy McTestface"). Phone numbers are in the 555-01xx range kept for fiction;
addresses and mail use `example.com` and `.test`.

Each document carries its **truth**: how many occurrences of each class it holds, as
the scanner should report them. A value is labeled only where the scanner claims to
find it: in stored text, a card number, an SSN, an ITIN, or a date of birth next to a
birth-date word; in a conversation, any class a prompt asks for as well.

**Hard negatives** are values that look sensitive and are not: order and tracking
numbers (UPS, FedEx, USPS formats), phone numbers, invoice and PO ids, IBANs and ABA
routing numbers, Luhn-valid numbers that are not cards (IMEIs, member numbers), epoch
timestamps, version strings, UUIDs, AWS account ids, the SSA and IRS sample and
advertising numbers, ZIP+4 codes and dates that are not birth dates. Some documents hold
only one kind (`neg:<kind>`), so a false positive there names its source; the realistic
documents mix them with positives.

`python tests/bench_corpus.py DIR` writes the corpus to DIR with a `labels.jsonl`, for
reading it by eye.
"""

from __future__ import annotations

import bz2
import datetime as _dt
import gzip
import io
import json
import random
import sys
import tarfile
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

from sensitive_data_core.engine.conversation import Turn
from sensitive_data_core.engine.rules import itin_structure_valid, ssn_structure_valid
from sensitive_data_core.engine.spec import load_spec

SEED = 20260930
NOW = _dt.date(2026, 9, 29)
SPEC = load_spec()
_CARD = SPEC.classes["card"]
_TEST_CARDS = set(_CARD.test_numbers)
_SSN_SAMPLES = set(SPEC.classes["us_ssn"].dummy_values)
_ITIN_ADS = set(SPEC.classes["us_itin"].test_numbers)
_FIXED_TIME = (2026, 9, 28, 12, 0, 0)

FIRST = [
    "Testy",
    "Sample",
    "Placeholder",
    "Fakey",
    "Demo",
    "Mock",
    "Dummy",
    "Example",
    "Fixture",
    "Stubby",
    "Pseudo",
    "Notta",
]
LAST = [
    "McTestface",
    "Notreal",
    "Fakerson",
    "Madeup",
    "Samplesworth",
    "Fictional",
    "Imaginary",
    "Pretendo",
    "Mockington",
    "Stubbs",
    "Nobody",
    "Placeholderson",
]
WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
MERCHANTS = [
    "EXAMPLE MART",
    "TEST GROCERY CO",
    "SAMPLE FUEL 22",
    "FAKE CAFE",
    "PLACEHOLDER PHARMACY",
    "DEMO BOOKS",
    "MOCK HARDWARE",
]


def luhn(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - total % 10) % 10)


def luhn_ok(digits: str) -> bool:
    return luhn(digits[:-1]) == digits


@dataclass
class Doc:
    """One document: its object key, its bytes, and how many of each class it holds."""

    name: str
    category: str
    data: bytes
    truth: Counter[str] = field(default_factory=Counter)
    # The turns of each conversation in it, as its parser reads them: the conversation
    # engine's runner classifies these directly.
    conversations: list[list[Turn]] = field(default_factory=list)
    # Every value planted in it, sensitive or not: none may appear in any output.
    values: set[str] = field(default_factory=set)
    negatives: Counter[str] = field(default_factory=Counter)

    def __repr__(self) -> str:
        return f"Doc(name={self.name!r}, category={self.category!r})"


class Gen:
    """Made-up values from one seeded generator. `pos` labels a value; `neg` counts a hard
    negative by kind. Both remember the value for the no-leak check."""

    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)  # noqa: S311 - made-up data, not secrets
        self.truth: Counter[str] = Counter()
        self.negatives: Counter[str] = Counter()
        self.values: set[str] = set()
        self.conversations: list[list[Turn]] = []

    def start(self) -> None:
        self.truth = Counter()
        self.negatives = Counter()
        self.values = set()
        self.conversations = []

    def pos(self, cls: str, text: str) -> str:
        self.truth[cls] += 1
        self._remember(text)
        return text

    def neg(self, kind: str, text: str) -> str:
        self.negatives[kind] += 1
        self._remember(text)
        return text

    def _remember(self, text: str) -> None:
        digits = "".join(c for c in text if c.isdigit())
        if len(digits) >= 6:
            self.values.add(digits)

    # ---------------------------------------------------------------- basics

    def digits(self, n: int, first: str = "123456789") -> str:
        return self.r.choice(first) + "".join(self.r.choice("0123456789") for _ in range(n - 1))

    def name(self) -> str:
        return f"{self.r.choice(FIRST)} {self.r.choice(LAST)}"

    def email(self, name: str) -> str:
        return name.lower().replace(" ", ".") + "@example.com"

    def phone(self) -> str:
        area = self.r.choice(["208", "212", "303", "415", "503", "617", "702", "907"])
        line = f"01{self.r.randint(0, 99):02d}"
        style = self.r.randrange(5)
        if style == 0:
            return f"({area}) 555-{line}"
        if style == 1:
            return f"+1 {area} 555 {line}"
        if style == 2:
            return f"{area}.555.{line}"
        if style == 3:
            return f"1{area}555{line}"
        return f"{area}-555-{line}"

    def date(self, lo: int, hi: int) -> _dt.date:
        start = _dt.date(lo, 1, 1).toordinal()
        end = _dt.date(hi, 12, 28).toordinal()
        return _dt.date.fromordinal(self.r.randint(start, end))

    def fmt_date(self, d: _dt.date, style: int | None = None) -> str:
        s = self.r.randrange(4) if style is None else style
        if s == 0:
            return f"{d.month:02d}/{d.day:02d}/{d.year}"
        if s == 1:
            return d.isoformat()
        if s == 2:
            return f"{d.month}/{d.day}/{d.year}"
        return d.strftime("%B ") + f"{d.day}, {d.year}"

    # ---------------------------------------------------------------- positives

    def card(self) -> str:
        """A made-up card number of a known brand, never a published test number."""
        while True:
            brand = self.r.choice(
                [
                    "visa",
                    "visa",
                    "visa",
                    "mc",
                    "mc",
                    "mc2",
                    "amex",
                    "discover",
                    "jcb",
                    "diners",
                    "unionpay",
                ]
            )
            if brand == "visa":
                body = "4" + self.digits(14, "0123456789")
            elif brand == "mc":
                body = "5" + self.r.choice("12345") + self.digits(13, "0123456789")
            elif brand == "mc2":
                body = str(self.r.randint(2221, 2720)) + self.digits(11, "0123456789")
            elif brand == "amex":
                body = self.r.choice(["34", "37"]) + self.digits(12, "0123456789")
            elif brand == "discover":
                body = "6011" + self.digits(11, "0123456789")
            elif brand == "jcb":
                body = str(self.r.randint(3528, 3589)) + self.digits(11, "0123456789")
            elif brand == "diners":
                body = "36" + self.digits(11, "0123456789")
            else:
                body = "62" + str(self.r.randint(0, 1)) + self.digits(12, "0123456789")
            pan = luhn(body)
            if pan not in _TEST_CARDS and len(set(pan)) > 2:
                return pan

    def printed_card(self, pan: str) -> str:
        style = self.r.randrange(3)
        if style == 0:
            return pan
        sep = " " if style == 1 else "-"
        if len(pan) == 15:
            return f"{pan[:4]}{sep}{pan[4:10]}{sep}{pan[10:]}"
        if len(pan) == 14:
            return f"{pan[:4]}{sep}{pan[4:10]}{sep}{pan[10:]}"
        return sep.join(pan[i : i + 4] for i in range(0, len(pan), 4))

    def ssn(self) -> str:
        while True:
            area, group, serial = (
                self.r.randint(1, 899),
                self.r.randint(1, 99),
                self.r.randint(1, 9999),
            )
            v = f"{area:03d}{group:02d}{serial:04d}"
            if ssn_structure_valid(v) and v not in _SSN_SAMPLES:
                return v

    def itin(self) -> str:
        groups = [*range(50, 66), *range(70, 89), 90, 91, 92, *range(94, 100)]
        while True:
            area, group, serial = (
                self.r.randint(0, 99),
                self.r.choice(groups),
                self.r.randint(0, 9999),
            )
            v = f"9{area:02d}{group:02d}{serial:04d}"
            if itin_structure_valid(v) and v not in _ITIN_ADS:
                return v

    @staticmethod
    def dashed(v: str) -> str:
        return f"{v[:3]}-{v[3:5]}-{v[5:]}"

    def dob(self) -> _dt.date:
        return self.date(1942, 2006)

    # ---------------------------------------------------------------- negatives

    def order_number(self) -> str:
        style = self.r.randrange(3)
        if style == 0:
            return f"{self.digits(3)}-{self.digits(7, '0123456789')}-{self.digits(7, '0123456789')}"
        if style == 1:
            return self.digits(self.r.choice([10, 12, 16]))
        return f"SO-{self.digits(8)}"

    def tracking(self) -> tuple[str, str]:
        kind = self.r.choice(["ups", "fedex", "usps"])
        if kind == "ups":
            body = "".join(self.r.choice("0123456789ABCDEFGHJKLMNPRSTUVWXYZ") for _ in range(8))
            return kind, f"1Z{body[:6]}{self.digits(10, '0123456789')}"
        if kind == "fedex":
            n = self.r.choice([12, 15, 20])
            d = self.digits(n)
            return kind, d if self.r.random() < 0.5 else " ".join(
                d[i : i + 4] for i in range(0, n, 4)
            )
        d = "94" + self.digits(20, "0123456789")
        return kind, " ".join(d[i : i + 4] for i in range(0, 22, 4))

    def invoice(self) -> str:
        style = self.r.randrange(3)
        if style == 0:
            return f"INV-{self.r.randint(2019, 2026)}-{self.r.randint(1, 999999):06d}"
        if style == 1:
            return f"PO {self.digits(10, '45')}"
        return self.digits(8)

    def iban(self) -> str:
        country, bank_len = self.r.choice([("DE", 18), ("GB", 14), ("FR", 23), ("NL", 10)])
        bban = self.digits(bank_len, "0123456789")
        if country == "GB":
            bban = "".join(self.r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(4)) + bban
        if country == "NL":
            bban = "".join(self.r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(4)) + bban
        rearranged = bban + country + "00"
        num = "".join(str(int(c, 36)) for c in rearranged)
        check = 98 - int(num) % 97
        iban = f"{country}{check:02d}{bban}"
        return " ".join(iban[i : i + 4] for i in range(0, len(iban), 4))

    def routing(self) -> str:
        while True:
            body = self.r.choice(["0", "1", "2", "3"]) + self.digits(7, "0123456789")
            w = [3, 7, 1, 3, 7, 1, 3, 7]
            s = sum(int(c) * w[i] for i, c in enumerate(body))
            full = body + str((10 - s % 10) % 10)
            return full

    def account(self) -> str:
        return self.digits(self.r.randint(8, 12), "0123456789")

    def luhn_non_card(self) -> tuple[str, str]:
        """(label, number): Luhn-valid numbers that are not cards."""
        kind = self.r.randrange(3)
        if kind == 0:
            return "IMEI", luhn("35" + self.digits(12, "0123456789"))
        if kind == 1:
            return "Member number", luhn("6" + self.digits(14, "0123456789"))
        return "Loyalty ID", luhn("4" + self.digits(14, "0123456789"))

    def epoch(self) -> str:
        s = self.r.randint(1_600_000_000, 1_800_000_000)
        return str(s) if self.r.random() < 0.5 else str(s * 1000 + self.r.randint(0, 999))

    def version(self) -> str:
        style = self.r.randrange(3)
        if style == 0:
            return f"v{self.r.randint(0, 9)}.{self.r.randint(0, 30)}.{self.r.randint(0, 99)}"
        if style == 1:
            return (
                f"{self.r.randint(1, 9)}.{self.r.randint(0, 9)}.{self.digits(5)}.{self.digits(5)}"
            )
        y, m, d = self.r.randint(2019, 2026), self.r.randint(1, 12), self.r.randint(1, 28)
        return f"build {y}{m:02d}{d:02d}.{self.r.randint(1, 9)}"

    def uuid(self) -> str:
        # Some UUIDs are all digits in a group or more: realistic, and the hard kind.
        hexd = "0123456789abcdef" if self.r.random() < 0.6 else "0123456789"
        g = ["".join(self.r.choice(hexd) for _ in range(n)) for n in (8, 4, 4, 4, 12)]
        return "-".join(g)

    def aws_account(self) -> str:
        return self.digits(12)

    def zip4(self) -> str:
        return f"{self.r.randint(10000, 99950)}-{self.r.randint(1, 9999):04d}"


# -------------------------------------------------------------------- file formats


def _zipinfo(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _zip(parts: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in parts.items():
            z.writestr(_zipinfo(name), body)
    return buf.getvalue()


_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
_P = "http://schemas.openxmlformats.org/presentationml/2006/main"


def docx(paragraphs: list[str]) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{escape(p)}</w:t></w:r></w:p>" for p in paragraphs)
    return _zip(
        {
            "[Content_Types].xml": "<Types/>",
            "word/document.xml": f'<w:document xmlns:w="{_W}"><w:body>{body}</w:body></w:document>',
        }
    )


def xlsx(rows: list[list[str]]) -> bytes:
    strings: list[str] = []
    cells = []
    for r, row in enumerate(rows, start=1):
        out = []
        for c, value in enumerate(row):
            strings.append(value)
            out.append(f'<c r="{chr(65 + c)}{r}" t="s"><v>{len(strings) - 1}</v></c>')
        cells.append(f'<row r="{r}">{"".join(out)}</row>')
    si = "".join(f"<si><t>{escape(s)}</t></si>" for s in strings)
    return _zip(
        {
            "[Content_Types].xml": "<Types/>",
            "xl/worksheets/sheet1.xml": f'<worksheet xmlns="{_S}"><sheetData>'
            f"{''.join(cells)}</sheetData></worksheet>",
            "xl/sharedStrings.xml": f'<sst xmlns="{_S}">{si}</sst>',
        }
    )


def pptx(slides: list[list[str]]) -> bytes:
    parts: dict[str, str | bytes] = {"[Content_Types].xml": "<Types/>"}
    for i, paras in enumerate(slides, start=1):
        body = "".join(f"<a:p><a:r><a:t>{escape(t)}</a:t></a:r></a:p>" for t in paras)
        parts[f"ppt/slides/slide{i}.xml"] = (
            f'<p:sld xmlns:p="{_P}" xmlns:a="{_A}"><p:cSld><p:spTree><p:sp><p:txBody>'
            f"{body}</p:txBody></p:sp></p:spTree></p:cSld></p:sld>"
        )
    return _zip(parts)


def _pdf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def pdf(lines: list[str]) -> bytes:
    """A PDF with one text line per row, 40 rows a page."""
    pages = [lines[i : i + 40] for i in range(0, len(lines), 40)] or [[]]
    objs: list[bytes] = [b"<< /Type /Catalog /Pages 2 0 R >>", b""]
    kids = []
    font = 3
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for page in pages:
        body = "BT /F1 10 Tf 50 760 Td " + " ".join(f"({_pdf_escape(x)}) Tj 0 -18 Td" for x in page)
        stream = (body + " ET").encode("latin-1")
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        content = len(objs)
        objs.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R"
            b" /Resources << /Font << /F1 %d 0 R >> >> >>" % (content, font)
        )
        kids.append(len(objs))
    objs[1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (
        b" ".join(b"%d 0 R" % k for k in kids),
        len(kids),
    )
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, o in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def tar_gz(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1790000000
            t.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)


def parquet(columns: dict[str, list[object]], types: dict[str, str]) -> bytes:
    import pyarrow as pa
    import pyarrow.parquet as pq

    arrays = {}
    for name, values in columns.items():
        t = types.get(name, "string")
        typ = {
            "string": pa.string(),
            "int64": pa.int64(),
            "date": pa.date32(),
            "timestamp": pa.timestamp("ms"),
        }[t]
        arrays[name] = pa.array(values, type=typ)
    buf = io.BytesIO()
    pq.write_table(pa.table(arrays), buf, compression="snappy")
    return buf.getvalue()


# -------------------------------------------------------------------- documents


def _dob_word(g: Gen) -> str:
    return g.r.choice(["DOB", "Date of birth", "Birth date", "D.O.B.", "Birthdate"])


def statement_lines(g: Gen, *, card_statement: bool) -> list[str]:
    """A bank or card statement, as its lines. A card statement may print the full card."""
    name = g.name()
    start = g.date(2025, 2026)
    lines = [
        "FIRST EXAMPLE BANK - " + ("CREDIT CARD STATEMENT" if card_statement else "CHECKING"),
        f"Statement period: {g.fmt_date(start, 0)} - "
        f"{g.fmt_date(start + _dt.timedelta(days=30), 0)}",
        f"Account holder: {name}",
        "Mailing address: 100 Example Way, Testville, ID " + g.neg("zip4", g.zip4()),
        "Customer service: " + g.neg("phone", g.phone()),
    ]
    if card_statement:
        pan = g.card()
        if g.r.random() < 0.6:
            lines.append("Card number: " + g.pos("card", g.printed_card(pan)))
        else:
            lines.append(f"Card number: XXXX XXXX XXXX {pan[-4:]}")
        lines.append(
            f"Payment due date: {g.fmt_date(start + _dt.timedelta(days=55), 0)}"
            "   Minimum payment: $35.00"
        )
    else:
        lines.append("Account number: " + g.neg("account", g.account()))
        lines.append("Routing number (ABA): " + g.neg("routing", g.routing()))
    lines.append("Date        Description                                   Amount")
    day = start
    for _ in range(g.r.randint(8, 16)):
        day += _dt.timedelta(days=g.r.randint(0, 3))
        amount = f"{g.r.randint(1, 900)}.{g.r.randint(0, 99):02d}"
        kind = g.r.randrange(6)
        if kind == 0:
            ref = g.neg("reference", g.digits(g.r.choice([10, 11, 12])))
            desc = f"POS PURCHASE {g.r.choice(MERCHANTS)} REF {ref}"
        elif kind == 1:
            desc = f"ACH DEPOSIT PAYROLL PPD ID {g.neg('reference', g.digits(10))}"
        elif kind == 2:
            desc = f"ONLINE TRANSFER CONF# {g.neg('reference', g.digits(9))}"
        elif kind == 3:
            desc = f"CHECK #{g.r.randint(1000, 9999)}"
        elif kind == 4:
            desc = f"INTL WIRE FROM {g.neg('iban', g.iban())}"
        else:
            desc = f"CARD PURCHASE {g.r.choice(MERCHANTS)} ORDER {g.neg('order', g.order_number())}"
        lines.append(f"{g.fmt_date(day, 0)}  {desc:<48}  -{amount}")
    lines.append(f"Questions? Call {g.neg('phone', g.phone())} or visit example.com/help")
    return lines


def crm_csv(g: Gen, rows: int) -> str:
    head = "customer_id,full_name,email,phone,card_number,order_id,tracking_number,created_at,zip"
    out = [head]
    for _ in range(rows):
        name = g.name()
        card = g.pos("card", g.printed_card(g.card())) if g.r.random() < 0.5 else ""
        _, track = g.tracking()
        out.append(
            ",".join(
                [
                    g.neg("customer_id", g.digits(8)),
                    name,
                    g.email(name),
                    g.neg("phone", g.phone()),
                    card,
                    g.neg("order", g.order_number()),
                    g.neg("tracking", track),
                    g.fmt_date(g.date(2024, 2026), 1) + "T10:15:00Z",
                    g.neg("zip4", g.zip4()),
                ]
            )
        )
    return "\n".join(out) + "\n"


def hr_csv(g: Gen, rows: int) -> str:
    head = "employee_id,name,ssn,date_of_birth,hire_date,routing_number,account_number,salary"
    out = [head]
    for _ in range(rows):
        roll = g.r.random()
        if roll < 0.7:
            v = g.ssn()
            tax = g.pos("us_ssn", g.dashed(v) if g.r.random() < 0.6 else v)
        elif roll < 0.85:
            v = g.itin()
            tax = g.pos("us_itin", g.dashed(v) if g.r.random() < 0.6 else v)
        else:
            tax = ""
        dob = g.pos("dob", g.fmt_date(g.dob(), g.r.choice([0, 1, 2])))
        out.append(
            ",".join(
                [
                    g.neg("employee_id", "E" + g.digits(6)),
                    g.name(),
                    tax,
                    dob,
                    g.neg("date", g.fmt_date(g.date(2012, 2026), g.r.choice([0, 1]))),
                    g.neg("routing", g.routing()),
                    g.neg("account", g.account()),
                    str(g.r.randint(40, 190) * 1000),
                ]
            )
        )
    return "\n".join(out) + "\n"


def ticket_text(g: Gen) -> str:
    """A support ticket's description, as a customer writes it."""
    name = g.name()
    parts = [f"Hi, this is {name}."]
    order = g.neg("order", g.order_number())
    kind = g.r.randrange(8)
    if kind == 7:
        # A card with its expiry right after it, as people type them.
        parts.append(
            "Please use my other card "
            + g.pos("card", g.printed_card(g.card()))
            + f" {g.r.randint(1, 12):02d}/{g.r.randint(27, 31)} for the renewal."
        )
    elif kind == 6:
        parts.append(
            "I don't have an SSN, my ITIN is "
            + g.pos("us_itin", g.dashed(g.itin()) if g.r.random() < 0.7 else g.itin())
            + ". I heard about the refund on social media, post "
            + g.neg("social_media", g.digits(9))
            + "."
        )
    elif kind == 0:
        parts.append(
            f"I was charged twice for order {order}. The card I used is "
            + g.pos("card", g.printed_card(g.card()))
            + ", can you refund one?"
        )
    elif kind == 1:
        _, track = g.tracking()
        parts.append(f"My package hasn't arrived. Tracking number {g.neg('tracking', track)}.")
    elif kind == 2:
        parts.append(
            "For the tax form you asked for, my SSN is "
            + g.pos("us_ssn", g.dashed(g.ssn()))
            + " and my date of birth is "
            + g.pos("dob", g.fmt_date(g.dob()))
            + ", charged on "
            + g.neg("date_not_dob", g.fmt_date(g.date(2026, 2026), g.r.choice([0, 1, 2])))
            + "."
        )
    elif kind == 3:
        parts.append(
            f"Please call me back at {g.neg('phone', g.phone())}, reference "
            f"{g.neg('invoice', g.invoice())}."
        )
    elif kind == 4:
        parts.append(
            "Updating billing: new visa "
            + g.pos("card", g.card())
            + f" exp {g.r.randint(1, 12):02d}/{g.r.randint(27, 31)}."
        )
    else:
        parts.append(
            f"The app crashes on version {g.neg('version', g.version())}, "
            f"request id {g.neg('uuid', g.uuid())}."
        )
    parts.append("Thanks!")
    return " ".join(parts)


def ticket_json(g: Gen, n: int) -> str:
    tickets = []
    for _ in range(n):
        tickets.append(
            {
                "id": int(g.neg("ticket_id", g.digits(7))),
                "created_at": g.fmt_date(g.date(2025, 2026), 1) + "T08:30:00Z",
                "subject": g.r.choice(["Refund", "Where is my order", "Billing", "App crash"]),
                "description": ticket_text(g),
                "requester": {"phone": g.neg("phone", g.phone())},
                "tags": ["web", "priority-" + str(g.r.randint(1, 4))],
            }
        )
    return json.dumps({"tickets": tickets}, indent=1)


def email_text(g: Gen) -> str:
    name = g.name()
    day = g.date(2025, 2026)
    body = ticket_text(g)
    if g.r.random() < 0.3:
        body += (
            "\n\nAlso my new direct deposit: routing "
            + g.neg("routing", g.routing())
            + " account "
            + g.neg("account", g.account())
            + "."
        )
    return (
        f"From: {name} <{g.email(name)}>\n"
        "To: support@example.com\n"
        f"Date: {day.strftime('%a, %d %b %Y')} 10:12:00 -0600\n"
        f"Message-ID: <{g.neg('uuid', g.uuid())}@mail.example.com>\n"
        "Subject: Re: your request\n\n"
        f"{body}\n\n--\n{name}\n{g.neg('phone', g.phone())}\n"
    )


# -------------------------------------------------------------------- conversations


def _spoken(digits: str, group: int = 4) -> str:
    chunks = [digits[i : i + group] for i in range(0, len(digits), group)]
    return ", ".join(" ".join(WORDS[int(c)] for c in chunk) for chunk in chunks)


def _spoken_loose(g: Gen, digits: str) -> str:
    """Digits as an ASR engine writes a caller: words, "oh", "double", fillers, or digits."""
    style = g.r.randrange(5)
    if style == 0:
        return " ".join(WORDS[int(c)] for c in digits)
    if style == 1:
        out = []
        i = 0
        while i < len(digits):
            if i + 1 < len(digits) and digits[i] == digits[i + 1] and g.r.random() < 0.7:
                out.append("double " + WORDS[int(digits[i])])
                i += 2
                continue
            out.append("oh" if digits[i] == "0" else WORDS[int(digits[i])])
            i += 1
        return " ".join(out)
    if style == 2:
        words = [WORDS[int(c)] for c in digits]
        words.insert(g.r.randint(2, len(words) - 2), g.r.choice(["uh", "um"]))
        return " ".join(words)
    if style == 3:
        return " ".join(digits)
    return _spoken(digits, 4)


def _spoken_date(d: _dt.date) -> str:
    return d.strftime("%B ") + f"{d.day}, {d.year}"


def _spoken_year(y: int) -> str:
    tens = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]
    teens = [
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
    ]
    head = "nineteen" if y < 2000 else "two thousand"
    rest = y % 100
    if y >= 2000:
        tail = WORDS[rest] if rest < 10 else teens[rest - 10] if rest < 20 else tens[rest // 10]
        return f"{head} {tail}" if rest else head
    if rest < 10:
        return f"{head} oh {WORDS[rest]}"
    if rest < 20:
        return f"{head} {teens[rest - 10]}"
    return f"{head} {tens[rest // 10]}" + (f" {WORDS[rest % 10]}" if rest % 10 else "")


_ORD = [
    "",
    "first",
    "second",
    "third",
    "fourth",
    "fifth",
    "sixth",
    "seventh",
    "eighth",
    "ninth",
    "tenth",
    "eleventh",
    "twelfth",
    "thirteenth",
    "fourteenth",
    "fifteenth",
    "sixteenth",
    "seventeenth",
    "eighteenth",
    "nineteenth",
    "twentieth",
]


def _spoken_dob(g: Gen, d: _dt.date) -> str:
    day = (
        _ORD[d.day]
        if d.day <= 20
        else (
            ("twenty" if d.day < 30 else "thirty") + (f"-{_ORD[d.day % 10]}" if d.day % 10 else "")
        )
    )
    if d.day in (20, 30):
        day = "twentieth" if d.day == 20 else "thirtieth"
    month = d.strftime("%B")
    style = g.r.randrange(3)
    if style == 0:
        return f"{month} {day}, {_spoken_year(d.year)}"
    if style == 1:
        return f"the {day} of {month} {_spoken_year(d.year)}"
    return _spoken_date(d)


def voice_call(g: Gen) -> list[Turn]:
    """An agent call (Contact Lens voice): verification, a payment, small talk, and the
    numbers a call carries that are not sensitive."""
    t: list[Turn] = []
    ms = 0

    def say(speaker: str, text: str) -> None:
        nonlocal ms
        t.append(Turn(speaker, text, "speech", ms, ms + 2000))
        ms += 2500

    say("agent", "Thank you for calling Example Services, this is Demo, how can I help?")
    say("customer", "Hi, I'm calling about my bill.")
    steps = [
        "dob",
        "ssn",
        "last4",
        "card",
        "order",
        "callback",
        "zip",
        "confirmation",
        "card_last4",
        "birth_year",
        "hold_card",
        "amount",
    ]
    for step in g.r.sample(steps, 5):
        if step == "dob":
            say(
                "agent",
                g.r.choice(["Can I have your date of birth please?", "And what's your birthday?"]),
            )
            d = g.dob()
            roll = g.r.random()
            text = _spoken_dob(g, d) if roll < 0.6 else g.fmt_date(d, g.r.choice([0, 2]))
            say("customer", g.pos("dob", text))
        elif step == "ssn":
            say(
                "agent",
                g.r.choice(
                    [
                        "And your social security number?",
                        "Can you verify your nine digit social?",
                        "I'll need your SSN to verify.",
                    ]
                ),
            )
            v = g.ssn()
            if g.r.random() < 0.6:
                say("customer", "It's " + g.pos("us_ssn", _spoken_loose(g, v)))
            else:
                say("customer", g.pos("us_ssn", g.dashed(v)))
        elif step == "last4":
            say("agent", "Just the last four of your social is fine.")
            say("customer", g.pos("us_ssn_last4", " ".join(WORDS[int(c)] for c in g.digits(4))))
        elif step in ("card", "hold_card"):
            say("agent", "What's the card number you'd like to use?")
            pan = g.card()
            if step == "hold_card":
                # The number comes a turn late: the prompt has passed, the context has not.
                say("customer", "Hang on, let me grab it.")
                say("agent", "Sure, take your time.")
                say("customer", g.pos("card", _spoken(pan)))
            elif g.r.random() < 0.5:
                half = 8
                say("customer", g.pos("card", _spoken_loose(g, pan[:half])))
                g.values.add(pan)
                say("agent", g.r.choice(["mm-hmm", "okay", "yes"]))
                say("customer", _spoken_loose(g, pan[half:]))
            else:
                say("customer", g.pos("card", g.printed_card(pan)))
            if g.r.random() < 0.4:
                # The agent reads it back: the value is in the transcript twice.
                say(
                    "agent",
                    "Let me read that back, "
                    + g.pos("card", g.printed_card(pan))
                    + ", is that right?",
                )
                say("customer", "Yes.")
            say("agent", "And the three digit security code on the back?")
            say("customer", g.pos("cvv", " ".join(WORDS[int(c)] for c in g.digits(3))))
        elif step == "card_last4":
            say("agent", "Which card do you want to use, the card number please?")
            say("customer", "The Visa ending in " + g.neg("card_last4", g.digits(4, "0123456789")))
        elif step == "birth_year":
            say("agent", "And your date of birth?")
            say("customer", "Born in " + g.neg("birth_year", str(g.dob().year)))
        elif step == "order":
            say("agent", "Do you have the order number handy?")
            say("customer", "Yes, it's " + g.neg("order", g.order_number()))
        elif step == "callback":
            say("agent", "What's the best number to reach you?")
            digits = "".join(c for c in g.phone() if c.isdigit())[-10:]
            say("customer", g.neg("phone", _spoken(digits, 3)))
        elif step == "confirmation":
            conf = g.digits(g.r.choice([9, 10, 12]))
            say("agent", "Your confirmation number is " + g.neg("confirmation", _spoken(conf, 3)))
        elif step == "amount":
            say("customer", f"The charge was ${g.r.randint(1000, 9999):,}.{g.r.randint(0, 99):02d}")
        else:
            say("agent", "And the zip code on the account?")
            say("customer", g.neg("zip4", g.zip4()))
    say("agent", "Great, you're all set. Anything else?")
    say("customer", "No, thank you.")
    return t


def chat_session(g: Gen) -> list[Turn]:
    """A Connect chat: typed answers, an order lookup, values pasted without a prompt."""
    t: list[Turn] = []
    ms = 1_790_607_600_000

    def say(speaker: str, text: str) -> None:
        nonlocal ms
        t.append(Turn(speaker, text, "chat", ms, None))
        ms += 10_000

    say("agent", "Hi! How can I help you today?")
    for kind in g.r.sample(range(8), 2):
        if kind == 0:
            say(
                "customer",
                "I need to update my card, the new one is "
                + g.pos("card", g.printed_card(g.card())),
            )
            say("agent", "Thanks, and the expiration date?")
            say("customer", f"{g.r.randint(1, 12):02d}/{g.r.randint(27, 31)}")
        elif kind == 1:
            say("customer", f"Where's my order? It's {g.neg('order', g.order_number())}")
            _, track = g.tracking()
            say("agent", f"It shipped, tracking {g.neg('tracking', track)}.")
        elif kind == 2:
            say("agent", "To verify, what's your account number?")
            say("customer", g.pos("account_number", g.account()))
            say("agent", "And your date of birth?")
            say("customer", g.pos("dob", g.fmt_date(g.dob(), g.r.choice([0, 2]))))
        elif kind == 3:
            say("customer", "My ITIN is " + g.pos("us_itin", g.dashed(g.itin())) + " for the form")
            say("agent", "Got it, thanks.")
        elif kind == 4:
            # Pasted with no word for it: the number alone.
            say("customer", "here you go " + g.pos("card", g.card()))
        elif kind == 5:
            say("agent", "What's the phone number on the account?")
            say("customer", g.neg("phone", g.phone()))
        elif kind == 6:
            say("customer", "Can you check invoice " + g.neg("invoice", g.invoice()) + "?")
        else:
            say("agent", "Please confirm your social.")
            v = g.ssn()
            say("customer", g.pos("us_ssn", v if g.r.random() < 0.5 else g.dashed(v)))
    say("agent", "Anything else I can help with?")
    say("customer", "no thanks")
    return t


def ivr_prompts(g: Gen) -> list[tuple[str, str, str | None]]:
    """(prompt, keyed answer, class or None) pairs: prompted DTMF."""
    out: list[tuple[str, str, str | None]] = []
    for step in g.r.sample(["ssn", "dob", "card", "cvv", "pin", "account", "zip", "menu"], 4):
        if step == "ssn":
            v = g.ssn() if g.r.random() < 0.8 else g.itin()
            out.append(
                (
                    "Please enter your nine digit Social Security number, followed by pound.",
                    v + "#",
                    "us_ssn" if v[0] != "9" else "us_itin",
                )
            )
        elif step == "dob":
            d = g.dob()
            out.append(
                (
                    "Please enter your date of birth as eight digits.",
                    f"{d.month:02d}{d.day:02d}{d.year}",
                    "dob",
                )
            )
        elif step == "card":
            out.append(
                ("Please enter your card number followed by the pound key.", g.card() + "#", "card")
            )
        elif step == "cvv":
            out.append(("Enter the three digit security code.", g.digits(3, "0123456789"), "cvv"))
        elif step == "pin":
            out.append(("Please enter your four digit PIN.", g.digits(4, "0123456789"), "pin"))
        elif step == "account":
            out.append(("Please enter your account number.", g.account(), "account_number"))
        elif step == "zip":
            out.append(
                ("Please enter your five digit zip code.", str(g.r.randint(10000, 99950)), None)
            )
        else:
            out.append(
                ("For billing, press 1. For technical support, press 2.", g.r.choice("12"), None)
            )
    return out


def connect_chat_doc(turns: list[Turn]) -> str:
    role = {"agent": "AGENT", "customer": "CUSTOMER", "bot": "SYSTEM"}
    base = _dt.datetime(2026, 9, 28, 15, 0, tzinfo=_dt.UTC)
    return json.dumps(
        {
            "Version": "2019-08-26",
            "AWSAccountId": "000000000000",
            "InstanceId": "66666666-7777-8888-9999-000000000000",
            "ContactId": "11111111-2222-3333-4444-555555555555",
            "Participants": [{"ParticipantId": "p-agent"}, {"ParticipantId": "p-customer"}],
            "Transcript": [
                {
                    "AbsoluteTime": (base + _dt.timedelta(seconds=10 * i))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
                    "Content": x.text,
                    "ContentType": "text/plain",
                    "Id": f"m{i}",
                    "Type": "MESSAGE",
                    "ParticipantId": "p-" + x.speaker,
                    "ParticipantRole": role[x.speaker],
                }
                for i, x in enumerate(turns)
            ],
        }
    )


def contact_lens_doc(turns: list[Turn]) -> str:
    return json.dumps(
        {
            "AccountId": "000000000000",
            "Channel": "VOICE",
            "JobStatus": "COMPLETED",
            "LanguageCode": "en-US",
            "Participants": [
                {"ParticipantId": "AGENT", "ParticipantRole": "AGENT"},
                {"ParticipantId": "CUSTOMER", "ParticipantRole": "CUSTOMER"},
            ],
            "ConversationCharacteristics": {"TotalConversationDurationMillis": 90000},
            "CustomerMetadata": {
                "ContactId": "11111111-2222-3333-4444-555555555555",
                "InstanceId": "66666666-7777-8888-9999-000000000000",
            },
            "Transcript": [
                {
                    "BeginOffsetMillis": x.begin_ms,
                    "EndOffsetMillis": x.end_ms,
                    "Id": f"turn-{i}",
                    "ParticipantId": x.speaker.upper(),
                    "Content": x.text,
                    "Sentiment": "NEUTRAL",
                }
                for i, x in enumerate(turns)
            ],
        }
    )


def flow_log_events(g: Gen) -> tuple[str, list[list[Turn]]]:
    """Connect flow log events, one JSON per line: each prompt and its keyed answer."""
    lines = []
    convs = []
    ts = _dt.datetime(2026, 9, 28, 15, 0, tzinfo=_dt.UTC)
    for prompt, answer, cls in ivr_prompts(g):
        if cls:
            g.pos(cls, answer)
        else:
            g.neg("ivr_menu", answer)
        stamp = ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        ts += _dt.timedelta(seconds=15)
        lines.append(
            json.dumps(
                {
                    "ContactId": "11111111-2222-3333-4444-555555555555",
                    "ContactFlowId": "arn:aws:connect:us-west-2:000000000000:instance/"
                    "66666666-7777-8888-9999-000000000000/contact-flow/abc",
                    "ContactFlowName": "Payments",
                    "ContactFlowModuleType": "GetUserInput",
                    "Identifier": "Get customer input",
                    "Timestamp": stamp,
                    "Parameters": {"Text": prompt, "Timeout": "8"},
                    "Results": answer,
                }
            )
        )
        ms = int(ts.timestamp() * 1000) - 15_000
        convs.append(
            [Turn("bot", prompt, "speech", ms, None), Turn("customer", answer, "dtmf", ms, None)]
        )
    return "\n".join(lines) + "\n", convs


def lex_log(g: Gen) -> tuple[str, list[list[Turn]]]:
    """Lex V2 conversation logs: each record is the caller's input and the bot's reply."""
    records = []
    turns: list[Turn] = []
    ts = _dt.datetime(2026, 9, 28, 15, 0, tzinfo=_dt.UTC)
    pairs = ivr_prompts(g)
    inputs = ["I want to pay my bill"] + [a for _, a, _ in pairs]
    replies = [p for p, _, _ in pairs] + ["Thanks, goodbye."]
    classes: list[str | None] = [None, *(c for _, _, c in pairs)]
    for n, (said, reply, cls) in enumerate(zip(inputs, replies, classes, strict=True)):
        if n:
            if cls:
                g.pos(cls, said)
            else:
                g.neg("ivr_menu", said)
        stamp = ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        ms = int(ts.timestamp() * 1000)
        ts += _dt.timedelta(seconds=12)
        records.append(
            json.dumps(
                {
                    "timestamp": stamp,
                    "sessionId": "session-made-up-1",
                    "inputMode": "DTMF" if cls else "Speech",
                    "inputTranscript": said,
                    "messages": [{"contentType": "PlainText", "content": reply}],
                    "bot": {"name": "PaymentsBot", "version": "3"},
                    "sessionState": {"intent": {"name": "PayBill"}},
                }
            )
        )
        turns.append(Turn("customer", said, "speech", ms, None))
        turns.append(Turn("bot", reply, "speech", ms, None))
    return "\n".join(records) + "\n", [turns]


# -------------------------------------------------------------------- logs


def app_log(g: Gen, n: int) -> str:
    lines = []
    ts = _dt.datetime(2026, 9, 28, 3, 0, tzinfo=_dt.UTC)
    for _ in range(n):
        ts += _dt.timedelta(milliseconds=g.r.randint(5, 4000))
        stamp = ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        kind = g.r.randrange(9)
        if kind == 0:
            msg = f"payment declined card={g.pos('card', g.card())} reason=insufficient_funds"
        elif kind == 1:
            msg = f"order {g.neg('order', g.order_number())} shipped via {g.tracking()[0]}"
        elif kind == 2:
            msg = f"request_id={g.neg('uuid', g.uuid())} latency_ms={g.r.randint(3, 900)}"
        elif kind == 3:
            msg = f"sync account={g.neg('aws_account', g.aws_account())} region=us-west-2 ok"
        elif kind == 4:
            msg = f"client version {g.neg('version', g.version())} ts={g.neg('epoch', g.epoch())}"
        elif kind == 5:
            msg = f"sms sent to {g.neg('phone', g.phone())} template=otp"
        elif kind == 6:
            msg = f"invoice {g.neg('invoice', g.invoice())} generated total=12.50"
        elif kind == 7:
            msg = f"kyc submitted ssn={g.pos('us_ssn', g.dashed(g.ssn()))} status=pending"
        else:
            msg = f"social media share post_id={g.neg('social_media', g.digits(9))} ok"
        level = g.r.choice(["INFO", "INFO", "WARN", "DEBUG"])
        lines.append(f"{stamp} {level} [worker-{g.r.randint(1, 8)}] {msg}")
    return "\n".join(lines) + "\n"


def access_log(g: Gen, n: int) -> str:
    lines = []
    ts = _dt.datetime(2026, 9, 28, 3, 0, tzinfo=_dt.UTC)
    for _ in range(n):
        ts += _dt.timedelta(seconds=g.r.randint(0, 30))
        ip = f"198.51.100.{g.r.randint(1, 254)}"
        kind = g.r.randrange(5)
        if kind == 0:
            path = f"/api/orders/{g.neg('order', g.digits(10))}"
        elif kind == 1:
            path = f"/track?number={g.neg('tracking', g.tracking()[1].replace(' ', ''))}"
        elif kind == 2:
            path = f"/checkout?cc={g.pos('card', g.card())}&amt=19.99"
        elif kind == 3:
            path = f"/static/app.{g.neg('version', g.digits(8))}.js"
        else:
            path = f"/api/sessions/{g.neg('uuid', g.uuid())}"
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        chrome = f"{g.r.randint(100, 140)}.0.{g.digits(4)}.{g.r.randint(10, 200)}"
        agent = f"Mozilla/5.0 (X11; Linux x86_64) Chrome/{chrome}"
        lines.append(
            f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" 200 {g.r.randint(100, 90000)} "-" "{agent}"'
        )
    return "\n".join(lines) + "\n"


def lambda_log(g: Gen, n: int) -> str:
    lines = []
    ts = _dt.datetime(2026, 9, 28, 3, 0, tzinfo=_dt.UTC)
    for _ in range(n):
        ts += _dt.timedelta(milliseconds=g.r.randint(5, 4000))
        rid = g.neg("uuid", g.uuid())
        kind = g.r.randrange(5)
        rec: dict[str, object] = {
            "timestamp": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": "INFO",
            "requestId": rid,
        }
        if kind == 0:
            rec["message"] = "customer lookup"
            rec["customer"] = {
                "name": g.name(),
                "dateOfBirth": g.pos("dob", g.fmt_date(g.dob(), 1)),
                "phone": g.neg("phone", g.phone()),
                "createdAt": g.neg("date_not_dob", g.fmt_date(g.date(2020, 2026), 1)),
            }
        elif kind == 1:
            rec["message"] = "charge created"
            rec["payment"] = {"cardNumber": g.pos("card", g.card()), "amount": 1999}
        elif kind == 2:
            rec["message"] = "billing run"
            rec["accountId"] = g.neg("aws_account", g.aws_account())
            rec["durationMs"] = g.r.randint(10, 9000)
        elif kind == 3:
            rec["message"] = "shipment"
            rec["trackingNumber"] = g.neg("tracking", g.tracking()[1])
            rec["orderId"] = g.neg("order", g.order_number())
        else:
            rec["message"] = "tax profile saved"
            rec["taxId"] = g.pos("us_ssn", g.dashed(g.ssn()))
        lines.append(json.dumps(rec))
    return "\n".join(lines) + "\n"


# -------------------------------------------------------------------- hard negatives


def negative_doc(g: Gen, kind: str) -> str:
    """One kind of hard negative, many times, in the context it lives in."""
    lines = []
    for _ in range(g.r.randint(12, 20)):
        if kind == "order":
            lines.append(f"Order #{g.neg(kind, g.order_number())} placed, total $42.00")
        elif kind == "tracking":
            carrier, number = g.tracking()
            lines.append(f"{carrier.upper()} {g.neg(kind, number)} out for delivery")
        elif kind == "phone":
            lines.append(f"Call us at {g.neg(kind, g.phone())} Mon-Fri 8-5")
        elif kind == "invoice":
            lines.append(f"Invoice {g.neg(kind, g.invoice())} due in 30 days")
        elif kind == "iban":
            lines.append(f"Beneficiary IBAN: {g.neg(kind, g.iban())}")
        elif kind == "routing":
            lines.append(
                f"ABA routing {g.neg(kind, g.routing())}, checking {g.neg(kind, g.account())}"
            )
        elif kind == "luhn_non_card":
            label, number = g.luhn_non_card()
            lines.append(f"{label}: {g.neg(kind, number)}")
        elif kind == "timestamp":
            lines.append(f"event at epoch {g.neg(kind, g.epoch())} processed")
        elif kind == "version":
            lines.append(f"Upgraded to {g.neg(kind, g.version())}")
        elif kind == "uuid":
            lines.append(f"session {g.neg(kind, g.uuid())} closed")
        elif kind == "aws_account":
            acct = g.neg(kind, g.aws_account())
            lines.append(f"arn:aws:iam::{acct}:role/Deployer assumed by {acct}")
        elif kind == "ssa_irs_samples":
            v = g.r.choice(
                [
                    "078-05-1120",
                    "219-09-9999",
                    "123-45-6789",
                    *(f"987-65-432{i}" for i in range(10)),
                ]
            )
            lines.append(f"Example SSN for the form instructions: {g.neg(kind, v)}")
        elif kind == "zip4":
            lines.append(f"Ship to 12 Test Ave, Sampletown ID {g.neg(kind, g.zip4())}")
        elif kind == "date_not_dob":
            d = g.date(1960, 2026)
            label = g.r.choice(
                [
                    "Invoice date",
                    "Hire date",
                    "Date of service",
                    "Expires",
                    "Last login",
                    "Policy effective",
                ]
            )
            lines.append(f"{label}: {g.neg(kind, g.fmt_date(d))}")
        elif kind == "masked_card":
            lines.append(f"Card ending in {g.neg(kind, g.digits(4, '0123456789'))} was charged")
        elif kind == "social_media":
            lines.append(f"Shared on social media, post {g.neg(kind, g.digits(9))}")
        elif kind == "test_cards":
            v = g.r.choice(sorted(_TEST_CARDS))
            lines.append(f"Use test card {g.neg(kind, v)} in the sandbox")
    return "\n".join(lines) + "\n"


NEGATIVE_KINDS = [
    "order",
    "tracking",
    "phone",
    "invoice",
    "iban",
    "routing",
    "luhn_non_card",
    "timestamp",
    "version",
    "uuid",
    "aws_account",
    "ssa_irs_samples",
    "zip4",
    "date_not_dob",
    "masked_card",
    "test_cards",
    "social_media",
]


# -------------------------------------------------------------------- the corpus


def build_corpus(seed: int = SEED) -> list[Doc]:
    g = Gen(seed)
    docs: list[Doc] = []

    def add(name: str, category: str, make: Callable[[], bytes | str]) -> Doc:
        g.start()
        data = make()
        raw = data.encode() if isinstance(data, str) else data
        doc = Doc(
            name,
            category,
            raw,
            Counter(g.truth),
            list(g.conversations),
            set(g.values),
            Counter(g.negatives),
        )
        docs.append(doc)
        return doc

    for i in range(20):
        add(
            f"statements/checking-{i:03d}.txt",
            "bank_statement",
            lambda: "\n".join(statement_lines(g, card_statement=False)) + "\n",
        )
        add(
            f"statements/card-{i:03d}.txt",
            "card_statement",
            lambda: "\n".join(statement_lines(g, card_statement=True)) + "\n",
        )
    for i in range(10):
        add(
            f"statements/pdf/card-{i:03d}.pdf",
            "pdf",
            lambda: pdf(statement_lines(g, card_statement=True)),
        )
        add(
            f"statements/pdf/checking-{i:03d}.pdf",
            "pdf",
            lambda: pdf(statement_lines(g, card_statement=False)),
        )
    for i in range(8):
        add(f"exports/crm/customers-{i:03d}.csv", "crm_csv", lambda: crm_csv(g, 40))
        add(f"exports/hr/employees-{i:03d}.csv", "hr_csv", lambda: hr_csv(g, 30))
    for i in range(20):
        add(f"support/tickets-{i:03d}.json", "ticket_json", lambda: ticket_json(g, 6))
        add(f"support/mail/msg-{i:03d}.eml", "email", lambda: email_text(g))

    def voice() -> str:
        turns = voice_call(g)
        g.conversations.append(turns)
        return contact_lens_doc(turns)

    def chat() -> str:
        turns = chat_session(g)
        g.conversations.append(turns)
        return connect_chat_doc(turns)

    def flow() -> str:
        text, convs = flow_log_events(g)
        g.conversations.extend(convs)
        return text

    def lex() -> str:
        text, convs = lex_log(g)
        g.conversations.extend(convs)
        return text

    for i in range(40):
        add(f"Analysis/Voice/2026/09/28/call-{i:03d}_analysis.json", "transcript_voice", voice)
        add(f"ChatTranscripts/2026/09/28/chat-{i:03d}.json", "transcript_chat", chat)
    for i in range(20):
        add(f"flow-logs/payments-{i:03d}.jsonl", "ivr_dtmf_flow_log", flow)
        add(f"lex/PaymentsBot-{i:03d}.jsonl", "ivr_lex_log", lex)
    for i in range(6):

        def letter() -> bytes:
            name = g.name()
            return docx(
                [
                    f"Offer letter for {name}",
                    f"Start date: {g.neg('date', g.fmt_date(g.date(2026, 2026)))}",
                    "Please complete the I-9 and W-4. For payroll we have your SSN as "
                    + g.pos("us_ssn", g.dashed(g.ssn()))
                    + " and date of birth "
                    + g.pos("dob", g.fmt_date(g.dob()))
                    + ".",
                    f"Questions: {g.neg('phone', g.phone())}",
                ]
            )

        def sheet() -> bytes:
            rows = [["Name", "Card number", "Order", "Phone"]]
            for _ in range(15):
                rows.append(
                    [
                        g.name(),
                        g.pos("card", g.printed_card(g.card())),
                        g.neg("order", g.order_number()),
                        g.neg("phone", g.phone()),
                    ]
                )
            return xlsx(rows)

        def deck() -> bytes:
            return pptx(
                [
                    ["Payments training", f"Version {g.neg('version', g.version())}"],
                    [
                        "Sandbox cards only",
                        "Use " + g.neg("test_cards", g.r.choice(sorted(_TEST_CARDS))),
                    ],
                    [
                        "Escalations",
                        "Example of a leaked card in a ticket: "
                        + g.pos("card", g.printed_card(g.card())),
                    ],
                ]
            )

        add(f"docs/hr/offer-{i:03d}.docx", "office_docx", letter)
        add(f"docs/finance/cards-{i:03d}.xlsx", "office_xlsx", sheet)
        add(f"docs/training/payments-{i:03d}.pptx", "office_pptx", deck)
    for i in range(10):
        add(f"logs/app/app-{i:03d}.log", "app_log", lambda: app_log(g, 60))
        add(f"logs/access/access-{i:03d}.log", "access_log", lambda: access_log(g, 60))
        add(f"logs/lambda/fn-{i:03d}.jsonl", "lambda_log", lambda: lambda_log(g, 40))
    for i in range(3):
        add(
            f"logs/archive/app-{i:03d}.tar.gz",
            "archive",
            lambda: tar_gz(
                {"app.log": app_log(g, 40).encode(), "access.log": access_log(g, 40).encode()}
            ),
        )
        add(
            f"logs/rotated/app-{i:03d}.log.gz",
            "archive",
            lambda: gzip.compress(app_log(g, 40).encode(), mtime=0),
        )
        add(
            f"logs/rotated/lambda-{i:03d}.jsonl.bz2",
            "archive",
            lambda: bz2.compress(lambda_log(g, 30).encode()),
        )
    for i in range(6):

        def rows() -> bytes:
            n = 50
            cols: dict[str, list[object]] = {
                "customer_id": [],
                "full_name": [],
                "card_number": [],
                "ssn": [],
                "date_of_birth": [],
                "created_at": [],
                "order_id": [],
                "phone": [],
                "member_number": [],
            }
            for _ in range(n):
                cols["customer_id"].append(int(g.neg("customer_id", g.digits(16))))
                cols["full_name"].append(g.name())
                cols["card_number"].append(g.pos("card", g.card()) if g.r.random() < 0.6 else None)
                cols["ssn"].append(
                    g.pos("us_ssn", g.dashed(g.ssn())) if g.r.random() < 0.5 else None
                )
                dob = g.dob()
                g.pos("dob", dob.isoformat())
                cols["date_of_birth"].append(dob)
                cols["created_at"].append(
                    _dt.datetime(2026, g.r.randint(1, 9), g.r.randint(1, 28), 10, 0)
                )
                cols["order_id"].append(g.neg("order", g.order_number()))
                cols["phone"].append(g.neg("phone", g.phone()))
                cols["member_number"].append(g.neg("luhn_non_card", g.luhn_non_card()[1]))
            return parquet(
                cols, {"customer_id": "int64", "date_of_birth": "date", "created_at": "timestamp"}
            )

        add(f"lake/customers/part-{i:05d}.snappy.parquet", "parquet", rows)
    for kind in NEGATIVE_KINDS:
        for i in range(4):
            add(f"negatives/{kind}-{i:02d}.txt", f"neg:{kind}", lambda k=kind: negative_doc(g, k))  # type: ignore[misc]
    return docs


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: bench_corpus.py DIR")  # noqa: T201
        return 2
    out = Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)
    docs = build_corpus()
    with (out / "labels.jsonl").open("w", encoding="utf-8") as f:
        for d in docs:
            path = out / d.name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(d.data)
            label = {
                "name": d.name,
                "category": d.category,
                "truth": dict(sorted(d.truth.items())),
                "negatives": dict(sorted(d.negatives.items())),
            }
            f.write(json.dumps(label) + "\n")
    print(f"{len(docs)} documents in {out}")  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
