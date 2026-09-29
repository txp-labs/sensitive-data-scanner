"""Builders for columnar and data-lake test files, and a stubbed Glue client.

Every value is made up (synthetic.py). Parquet and ORC are written with
pyarrow; Avro with fastavro, whose snappy and zstandard block writers are
supplied here through pyarrow's codecs (fastavro would otherwise need
cramjam or zstandard).
"""

from __future__ import annotations

import datetime as dt
import io
import zlib
from typing import Any

import boto3
import fastavro
import fastavro._write as _fw
import pyarrow as pa
import pyarrow.parquet as pq
from botocore.stub import Stubber
from pyarrow import orc

from synthetic import CARDS, SSN_A, SSN_B


def _long(n: int) -> bytes:
    n = (n << 1) ^ (n >> 63)
    out = bytearray()
    while n & ~0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _snappy_block(fo: Any, block: bytes, level: Any) -> None:
    data = pa.Codec("snappy").compress(block, asbytes=True)
    fo.write(_long(len(data) + 4))
    fo.write(data)
    fo.write(zlib.crc32(block).to_bytes(4, "big"))


def _zstd_block(fo: Any, block: bytes, level: Any) -> None:
    data = pa.Codec("zstd").compress(block, asbytes=True)
    fo.write(_long(len(data)))
    fo.write(data)


_fw.BLOCK_WRITERS["snappy"] = _snappy_block  # type: ignore[attr-defined]
_fw.BLOCK_WRITERS["zstandard"] = _zstd_block  # type: ignore[attr-defined]


def customer_rows() -> list[dict[str, Any]]:
    """Two customers: a card, an SSN (as a number), a date of birth, a nested card."""
    return [
        {
            "customer_id": "c-001",
            "card_number": CARDS["visa"],
            "ssn": int(SSN_A),
            "date_of_birth": dt.date(1981, 7, 4),
            "note": "prefers email",
            "order_id": 12345,
            "payment": {"pan": CARDS["amex"], "brand": "amex"},
        },
        {
            "customer_id": "c-002",
            "card_number": CARDS["jcb"],
            "ssn": int(SSN_B),
            "date_of_birth": dt.date(1990, 1, 2),
            "note": "order 12345 shipped",
            "order_id": 67890,
            "payment": {"pan": None, "brand": "none"},
        },
    ]


def arrow_table(rows: list[dict[str, Any]] | None = None) -> pa.Table:
    return pa.Table.from_pylist(rows or customer_rows())


def parquet_bytes(table: pa.Table | None = None, row_group_size: int | None = None) -> bytes:
    buf = io.BytesIO()
    pq.write_table(
        table if table is not None else arrow_table(), buf, row_group_size=row_group_size
    )
    return buf.getvalue()


def orc_bytes(table: pa.Table | None = None) -> bytes:
    buf = io.BytesIO()
    orc.write_table(table if table is not None else arrow_table(), buf)
    return buf.getvalue()


AVRO_SCHEMA = {
    "type": "record",
    "name": "Customer",
    "namespace": "example",
    "fields": [
        {"name": "customer_id", "type": "string"},
        {"name": "card_number", "type": "string"},
        {"name": "ssn", "type": "long"},
        {"name": "date_of_birth", "type": {"type": "int", "logicalType": "date"}},
        {"name": "note", "type": ["null", "string"]},
        {
            "name": "payment",
            "type": {
                "type": "record",
                "name": "Payment",
                "fields": [{"name": "pan", "type": ["null", "string"]}],
            },
        },
    ],
}


def avro_bytes(codec: str = "null", records: list[dict[str, Any]] | None = None) -> bytes:
    rows = records or [
        {
            "customer_id": r["customer_id"],
            "card_number": r["card_number"],
            "ssn": r["ssn"],
            "date_of_birth": r["date_of_birth"],
            "note": r["note"],
            "payment": {"pan": r["payment"]["pan"]},
        }
        for r in customer_rows()
    ]
    buf = io.BytesIO()
    fastavro.writer(buf, AVRO_SCHEMA, rows, codec=codec)
    return buf.getvalue()


def zstd_bytes(data: bytes) -> bytes:
    sink = pa.BufferOutputStream()
    with pa.CompressedOutputStream(sink, "zstd") as out:
        out.write(data)
    return bytes(sink.getvalue().to_pybytes())


class Glue:
    """A real boto3 Glue client whose every call is answered by a Stubber."""

    def __init__(self, region: str = "us-west-2") -> None:
        self.client = boto3.client(
            "glue",
            region_name=region,
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # noqa: S106 - a stub, never sent
        )
        self.stub = Stubber(self.client)
        self.stub.activate()

    def databases(self, *names: str, link: str | None = None) -> None:
        dbs: list[dict[str, Any]] = [{"Name": n} for n in names]
        if link:
            dbs.append(
                {"Name": link, "TargetDatabase": {"CatalogId": "210987654321", "DatabaseName": "x"}}
            )
        self.stub.add_response("get_databases", {"DatabaseList": dbs})

    def tables(self, database: str, tables: list[dict[str, Any]]) -> None:
        self.stub.add_response("get_tables", {"TableList": tables}, {"DatabaseName": database})

    def denied(self, database: str, message: str) -> None:
        self.stub.add_client_error(
            "get_tables",
            service_error_code="AccessDeniedException",
            service_message=message,
            http_status_code=400,
            expected_params={"DatabaseName": database},
        )


def glue_table(
    name: str,
    location: str,
    *,
    serde: str | None = None,
    columns: list[str] | None = None,
    params: dict[str, str] | None = None,
    serde_params: dict[str, str] | None = None,
    lake_formation: bool = False,
    table_type: str = "EXTERNAL_TABLE",
) -> dict[str, Any]:
    sd: dict[str, Any] = {
        "Location": location,
        "Columns": [{"Name": c, "Type": "string"} for c in columns or []],
        "SerdeInfo": {"Parameters": serde_params or {}},
    }
    if serde:
        sd["SerdeInfo"]["SerializationLibrary"] = serde
    return {
        "Name": name,
        "DatabaseName": "lake",
        "TableType": table_type,
        "StorageDescriptor": sd,
        "Parameters": params or {},
        "IsRegisteredWithLakeFormation": lake_formation,
    }
