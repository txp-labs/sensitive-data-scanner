"""The databases runner's findings sinks and its entry point. Every value is made up."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from sensitive_data_core.findings import EVENT_DETAIL_TYPE, EVENT_SOURCE
from sensitive_data_db import __main__ as entry
from sensitive_data_db.config import Secret, read_settings
from sensitive_data_db.sinks import (
    SIGNATURE_HEADER,
    EventBridgeSink,
    FileSink,
    HttpsSink,
    sign,
    sinks_for,
    verify,
)

KEY = "k" * 40
URL = "https://collector.example/findings?token=made-up-token"


def document(n: int = 1) -> dict[str, Any]:
    return {
        "schema": "sensitive-data-scanner.findings",
        "runId": "20260929T120000Z-0a1b2c3d",
        "findings": [{"id": f"{i:032x}", "pad": "x" * 150_000} for i in range(n)],
        "coverage": [],
    }


class Response(io.BytesIO):
    def __init__(self, status: int = 200) -> None:
        super().__init__(b"{}")
        self.status = status


class Opener:
    def __init__(self, *outcomes: int | Exception) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[urllib.request.Request] = []

    def __call__(self, req: urllib.request.Request, timeout: float) -> Response:
        self.requests.append(req)
        outcome = self.outcomes.pop(0) if self.outcomes else 200
        if isinstance(outcome, Exception):
            raise outcome
        return Response(outcome)


def test_https_posts_each_part_signed(capsys: pytest.CaptureFixture[str]) -> None:
    opener = Opener()
    sink = HttpsSink(Secret(URL), Secret(KEY), opener=opener, clock=lambda: 1_790_000_000)
    # Three findings of 150 KB: one per part, each part under the 200 KB limit.
    assert sink.push(document(3)) == 3
    assert len(opener.requests) == 3
    for i, req in enumerate(opener.requests, 1):
        body = req.data
        assert isinstance(body, bytes)
        header = str(req.get_header(SIGNATURE_HEADER.capitalize()))
        assert verify(KEY.encode(), header, body, now=1_790_000_010)
        assert not verify(KEY.encode(), header, body + b" ", now=1_790_000_010)
        assert not verify(KEY.encode(), header, body, now=1_790_000_000 + 301)
        assert not verify(b"another-key" * 4, header, body, now=1_790_000_010)
        assert json.loads(body)["part"] == i
        assert req.get_method() == "POST" and req.full_url == URL
    out = capsys.readouterr().out
    assert "made-up-token" not in out and KEY not in out
    assert "made-up-token" not in repr(sink)


def test_the_signature_is_over_the_timestamp_and_the_exact_body() -> None:
    assert sign(b"key", "100", b"{}") == (
        "t=100,v1=" + __import__("hmac").new(b"key", b"100.{}", "sha256").hexdigest()
    )


def test_https_retries_server_errors_but_not_a_refusal() -> None:
    sleeps: list[float] = []
    retry = Opener(urllib.error.URLError("down"), 503, 200)
    sink = HttpsSink(Secret(URL), Secret(KEY), opener=retry, sleep=sleeps.append)
    assert sink.push(document()) == 1
    assert len(retry.requests) == 3 and sleeps == [1, 2]
    refused = Opener(urllib.error.HTTPError(URL, 403, "no", {}, None))  # type: ignore[arg-type]
    sink = HttpsSink(Secret(URL), Secret(KEY), opener=refused, sleep=sleeps.append)
    assert sink.push(document()) == 0
    assert len(refused.requests) == 1


class Events:
    def __init__(self) -> None:
        self.calls: list[list[dict[str, Any]]] = []

    def put_events(self, Entries: list[dict[str, Any]]) -> dict[str, Any]:
        self.calls.append(Entries)
        return {"FailedEntryCount": 0}


def test_eventbridge_and_file_sinks(tmp_path: Path) -> None:
    events = Events()
    arn = "arn:aws:events:us-west-2:111122223333:event-bus/findings"
    assert EventBridgeSink(arn, events).push(document()) == 1
    entry_ = events.calls[0][0]
    assert (entry_["Source"], entry_["DetailType"], entry_["EventBusName"]) == (
        EVENT_SOURCE,
        EVENT_DETAIL_TYPE,
        arn,
    )
    path = tmp_path / "findings.json"
    assert FileSink(str(path)).push(document()) == 1
    assert json.loads(path.read_text())["runId"] == "20260929T120000Z-0a1b2c3d"
    s = read_settings(
        {
            "SCANNER_SITE": "dc-1",
            "DATABASE_URL_A": "postgresql://ro@db/app",
            "FINDINGS_HTTPS_URL": URL,
            "FINDINGS_HMAC_KEY": KEY,
            "FINDINGS_EVENT_BUS_ARN": arn,
            "FINDINGS_FILE": str(path),
        }
    )
    assert [type(x).__name__ for x in sinks_for(s)] == ["HttpsSink", "EventBridgeSink", "FileSink"]


def test_the_entry_point_reports_by_code_and_never_the_connection_string(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    for k in list(__import__("os").environ):
        if k.startswith(("DATABASE_URL", "FINDINGS_", "SCANNER_SITE")):
            monkeypatch.delenv(k)
    monkeypatch.setenv("SCANNER_SITE", "dc-1")
    monkeypatch.setenv("DATABASE_URL_BAD", "redis://u:made-up-secret@h/0")
    monkeypatch.setenv("FINDINGS_FILE", str(tmp_path / "f.json"))
    assert entry.main(["scan"]) == 1
    out = capsys.readouterr().out
    assert json.loads(out)["error"] == "unknown_scheme"
    assert "made-up-secret" not in out
    assert entry.main(["delete-everything"]) == 1
    # A database that refuses the connection: the run still reports it, by error name.
    monkeypatch.setenv("DATABASE_URL_BAD", "postgresql://ro:made-up-secret@127.0.0.1:1/app")
    monkeypatch.setenv("DB_CONNECT_TIMEOUT_SECONDS", "2")
    assert entry.main(["check"]) == 2
    assert entry.main([]) == 0
    doc = json.loads((tmp_path / "f.json").read_text())
    store = doc["discovery"]["stores"][0]
    assert (store["status"], store["reason"], store["error"]) == (
        "error",
        "error",
        "OperationalError",
    )
    out = capsys.readouterr().out
    assert "made-up-secret" not in out and "127.0.0.1" not in out
    for line in out.splitlines():
        json.loads(line)  # only the scanner's own JSON lines
