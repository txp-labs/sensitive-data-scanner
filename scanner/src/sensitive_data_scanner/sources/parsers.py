"""Parsers: AWS contact-center formats to conversation turns.

- Amazon Connect chat transcripts (`ChatTranscripts/.../*.json`)
- Contact Lens analysis output, voice or chat (`Analysis/.../*.json`)
- Amazon Lex V2 conversation logs (JSON, one record per line or per log event)
- Amazon Connect flow logs (one JSON event per block; "Store customer input"
  and "Get customer input" give a prompt and the keyed answer)
- Lambda JSON logs are not conversations; `scan.item` reads them as JSON.

Each parser returns the turns and what it knows about the contact. The text
of a turn is kept only in memory while the item is scanned.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from typing import Any

from ..engine.conversation import Turn


@dataclass(frozen=True)
class Conversation:
    format: str  # connect_chat | contact_lens | lex_v2_log | connect_flow_log
    turns: list[Turn]
    # JSON Pointer of each turn's text in the source document, for findings offsets.
    pointers: list[str] = field(default_factory=list)
    contact_id: str | None = None
    instance_id: str | None = None


def _ms(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int | float):
        return int(v)
    if isinstance(v, str):
        try:
            t = _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
        if t.tzinfo is None:
            t = t.replace(tzinfo=_dt.UTC)
        return int(t.timestamp() * 1000)
    return None


def _role(v: Any) -> str:
    role = str(v or "").upper()
    if role == "AGENT":
        return "agent"
    if role in ("SYSTEM", "BOT", "CUSTOM_BOT"):
        return "bot"
    return "customer"


def parse_connect_transcript(doc: Any) -> Conversation | None:
    """A Connect chat transcript or Contact Lens output (voice or chat), or None."""
    if not isinstance(doc, dict):
        return None
    transcript = doc.get("Transcript")
    if not isinstance(transcript, list) or not any(
        isinstance(t, dict) and "Content" in t for t in transcript
    ):
        return None
    voice = any(isinstance(t, dict) and "BeginOffsetMillis" in t for t in transcript)
    lens = voice or any(
        k in doc for k in ("ConversationCharacteristics", "Categories", "JobStatus")
    )
    roles: dict[str, str] = {}
    for p in doc.get("Participants") or []:
        if isinstance(p, dict) and p.get("ParticipantId"):
            roles[str(p["ParticipantId"])] = _role(p.get("ParticipantRole"))
    turns: list[Turn] = []
    pointers: list[str] = []
    for i, t in enumerate(transcript):
        if not isinstance(t, dict) or not isinstance(t.get("Content"), str):
            continue
        if isinstance(t.get("Type"), str) and t["Type"] != "MESSAGE":
            continue  # chat events (joined, left) and typing indicators
        pid = str(t.get("ParticipantId") or "")
        if t.get("ParticipantRole"):
            speaker = _role(t["ParticipantRole"])
        elif pid in roles:
            speaker = roles[pid]
        else:
            speaker = _role(pid)
        if voice:
            turns.append(
                Turn(
                    speaker,
                    t["Content"],
                    "speech",
                    _ms(t.get("BeginOffsetMillis")),
                    _ms(t.get("EndOffsetMillis")),
                )
            )
        else:
            turns.append(Turn(speaker, t["Content"], "chat", _ms(t.get("AbsoluteTime")), None))
        pointers.append(f"/Transcript/{i}/Content")
    meta = doc.get("CustomerMetadata") if isinstance(doc.get("CustomerMetadata"), dict) else {}
    contact = doc.get("ContactId") or (meta or {}).get("ContactId")
    instance = doc.get("InstanceId") or (meta or {}).get("InstanceId")
    return Conversation(
        "contact_lens" if lens else "connect_chat",
        turns,
        pointers,
        str(contact) if contact else None,
        str(instance) if instance else None,
    )


def is_lex_record(doc: Any) -> bool:
    return isinstance(doc, dict) and (
        "inputTranscript" in doc or ("sessionState" in doc and "bot" in doc)
    )


def parse_lex_records(records: list[dict[str, Any]]) -> list[Conversation]:
    """Lex V2 conversation log records, one conversation per session, in time order.

    Each record is the customer's input and the bot's reply; the reply is the
    prompt for the next record's input.
    """
    sessions: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for n, r in enumerate(records):
        if is_lex_record(r):
            sessions.setdefault(str(r.get("sessionId") or ""), []).append((n, r))
    out: list[Conversation] = []
    for items in sessions.values():
        items.sort(key=lambda x: (_ms(x[1].get("timestamp")) or 0, x[0]))
        turns: list[Turn] = []
        pointers: list[str] = []
        for n, r in items:
            ts = _ms(r.get("timestamp"))
            channel = "chat" if str(r.get("inputMode", "")).lower() == "text" else "speech"
            if isinstance(r.get("inputTranscript"), str):
                turns.append(Turn("customer", r["inputTranscript"], channel, ts, None))
                pointers.append(f"/{n}/inputTranscript")
            for j, m in enumerate(r.get("messages") or []):
                if isinstance(m, dict) and isinstance(m.get("content"), str):
                    turns.append(Turn("bot", m["content"], channel, ts, None))
                    pointers.append(f"/{n}/messages/{j}/content")
        out.append(Conversation("lex_v2_log", turns, pointers))
    return out


def is_flow_log(doc: Any) -> bool:
    return isinstance(doc, dict) and (
        "ContactFlowModuleType" in doc or ("ContactFlowId" in doc and "ContactId" in doc)
    )


def parse_flow_log(doc: Any) -> Conversation | None:
    """A Connect flow log event with a prompt and keyed input, as two turns; else None."""
    if not is_flow_log(doc):
        return None
    params = doc.get("Parameters") if isinstance(doc.get("Parameters"), dict) else {}
    prompt = (params or {}).get("Text")
    results = doc.get("Results")
    if not isinstance(prompt, str) or results is None or isinstance(results, dict | list):
        return None
    ts = _ms(doc.get("Timestamp"))
    arn = str(doc.get("ContactFlowId") or "")
    instance = arn.split("instance/")[1].split("/", maxsplit=1)[0] if "instance/" in arn else None
    return Conversation(
        "connect_flow_log",
        [Turn("bot", prompt, "speech", ts, None), Turn("customer", str(results), "dtmf", ts, None)],
        ["/Parameters/Text", "/Results"],
        str(doc["ContactId"]) if doc.get("ContactId") else None,
        instance,
    )


def parse_document(fmt: str, content: str) -> list[Conversation]:
    """Parse a document of a known format (as named in vectors' `document.format`)."""
    if fmt in ("connect_chat", "contact_lens"):
        c = parse_connect_transcript(json.loads(content))
        return [c] if c else []
    if fmt == "lex_v2_log":
        records = [json.loads(line) for line in content.splitlines() if line.strip()]
        return parse_lex_records(records)
    if fmt == "connect_flow_log":
        c = parse_flow_log(json.loads(content))
        return [c] if c else []
    raise ValueError("unknown document format")
