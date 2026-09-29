"""Every vector with a source `document` parses to exactly its turns."""

from __future__ import annotations

from typing import Any

import pytest

from conftest import all_conversation_vectors, turns_of
from sensitive_data_core.parsers import parse_document

WITH_DOCUMENTS = [c for c in all_conversation_vectors() if c.get("document")]


def test_every_source_format_has_vectors() -> None:
    formats = {c["document"]["format"] for c in WITH_DOCUMENTS}
    assert formats == {"connect_chat", "contact_lens", "lex_v2_log", "connect_flow_log"}


@pytest.mark.parametrize("case", WITH_DOCUMENTS, ids=lambda c: c["id"])
def test_document_parses_to_turns(case: dict[str, Any]) -> None:
    conversations = parse_document(case["document"]["format"], case["document"]["content"])
    assert len(conversations) == 1
    conv = conversations[0]
    assert conv.format == case["document"]["format"]
    assert conv.turns == turns_of(case)
    assert len(conv.pointers) == len(conv.turns)
