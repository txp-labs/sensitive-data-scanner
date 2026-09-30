# Test vectors

Synthetic conversation cases that every implementation of the spec must pass.
The format, and what each field means, is in [spec/README.md](../spec/README.md#vectors).

| File | Cases |
|---|---|
| `stugum-live.jsonl` | Every case from Stugum's live IVR run of 29 Sep 2026: keypad and spoken SSN, DOB and card entries, the retry prefix |
| `transcripts.jsonl` | txp-labs/mermera-attestation-app#1067's fixtures as conversations: Connect chat and Contact Lens transcripts, spoken and split-turn forms, near-misses, redacted `[PII]` turns |
| `answer-windows.jsonl` | Spec 0.2 ([#15](https://github.com/txp-labs/sensitive-data-scanner/issues/15)): keypad answers keyed in parts within one answer window, never across a bot turn; menu and question turns ending a pending value; backchannels that do not |
| `itin.jsonl` | Spec 0.2 ([#15](https://github.com/txp-labs/sensitive-data-scanner/issues/15)): `us_itin` after SSN and ITIN prompts, by context and formatted alone; group boundaries and near-misses; the IRS advertising range as test data |
| `prompt-phrases.jsonl` | Spec 0.3 ([#11](https://github.com/txp-labs/sensitive-data-scanner/issues/11)): prompt phrases on letter and digit boundaries, tolerant variants for dropped words with a near-miss for each, retry prefixes that ignore punctuation and match only at the start, low confidence for every class when no shape passes. Spec 0.4 ([#26](https://github.com/txp-labs/sensitive-data-scanner/issues/26)): "nine digit social" with "number" dropped, and its near-misses |
| `benchmark.jsonl` | Spec 0.5 ([#75](https://github.com/txp-labs/sensitive-data-scanner/issues/75)): "social media" is not SSN or ITIN context, with near-misses; and the accuracy benchmark's conversation cases (a card's last four and a birth year after a prompt at `low`, a card two turns late at `medium`, callback and confirmation numbers as nothing) |
| `logs.jsonl` | Lex V2 conversation logs and Connect flow logs |
| `normalize.jsonl` | Normalization input/output pairs, with each digit run's original range |

Never add a real card number, SSN or other personal value. Card numbers here
are made-up bodies with a computed Luhn check digit, or published test
numbers; SSNs and ITINs are arbitrary structurally valid numbers or published samples
(the IRS advertising range 987-65-4320 to 4329 for ITINs).
