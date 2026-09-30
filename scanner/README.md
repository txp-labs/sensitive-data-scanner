# sensitive-data-scanner (Python runner)

Packages in one uv workspace: the cloud-neutral core in `core/`
(`sensitive-data-scanner-core`, import `sensitive_data_core`: detection,
findings, budgets and sampling, the coverage summary, the findings push
interface, the sampled SQL pass and the adapter interface), and the AWS
scanner in `src/` (`sensitive-data-scanner`, import `sensitive_data_scanner`:
every boto3 adapter, discovery, the runner and the Lambda handler). The
core imports no cloud SDK, and a test keeps it that way. `db/` is the
databases-anywhere runner (`sensitive-data-scanner-db`, import
`sensitive_data_db`), also on the core ([docs/DATABASES.md](../docs/DATABASES.md)),
`azure/` the Azure scanner (`sensitive-data-scanner-azure`, import
`sensitive_data_azure`, [docs/AZURE.md](../docs/AZURE.md)), and `gcp/` the
Google Cloud scanner (`sensitive-data-scanner-gcp`, import
`sensitive_data_gcp`, [docs/GCP.md](../docs/GCP.md)).

Detection for the scanner: [Microsoft Presidio](https://github.com/microsoft/presidio)
Analyzer, with **no NLP model**, and recognizers for the classes in the
[spec](../spec/README.md).

| Recognizer | What it finds |
|---|---|
| `SpecCreditCardRecognizer` | Presidio's card pattern and Luhn checksum, plus the 2-series and 19-digit ranges, the spec's IIN table, and published test numbers set apart |
| `SpecUsSsnRecognizer` | Presidio's SSN recognizer with the spec's structure rules and sample numbers; nine bare digits only next to an SSN word |
| `SpecUsItinRecognizer` | Presidio's ITIN recognizer with the spec's structure rules (9xx area, groups 50-65, 70-88, 90-92, 94-99) and the IRS advertising range set apart; nine bare digits only next to an ITIN or SSN word |
| `DateOfBirthRecognizer` | Dates, kept only next to a DOB word |
| `SpokenDigitsRecognizer` | Card numbers, SSNs and ITINs read aloud in one text ("four five three nine, ..."), after the spec's normalization |
| `ConversationalPromptRecognizer` | A whole transcript: a bot or agent turn asking for class X classes the next customer turn as X, whatever its shape; values split across a speaker's turns |
| `SpecContextEnhancer` | Context words in a character window and in caller-supplied context (a JSON key, a CSV header), without an NLP model |

```python
import datetime as dt
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.engine.conversation import Turn

detector = Detector()
detector.analyze_text("SSN: 512-43-7788").detections
# [Detection(cls='us_ssn', via='context', confidence='high')]

detector.analyze_conversation(
    [
        Turn("bot", "Please enter or say your nine digit Social Security number."),
        Turn("customer", "123456789#", channel="dtmf"),
    ]
).detections
# [Detection(cls='us_ssn', via='prompt', confidence='high')]
```

A `Detection` has a class, how it was found, a confidence and spans. It never
has the value.

## Development

```sh
uv sync --locked
uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest
```

`pytest` runs every vector through the spec engine and through Presidio, and
runs the TypeScript package with Node (`test_parity.py`) to check that the two
agree on every vector. CI sets `SDS_REQUIRE_PARITY=1`, so a missing Node is a
failure there and not a skip.
