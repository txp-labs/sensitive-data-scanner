# sensitive-data-scanner-core

The cloud-neutral core of the scanner, shared by every platform's package:

| Module | What it is |
|---|---|
| `engine`, `detect` | The spec (`spec/`) and Presidio detection, with no NLP model |
| `findings` | The findings contract (schema `sensitive-data-scanner.findings`): ids, offsets, coverage, the document |
| `adapter` | The `Adapter` interface a kind of store plugs in with, the run budget and the finding store |
| `rules` | Allow, deny and sampling rules (`DISCOVER_ALLOW`, `DISCOVER_DENY`, `DISCOVER_SAMPLING`) |
| `coverage` | The coverage summary: every store found, read or not, and why |
| `push` | The findings push interface (`FindingsSink`) and the split of a document into parts |
| `scan` | Readers every source shares: text, JSON, columnar formats, and the sampled read-only SQL pass (`scan/sql.py`) |
| `safety` | The no-values rule in code: masking, the only logger, safe error names |

It depends on no cloud SDK. The AWS scanner is `sensitive-data-scanner`
(`../src`), and the databases-anywhere container is `sensitive-data-scanner-db`
(`../db`). Development and tests run from `scanner/` (see `../README.md`).
