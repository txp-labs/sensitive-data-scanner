# sensitive-data-scanner

Find card numbers, US Social Security numbers and other sensitive data in your
own cloud storage, logs and tables, **without the data ever leaving your
account**.

> **Status: 0.2.0, tested and not yet run against real AWS.**
> - **Proven by tests:** detection, the AWS adapters (S3 and CloudWatch Logs
>   against moto, DynamoDB against botocore's Stubber), the findings
>   contract and the no-leak guarantee.
> - **Not yet proven:** a first run in a real account. See the release notes
>   and [docs/RELEASING.md](docs/RELEASING.md).

## What it does

The scanner runs **inside the cloud account it scans**. It **discovers** the
stores in the account and region (S3 buckets, CloudWatch log groups,
DynamoDB tables), or reads the ones you name, looks for sensitive data, and
writes **findings only** to a results store in the same account:

- the kind of data (card number, US SSN or ITIN, date of birth, and more);
- where it was found: account, region, object and version; log group,
  stream and time; or DynamoDB table, a hash of the item's key and the
  attribute path; and the Amazon Connect contact;
- how many, how confident, and where in the item (offsets);
- how much was scanned, sampled or skipped, and every store it did not read,
  with the reason (denied, KMS access, too large, unsupported format, or
  deferred to the next run by the budget).

**It never records the values themselves.** No card number, SSN or other
detected value is written to its results, events, logs or error messages. A
test suite scans every test case end to end and enforces this. A reviewer
follows the finding's console link and opens the item with their own access.

It is built for places where sensitive data turns up by accident, above all
**contact-center transcripts**:

- a caller reads a card number aloud ("four two four two, four two four
  two…") or splits it across two turns;
- a caller keys digits after an IVR prompt such as "enter your nine digit
  Social Security number".

## How detection works

Detection uses [Microsoft Presidio](https://github.com/microsoft/presidio)
(MIT), run **with no NLP model**. The scanner adds:

- **The spec's rules on Presidio's own card, SSN and ITIN recognizers:** Luhn
  and IIN, published test numbers set apart, SSN and ITIN structure, and dates
  of birth next to a DOB word.
- **Transcript normalization:** spoken digits, "oh", "double" and "triple",
  spoken dates, and numbers split across consecutive turns of one speaker
  (a keypad answer only within one answer window; a menu or question turn
  ends the value).
- **A conversational recognizer:** a bot or agent turn that asks for class X
  ("Please enter your card number") classes the next customer turn as X,
  whatever its shape. A Luhn-failing entry right after a card prompt is
  still a card, with low confidence.
- **Source adapters:** S3 (with Amazon Connect chat and Contact Lens
  transcripts and Lex logs), CloudWatch Logs (Connect flow logs, Lex V2
  conversation logs, Lambda logs), and DynamoDB (a paginated Query or Scan,
  read attribute by attribute, with paths that select list elements by
  attribute; each keypad entry is read after the nearest prompt before it,
  and planted test inputs are told apart from leaks).
  Azure and Google Cloud come later.
- **The findings contract:** a documented, versioned schema
  ([docs/FINDINGS.md](docs/FINDINGS.md)), so any tool can consume the
  results.

The rules live in a declarative **spec** ([spec/README.md](spec/README.md))
with a shared corpus of synthetic **test vectors** ([vectors/](vectors)). The
same spec drives a zero-dependency TypeScript package,
`@txp-labs/sensitive-data-spec` ([packages/spec-ts](packages/spec-ts)), for
redacting turns in memory during a live call. The Python runner and the
TypeScript package are tested against every vector, and against each other.

## Usage

### Run it on AWS Lambda

Every release publishes:

- a container image: `ghcr.io/txp-labs/sensitive-data-scanner:<version>`;
- a Lambda zip for `python3.12` (x86_64).

The handler is `sensitive_data_scanner.handler.handler`. Schedule it with
EventBridge Scheduler at least daily, and give it:

- read-only access to the stores you name, or list and read access for
  discovery;
- write access to its own results bucket only.

Configure it with environment variables, for example:

```sh
RESULTS_BUCKET=my-scanner-results
SCAN_BUCKETS=amazon-connect-1a2b3c
SCAN_PREFIXES=amazon-connect-1a2b3c/connect/my-instance/
SCAN_LOG_GROUPS=/aws/connect/my-instance,/aws/lex/PaymentBot
# or discover every bucket, log group and table in the account and region,
# with overrides by name or tag
DISCOVER=all
DISCOVER_DENY=s3:*-cloudtrail,tag:sensitive-data-scan=off
# optional: DynamoDB tables, as JSON (see docs/ARCHITECTURE.md)
SCAN_DYNAMODB='[{"table":"stugum","partition":"T#t_0123abcd","sortPrefix":"RUN#","include":["stepResults[kind=sendDtmf].observedDtmf","stepResults[kind=waitForPrompt].observedText","steps","lastHeardText","errorMessage"],"keypad":["stepResults[kind=sendDtmf].observedDtmf","steps[kind=sendDtmf].digits"],"prompts":["stepResults[kind=waitForPrompt].observedText"],"planted":["steps"],"orderBy":"stepIndex"}]'
# optional: push findings to your own EventBridge bus as they are written
FINDINGS_EVENT_BUS_ARN=arn:aws:events:us-west-2:111122223333:event-bus/findings
```

- Every setting, and the permissions it needs:
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- The results: `findings/latest.json` in the results bucket
  ([docs/FINDINGS.md](docs/FINDINGS.md)).

### Use the detection from Python

```python
from sensitive_data_scanner.detect.analyzer import Detector
from sensitive_data_scanner.engine.conversation import Turn

detector = Detector()
detector.analyze_conversation([
    Turn("bot", "Please enter or say your nine digit Social Security number."),
    Turn("customer", "123456789#", channel="dtmf"),
]).detections
# [Detection(cls='us_ssn', via='prompt', confidence='high')]
```

### Redact a live call in TypeScript

```ts
import { loadSpec, redactTurns, armedClasses } from '@txp-labs/sensitive-data-spec';
```

See [packages/spec-ts/README.md](packages/spec-ts/README.md). The package is
not on npm yet.

## Security model

- It runs in your account, with read-only access to the stores you choose
  and write access to its own results store only.
- There is no inbound network access. A consumer reads results from your
  results store, or receives findings events on its own EventBridge bus.
- Every release can be rebuilt from its tag:
  - dependencies are locked with hashes, and base images are pinned by
    digest;
  - each release carries SPDX SBOMs and SHA-256 checksums.
- **Releases are not yet signed.** Signing is planned; see
  [docs/RELEASING.md](docs/RELEASING.md).
- To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not
  open a public issue.

## Repository

| Path | What |
|---|---|
| `spec/`, `vectors/` | The spec (classes, normalization) and the synthetic test vectors |
| `packages/spec-ts/` | The TypeScript package |
| `scanner/` | The Python runner: Presidio recognizers, AWS adapters (S3, CloudWatch Logs, DynamoDB), findings |
| `schema/` | The findings JSON Schema |
| `docs/` | [Architecture](docs/ARCHITECTURE.md), [findings](docs/FINDINGS.md), [releasing](docs/RELEASING.md) |

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

We welcome issues now. **Pull requests from outside contributors open once our
Contributor License Agreement has completed legal review.** See
[CONTRIBUTING.md](CONTRIBUTING.md).

Maintained by [txp-labs](https://github.com/txp-labs). It powers the
sensitive-data checks in Mermera, and works on its own too.
