# Accuracy benchmark

How well the scanner finds what it claims to find, and what it reports that it
should not. Issue [#75](https://github.com/txp-labs/sensitive-data-scanner/issues/75).

- **Corpus:** `scanner/tests/bench_corpus.py` builds 367 realistic, made-up
  documents from one seed, the same bytes every time. No real data, and every
  name is obviously fake ("Testy McTestface").
- **Scoring:** `scanner/tests/bench_score.py` reads them and scores the result
  against each document's ground truth.
- **Baseline:** `benchmark/baseline.json`. CI fails on a regression past it.

```sh
cd scanner
uv run python tests/bench_score.py            # the report
uv run python tests/bench_score.py --check    # what CI runs: fail on a regression
uv run python tests/bench_score.py --update   # rewrite the baseline after a real change
uv run python tests/bench_corpus.py /tmp/corpus   # the corpus as files, with labels.jsonl
```

The whole benchmark runs in about a second.

## The corpus

| Kind | Documents | Read as |
|---|---|---|
| Checking and card statements | 40 text, 20 PDF | text, PDF |
| CRM and HR exports | 8 + 8 | CSV |
| Support tickets and emails | 20 + 20 | JSON, RFC 822 text |
| Agent calls | 40 | Contact Lens voice transcripts |
| Chats | 40 | Connect chat transcripts |
| IVR with prompted keypad entry | 20 + 20 | Connect flow logs, Lex V2 conversation logs |
| Office files | 6 each | Word, Excel, PowerPoint |
| Logs | 10 each, plus 9 archives | app and access logs, Lambda JSON lines, `.tar.gz`, `.gz`, `.bz2` |
| Data lake | 6 | Parquet (strings, integers, dates, timestamps) |
| Hard negatives | 17 kinds × 4 | text |

**Positives** are labeled only where the scanner claims to find them:

- in stored text: card numbers, SSNs, ITINs, and dates of birth next to a
  birth-date word;
- in conversations: every class a prompt asks for as well (CVV, PIN, account
  number, the last four of an SSN).

**Hard negatives** are values that look sensitive and are not. They are mixed
into the realistic documents, and each kind also has documents of its own
(`neg:<kind>`), so a false positive there names its source:

- order numbers;
- UPS, FedEx and USPS tracking numbers;
- phone numbers in the 555-01xx fiction range;
- invoice and PO ids;
- IBANs and ABA routing numbers, with valid check digits;
- Luhn-valid numbers that are not cards (IMEIs, member and loyalty numbers);
- epoch timestamps, version and build strings, UUIDs, AWS account ids;
- the SSA and IRS sample and advertising numbers;
- ZIP+4 codes;
- dates that are not birth dates;
- masked cards and published test cards;
- nine-digit ids next to "social media".

Calls hold the hard cases a real call does:

- a card read in two halves around "mm-hmm";
- "oh", "double" and fillers ("uh");
- spoken dates ("the fourteenth of May nineteen eighty-five");
- a number given a turn late ("hang on, let me grab it");
- the agent reading the card back;
- "the Visa ending in 1784" and "born in 1985" given where the prompt asked for
  a whole card or date;
- callback, confirmation and order numbers.

## Two runners

- **objects**: every document through the full reader path, as a bucket's
  object is read. That is `read_object` (sniffing, archives, PDF, Office,
  Parquet, JSON, CSV, text and the transcript parsers), then `record`, which
  writes the findings. Counts come from each finding's `confidenceCounts`,
  exactly what a consumer sees.
- **conversation**: every conversation in the corpus, as its parser reads it,
  through the spec's conversation engine (`classify`). This is what Stugum's
  call engine, which implements the same spec, would report.

## Scoring

The benchmark scores each document and class by count:

- `tp = min(truth, detected)`;
- `fp = detected - tp`;
- `fn = truth - tp`.

At a threshold, only detections at that confidence or above count: `low` is
every detection, and `high` only the high ones.

With this scoring, a miss and a false positive of the same class in one
document cancel out. The hard-negative documents hold no positives, so they
measure false positives without that masking.

The same run checks that no finding, coverage record or `repr` holds any value
planted in the corpus, positive or negative.

## Results

Spec 0.4. `medium` is omitted where it equals `low`. The full table is in
`benchmark/baseline.json`.

### Before the fixes

**objects** (every reader):

| Class | P @low | R @low | F1 @low | P @high | R @high | F1 @high |
|---|---:|---:|---:|---:|---:|---:|
| `card` | 0.856 | 0.999 | 0.922 | 0.991 | 0.806 | 0.889 |
| `us_ssn` | 0.565 | 1.000 | 0.722 | 0.519 | 0.831 | 0.639 |
| `us_itin` | 0.866 | 1.000 | 0.928 | 0.866 | 1.000 | 0.928 |
| `dob` | 0.600 | 1.000 | 0.750 | 0.608 | 1.000 | 0.756 |
| `cvv`, `pin`, `account_number`, `us_ssn_last4` | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

**conversation** (the spec's engine):

| Class | P @low | R @low | F1 @low | P @high | R @high | F1 @high |
|---|---:|---:|---:|---:|---:|---:|
| `card` | 0.848 | 0.987 | 0.912 | 1.000 | 0.608 | 0.756 |
| `dob` | 0.779 | 1.000 | 0.876 | 1.000 | 1.000 | 1.000 |
| `us_ssn`, `us_itin`, `cvv`, `pin`, `account_number`, `us_ssn_last4` | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

## Findings

**Weak classes.** In stored text, `us_ssn` (precision 0.57) and `dob` (0.60)
are the weakest, followed by `card` (0.86). Recall is near 1.0 everywhere, so
the problem is false positives, and nearly all of them are high confidence.
In conversations, the engine is precise at `high` and `medium`. Its weak spot
is `card` recall at `high`, 0.61: a card that comes a turn late, or is read
back, has no card word within two turns and is reported at `medium`.

**Top false-positive sources, stored text:**

1. **A CSV's header was context for every cell** (283 `us_ssn`, 240 `dob`, 2
   `us_itin` in HR exports). With `ssn` and `date_of_birth` columns in the
   header, every routing number became a high-confidence SSN, and every hire
   date a date of birth. A table read by a catalog (`scan/columnar.py`)
   already gives each column only its own name.
2. **A JSON document's keys were context for every value in it** (188 `dob`
   in Lambda logs, 26 more in archived logs). One `dateOfBirth` key anywhere
   in a log record made the record's `timestamp`, and a sibling `createdAt`, a
   date of birth.
3. **"social media" is SSN context** (59 `us_ssn` and 4 `us_itin` in the
   `social_media` negatives, 66 and 4 in app logs, 15 in tickets). The spec's
   context word `social` matches "social media", although spec 0.4 already
   keeps "nine digit social media account number" from arming an SSN prompt.
4. **Luhn-valid numbers that are not cards** (124 in a Parquet
   `member_number` column, 7 in the negatives). By design (`standalone: any`):
   a 16-digit Luhn-valid number with a known IIN and no suppressing word is a
   `medium` card. None is `high`.
5. **A card inside a longer run of digit groups** (5 in CRM exports, 3 in
   PDFs, 2 in statements). Presidio's card pattern starts at any word
   boundary, so four groups in the middle of a USPS tracking number
   (`9400 1111 4539 1488 0343 6467 00`), or of an IBAN, could pass Luhn and
   the IIN table. The spec's own pattern, and the conversation engine, never
   start a card inside a digit run.
6. **A date near a date of birth** (13 in tickets, 2 in emails): "my date of
   birth is 03/14/1985, charged on 09/03/2026". Any date within 64 characters
   after a DOB word takes the context, even with the birth date between them.

**Conversation false positives** (14 `card`, 17 `dob`, all `low`):

- "the Visa ending in 1784" after a card prompt;
- "born in 1985" after a date-of-birth prompt.

This is the spec's rule: a prompted answer that fits no shape is the prompted
class at `low` confidence. The benchmark keeps it visible. The rule is not a
bug: a consumer that filters to `medium` and above loses none of the
conversation positives.

**Misses:** one card pasted in chat, suppressed by "invoice" in the previous
turn.
