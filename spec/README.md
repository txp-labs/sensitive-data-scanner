# The sensitive-data spec, version 0.1

This directory is a **contract**. Three implementations follow it:

- the Python runner (`scanner/`), which scans stored transcripts and logs;
- the TypeScript package `@txp-labs/sensitive-data-spec` (`packages/spec-ts`);
- Stugum's call engine, which imports that package to redact turns in memory
  while a call is live.

All three are tested against the same cases in [`vectors/`](../vectors). A
change to anything here is a change to the contract (see
[Stability](#stability)).

| File | What it holds | Schema |
|---|---|---|
| `classes.yaml` | Classes, prompt phrases, shapes, context words, test numbers, IIN table | `schema/classes.schema.json` |
| `normalize.yaml` | The normalization steps and their word tables | `schema/normalize.schema.json` |
| `../vectors/*.jsonl` | Conversation test cases | `schema/vector.schema.json` |
| `../vectors/normalize.jsonl` | Normalization input/output pairs | `schema/normalize-vector.schema.json` |

Every value in this directory and in `vectors/` is synthetic or a published
test number. **Never add a real card number, SSN or other personal value**,
not even in a test.

## Terms

- **Turn:** one message in a conversation: a `speaker` (`bot`, `agent` or
  `customer`), its `text`, and optionally a `channel` (`speech`, `dtmf`,
  `chat`) and `beginMs` / `endMs` times in milliseconds.
- **Prompt:** a bot or agent turn that asks for a class of data.
- **Value:** a run of digits (or a date) that may be sensitive.
- **Match:** a value given a class. It has a location, a `via` and a
  `confidence`, and never the value itself.
  - `via` is `prompt` (the previous prompt asked for it), `context` (a
    context word is nearby) or `shape` (the value alone looks like it).
  - `confidence` is `high`, `medium` or `low`.

Regular expressions in the spec (prompt phrases, context exclusions) are
matched **case-insensitively with ASCII semantics**: `\b`, `\d` and `\w` are
ASCII only. Write them in the subset that Python `re` and JavaScript
`RegExp` agree on: no lookbehind, no named groups, no inline flags.

## Normalization

Each turn's text is normalized on its own, by the steps in
`normalize.yaml`, in order. Each normalized character remembers the range of
the original text it came from; a span in normalized text maps back to the
original from the first character's start to the last character's end.
Implementations must reproduce `vectors/normalize.jsonl` exactly: the
normalized text, and the original range of every digit run.

"Digit" means ASCII `0`-`9`. "Letter" means ASCII `A`-`Z` or `a`-`z`. A
"word" is a maximal run of letters. "Whitespace" is space, tab, CR or LF.

1. **`strip_keypad_terminator`**: remove a terminator character (`#`, `*`)
   when the character before it is a digit and the character after it is
   the end of the text or neither a letter nor a digit.
   `123456789#` becomes `123456789`.
2. **`spoken_dates_to_iso`**: replace a date that names its month with
   `YYYY-MM-DD`. The grammar (words are case-insensitive, and word
   boundaries apply at both ends):
   - `DATE := MONTH[.] ,? WS (the WS)? DAY ,? WS YEAR`, or
     `(the WS)? DAY WS (of WS)? MONTH[.] ,? WS YEAR`.
     `WS` is one or more whitespace characters.
   - `MONTH` is a key of `months`.
   - `DAY` is `TENS_DAY (-|WS) (ORDINAL_1_9 | UNIT)`, an ordinal, a teen,
     a unit, `TENS_DAY` alone, or 1-2 digits with an optional
     `st`/`nd`/`rd`/`th`. `TENS_DAY` is a `tens` word worth 20 or 30.
     `ORDINAL_1_9` is an ordinal worth 1-9. The day's value is the sum of
     its words.
   - `YEAR` is 4 digits; or a century word (the `teens`/`tens` word worth
     19 or 20) then, after `-` or whitespace, one of: a teen; a `tens` word
     with an optional unit; `oh` or `o` then a unit; or `hundred` (00). Or
     it is `two thousand` with an optional `and` and then a teen, a `tens`
     word with an optional unit, or a unit.
   - Alternatives are tried longest word first, left to right.
   - A match converts only if the year is within `yearRange` and the date
     exists (February 29 only in leap years). Otherwise the text is left as
     it is.
   - Every character of the ISO date maps to the whole matched range.

   `January first, nineteen eighty` becomes `1980-01-01`.
   `March 3, 1979` becomes `1979-03-03`.
3. **`number_words_to_digits`**: replace each word in `words` with its
   digit, left to right.
   - `oh` and `o` (`zeroOnlyNextToDigits`) become `0` only when the last
     non-whitespace character already output is a digit, or the next word
     or character after whitespace is a digit, a digit word or a
     multiplier.
   - A multiplier (`double`, `triple`) followed, after whitespace, by a
     digit word or by a single digit (not part of a longer number) becomes
     that digit repeated. The replacement maps to the range from the
     multiplier to the digit.

   `one oh double five` becomes `1 0 55`.
4. **`drop_fillers_between_digits`**: remove a filler word when the nearest
   non-separator on each side (skipping separators and other fillers) is a
   digit.
5. **`collapse_digit_separators`**: remove each run of separator characters
   (space, `-`, `.`, `,`) that has a digit immediately before and after it.
   There is one exception: date tokens are protected. They are ISO dates
   (`\d{4}-\d{2}-\d{2}`) and slashed dates (`\d{1,2}/\d{1,2}/(\d{4}|\d{2})`),
   not inside a longer digit run. A run is not removed if it touches a
   protected character or contains one.
   `4 5 3 9, 1 4 8 8` becomes `45391488`; `DOB 7/4/1981 5 1 2` becomes
   `DOB 7/4/1981 512`.
6. **`join_same_speaker_turns`**: not a text change; see
   [Joining turns](#joining-turns).

## Classification

`classify(turns)` returns every match in a conversation, in order of
position. It also counts values set aside as test data or suppressed, which
are not matches.

### Tokens

In each normalized turn, the candidate values are:

- the date tokens (ISO and slashed dates, as above); and
- every maximal run of digits that is not inside a date token.

A token with a letter or `_` directly before or after it is **not** a
candidate (it is part of an id or a word, like `deadbeef4539…`).

A token is **at the start** of its turn when no letter or digit comes before
it, and **at the end** when no letter or digit comes after it.

### Prompts

For each `bot` or `agent` turn:

1. Lower-case the text, replace `’` with `'`, and remove leading whitespace.
   If it starts with a `retryPrefixes` entry, remove the prefix and then any
   whitespace and `. , ! ? ; :`. The turn is then a **retry**.
2. Find every match of every class's `promptPhrases`. When two matches of
   **different** classes overlap, drop the shorter one. Example: "last four
   of your social security number" arms `us_ssn_last4`, not `us_ssn`.
3. The classes left, in order of their first match, are the turn's
   **prompted classes**.
4. What the turn arms:
   - If there are prompted classes, the turn arms them.
   - If there are none, a retry re-arms the last armed classes
     (`surviveRetry`).
   - Any other bot or agent turn ("mm-hmm", "Thank you.") leaves the armed
     classes as they were.
5. A turn that arms or re-arms classes ends any value that another speaker
   is still reading out.

The first `customer` turn after that takes the armed classes and disarms
them (`promptCarryover.turns: 1`). Every value that **starts** in that turn
is prompted, and a value joined from later turns keeps the prompt.

### Joining turns

A value may continue in a later turn of the **same speaker**. The last token
of a turn is left **open** when it is a digit run at the end of the turn. It
continues into that speaker's next turn when all of these hold:

- the next turn's first token is a digit run at the start of the turn;
- neither turn's channel is in `neverJoinChannels` (a keypad entry is whole);
- the time from the open turn's end (`endMs`, else `beginMs`) to the next
  turn's `beginMs` is at most `withinSeconds`, or either time is unknown;
- at most `maxInterveningTurns` turns of other speakers come between;
- the joined value would not be longer than the limit: the largest
  `digits` maximum of its prompted classes (8 for `dob`), or 19 if it is
  not prompted;
- the open value is not complete (`stopWhenClassComplete`):
  - a prompted value is complete when it passes a prompted class's shape
    in full, or has reached the limit;
  - an unprompted value is complete when it is a structurally valid
    nine-digit SSN, or a 13-19 digit card that passes Luhn and has a known
    IIN.

A continued value stays open while the turn holds nothing else. An open value
is also closed once more than `maxInterveningTurns` turns have passed, and at
the end of the conversation. A value spanning turns is reported from its
first turn (`turn`, `start`) to its last (`endTurn`, `end`).

### Shapes

- **Digit count:** the value's length is within `shape.digits` (a number,
  or `[min, max]`).
- **Card:** try the whole value if it has 13-19 digits, then shorter heads
  from 19 digits (or one fewer than the length) down to 13.
  - A head passes **in full** if it passes `luhn` and `iin_known`.
  - The whole value (never a shorter head) passes **soft** if it passes
    Luhn but not `iin_known`, the only rule in `softRules`.
  - `iin_known` means the first rule in `cardBrands` whose prefix matches
    also lists the number's length. A range `a-b` compares the first
    `len(a)` digits.
- **SSN:** nine digits; area not 000, 666 or 900-999; group not 00; serial
  not 0000.
- **Date** (`dob`):
  - `date_mmddyy` (6 digits) or `date_mmddyyyy` (8 digits);
  - a slashed date (`m/d/yy` or `m/d/yyyy`) or an ISO date (which
    `spoken_date` produces).
  - Every form must be a real date and a plausible birth date: its year is
    between 1900 and the current year.
  - A two-digit year is this century when that is not in the future, and
    otherwise last century.

### Prompted values

A value that starts in the prompted customer turn:

- **A date token**, when `dob` is prompted: `dob`, `high` if its shape
  passes, else `low`. When `dob` is not prompted, it is treated as
  unprompted.
- **Any other value**, in this order:
  - the first prompted class whose shape it passes **in full**: `high`;
  - else the first it passes **soft**: `medium`;
  - else, if the unprompted rules below give it another class, that match
    (a valid card after an SSN prompt is a card);
  - else the first prompted class: `low` (`promptedWithoutShape`).
- The span is the **whole value**.
- Test numbers and dummy values are **not** excluded from prompted values.
  A known test card keyed after a card prompt is still a card.

### Unprompted values

Context is the original text of the value's turns, and the
`contextWindow.turnsBefore` turns before the first of them, joined with
newlines. A class has context when one of its `contextWords` appears there
as a whole word or phrase, after its `contextExclusions` are removed.

The rules below are checked in order: card, then SSN, then DOB.

1. **Card** (13 or more digits): take the first candidate length (as in
   [Shapes](#shapes)) that passes in full. Then:
   - if it is a test number or has at most `testNumbersMaxDistinctDigits`
     distinct digits, it is excluded as test data;
   - else, with card context: `card`, via `context`, `high`;
   - else, with a `suppressWords` word in the context: suppressed;
   - else, if `standalone: any`: `card`, via `shape`, `medium`.

   The span covers only the digits that passed.
2. **SSN** (exactly nine digits, structurally valid):
   - if it is a `dummyValues` entry, it is excluded as test data;
   - else, with SSN context: `us_ssn`, via `context`, `high`;
   - else, if `standalone: formatted` and the value sits in one turn whose
     original text is exactly `ddd-dd-dddd` or `ddd dd dddd` (one kind of
     separator): `us_ssn`, via `shape`, `medium`.
3. **DOB** (a 6- or 8-digit run, or a date token, with a valid date shape)
   with DOB context: `dob`, via `context`, `high`.

Classes with no `standalone` and no `contextWords` (`cvv`, `pin`,
`account_number`, `us_ssn_last4`) are only ever matched through a prompt.

## Vectors

`vectors/*.jsonl` holds one case per line, all synthetic.

- `expect` lists every match, in order. Spans are over the **normalized**
  text of the turn. `expect: []` means nothing may match (near-misses, and
  redacted `[PII]` turns).
- Classification uses the current year for date plausibility. Vectors are
  evaluated as of 2026-09-29, unless a case sets `now`.
- `document`, when present, is the raw source the turns were read from: a
  Connect chat transcript, a Contact Lens transcript, Lex V2 conversation
  logs or a Connect flow log event. A source parser must turn it into
  exactly `turns`.
- `source` says where a case came from: a Stugum live run, or the fixtures
  of txp-labs/mermera-attestation-app#1067.

## Stability

- `specVersion` is `"0.1"`.
- Before 1.0, a **breaking change bumps the minor version** (0.1 to 0.2).
  A change is breaking if it can change the matches for any input, or if it
  changes a file's shape. Every change is listed in the repository
  CHANGELOG.
- Adding a vector that the current implementations already pass is not a
  change to the contract.
- An implementation declares the `specVersion` it implements and refuses to
  load a spec file with any other version.

## Changes from the v0 draft

The v0 draft was posted in txp-labs/mermera-attestation-app#1059. Version 0.1
differs from it as follows. Stugum mirrors this contract, so every change is
listed here.

1. **Normalization order.** `spoken_dates_to_iso` now runs second, before
   `number_words_to_digits`, so it sees the words as said. Two steps were
   added:
   - `drop_fillers_between_digits`;
   - `collapse_digit_separators`, which now never removes separators inside
     or next to a date.
2. **`join_same_speaker_turns`** gains two fields:
   - `maxInterveningTurns: 3`: another speaker's backchannel ("mm-hmm") may
     come between the parts;
   - `neverJoinChannels: [dtmf]`: a keypad entry is whole.
3. **Expectations gain `confidence`** (`high` / `medium` / `low`, required),
   and `endTurn` for a value that spans turns. Vectors gain optional
   `description`, `now`, `beginMs` / `endMs` on turns, and `document`.
4. **`"last four of your social"` moved** out of `us_ssn.promptPhrases`; it
   is only in `us_ssn_last4`. Overlapping prompt matches of different
   classes resolve to the longer one.
5. **New class fields:**
   - `standalone` (`any` / `formatted` / `never`);
   - `contextExclusions` (us_ssn);
   - `suppressWords` (card);
   - `softRules` (card: `iin_known`);
   - `dummyValues` (us_ssn), `testNumbers` and `testNumbersMaxDistinctDigits`
     (card);
   - `contextWords` for `dob`.
   - The card's `contextWords` list is longer (it adds brands, expiry words,
     payment and billing).
6. **New top-level fields:** `contextWindow.turnsBefore: 2`, and
   `cardBrands` (the IIN table `iin_known` reads).
7. **New `dob` shape kinds:** `date_slashed` and `date_iso`.
8. **A new vector file**, `vectors/normalize.jsonl`, and JSON Schemas for the
   vector files.
9. **The Stugum card case `1111222233334444#`** is `card` via `prompt` with
   **medium** confidence. It is Luhn-valid, but no network issues numbers
   starting with 1, so it fails only the soft rule.
