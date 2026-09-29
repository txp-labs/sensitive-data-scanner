# The sensitive-data spec, version 0.4

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

A **prompt phrase** matches only with neither a letter nor a digit (or with
the start or end of the text) on each side. The implementations apply that
boundary, so a phrase does not carry its own `\b`: each phrase `P` is matched
as `(?<![A-Za-z0-9])(?:P)(?![A-Za-z0-9])`. `born` does not match inside
"stubborn", and `4 digit code` does not match inside "14 digit code".

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
   - A retry prefix is a run of words (split on whitespace and
     `. , ! ? ; :`). It matches when the text starts with any run of those
     separator characters, then its words in order, each apart from the next
     by one or more of them, and then neither a letter nor a digit (or the
     end of the text). So "Sorry, I didn't get that!" and "Sorry... I didn't
     catch that." are retries of `sorry i didn't get that` and
     `sorry i didn't catch that`.
   - A prefix matches only at the **start** of the turn: "Okay. Sorry, I
     didn't get that." is not a retry.
2. Find every match of every class's `promptPhrases`, with the boundary
   above. When two matches of
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
   is still reading out. So does a **menu or question** turn: one that
   matches a `menuOrQuestionTurns` pattern of `join_same_speaker_turns`
   (matched like prompt phrases, against the same text as step 1).
   "Thanks. Reply 1 for more." and "Is that a Visa?" are menu or question
   turns; "mm-hmm", "Okay." and "Thank you." are backchannels and end
   nothing.

The first `customer` turn after that takes the armed classes and disarms
them (`promptCarryover.turns: 1`). Every value that **starts** in that turn
is prompted, and a value joined from later turns keeps the prompt.

### Joining turns

A value may continue in a later turn of the **same speaker**. The last token
of a turn is left **open** when it is a digit run at the end of the turn. It
continues into that speaker's next turn when all of these hold:

- the next turn's first token is a digit run at the start of the turn;
- if either the open value or the next turn has a part in an
  `answerWindowChannels` channel (`dtmf`), no turn of another speaker comes
  between them: a keypad answer may be keyed in parts (`0101`, then `80#`)
  within one prompt's answer window, never across a bot or agent turn;
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
    nine-digit SSN or ITIN, or a 13-19 digit card that passes Luhn and has a
    known IIN.

A continued value stays open while the turn holds nothing else. An open value
is closed:

- by a prompt, retry, menu or question turn of another speaker (see
  [Prompts](#prompts));
- if it has a part in an `answerWindowChannels` channel, by any turn of
  another speaker;
- once more than `maxInterveningTurns` turns have passed;
- at the end of the conversation.
 A value spanning turns is reported from its
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
- **ITIN** (`us_itin`): nine digits; area 900-999 (`area_9xx`); group 50-65,
  70-88, 90-92 or 94-99 (`group_50_65_70_88_90_92_94_99`). No nine-digit
  value is both an SSN and an ITIN.
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
  - else the first prompted class: `low`. This holds for **every** class;
    there is no per-class setting for it.
- The span is the **whole value**.
- Test numbers and dummy values are **not** excluded from prompted values.
  A known test card keyed after a card prompt is still a card.

### Unprompted values

Context is the original text of the value's turns, and the
`contextWindow.turnsBefore` turns before the first of them, joined with
newlines. A class has context when one of its `contextWords` appears there
as a whole word or phrase, after its `contextExclusions` are removed.

The rules below are checked in order: card, then SSN, then ITIN, then DOB.

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
3. **ITIN** (exactly nine digits, structurally valid as an ITIN):
   - if it is a `testNumbers` entry (the IRS advertising range 987-65-4320
     to 987-65-4329), it is excluded as test data;
   - else, with ITIN context: `us_itin`, via `context`, `high`. The ITIN
     context words include the SSN words, so "SSN 912-70-1234" is an ITIN;
   - else, if `standalone: formatted` and the value is formatted as for an
     SSN: `us_itin`, via `shape`, `medium`.
4. **DOB** (a 6- or 8-digit run, or a date token, with a valid date shape)
   with DOB context: `dob`, via `context`, `high`.

Classes with no `standalone` and no `contextWords` (`cvv`, `pin`,
`account_number`, `us_ssn_last4`) are only ever matched through a prompt.

### ITIN and SSN

`us_itin` is its own class, reported under its own name, with the **same
severity as `us_ssn` (`high`)**: it identifies a taxpayer the same way and is
protected the same way. A caller without an SSN gives an ITIN where an SSN is
asked for, so `us_itin` lists the SSN prompt phrases too: an SSN prompt arms
`us_ssn` and `us_itin` (in that order), and an answer is `us_ssn` if it is a
valid SSN, `us_itin` if it is a valid ITIN, and otherwise `us_ssn` with `low`
confidence. As with cards, the advertising-range test numbers are excluded
only from shape and context detection; keyed after a prompt, they are
classed.

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

- `specVersion` is `"0.4"`.
- A version has two parts, `major.minor`, and no patch. The findings schema
  requires `specVersion` to match `^[0-9]+\.[0-9]+$`.
- Before 1.0, a **breaking change bumps the minor version** (0.3 to 0.4).
  A change is breaking if it can change the matches for any input, or if it
  changes a file's shape. Every change is listed in the repository
  CHANGELOG.
- A change that cannot alter any match or any file's shape does not change
  the version. That covers a comment, a vector the implementations already
  pass, or a new export from an implementation.
- Adding a vector that the current implementations already pass is not a
  change to the contract.
- An implementation declares the `specVersion` it implements and refuses to
  load a spec file with any other version.

## Changes from 0.3

Version 0.4 settles txp-labs/sensitive-data-scanner#26, raised by Stugum after
it adopted 0.3. The issue asked for 0.3.1, but this spec has no patch
version. The new phrase can change matches ("nine digit social" arms nothing
in 0.3), so under [Stability](#stability) it is a minor bump. A 0.3
implementation refuses 0.4 files, so a mirror cannot drift unnoticed. Every
rule has vectors, near-misses included, in `vectors/prompt-phrases.jsonl`.

1. **"nine digit social" arms `us_ssn` and `us_itin`.** Both classes gain
   the phrase `(?:nine|9)[- ]digit social(?: security)?(?: number)?(?! media)`.
   - It matches "Please say your nine digit social." and "Enter your 9-digit
     Social Security." In 0.3 these armed nothing.
   - "social" alone still arms nothing ("Say your social."), because it is
     too common a word. The phrase needs "nine digit" or "9-digit" in front,
     and the 0.3 phrase `social(?: security)? number` still needs "number".
   - "nine digit social media account number" arms only `account_number`.
     The `(?! media)` lookahead, which is inside the allowed subset, keeps
     the SSN phrase out.
   - "19 digit social code" arms nothing: the boundary keeps the phrase's
     `9` from following a digit.
2. **The boundary comment in `classes.yaml`** now describes the boundary the
   implementations apply, and this README already described: neither a
   letter **nor a digit** on each side. It used to say "letter boundary …
   non-letter". This is a comment only; no match changes.
3. **`specVersion` is `"0.4"`** in both spec files and schemas. An
   implementation of 0.3 refuses them.

Not a spec change, but for consumers of the TypeScript package:
`promptRegex(phrase)`, the boundary wrapper
(`(?<![A-Za-z0-9])(?:P)(?![A-Za-z0-9])`, case-insensitive), is now exported
from the package index. Build your own phrase with it instead of copying
it. The package's version and the spec's version are separate (see
`packages/spec-ts/README.md`).

## Changes from 0.2

Version 0.3 settles txp-labs/sensitive-data-scanner#11, raised by Stugum in
its review of 0.1. Stugum mirrors this contract, so every change is listed
here. Each change can alter matches, so 0.3 is breaking. Every rule has
vectors, near-misses included, in `vectors/prompt-phrases.jsonl`.

1. **Prompt phrases match on boundaries.** A phrase matches only with
   neither a letter nor a digit, or the start or end of the text, on each
   side. The implementations apply the boundary as
   `(?<![A-Za-z0-9])(?:P)(?![A-Za-z0-9])`, so the phrases dropped their own
   `\b` (`ssn`, `itin`, `dob`, `cvv` and `pin` are now bare). "stubborn" no
   longer arms `dob`, and "14 digit code" does not arm `cvv`. The issue asked
   for a non-letter boundary; digits count too, so a phrase that starts or
   ends with a digit cannot match inside a longer number.
2. **Tolerant variants for dropped words**, each with a near-miss vector:
   - `us_ssn` and `us_itin`: `social(?: security)? number` replaces
     `social security number`, so "nine digit Social number" arms them.
     "social media account number" still arms only `account_number`.
   - `us_itin`: `taxpayer id(?:entification)? number` replaces `taxpayer
     identification number` ("taxpayer ID number"). "taxpayer identity"
     arms nothing.
   - `dob`: `birth ?date` is added ("birth date", "birthdate"). "birthdates"
     arms nothing.
   - `card`: `(?:credit |debit )?card number` and `(?:credit|debit) card`
     replace the three 0.2 phrases, and `number on (?:the front of )?your
     (?:credit |debit )?card` is added ("the long number on the front of
     your card"). "debit cards" arms nothing.
   - `cvv`: `cvc`, `(?:three|four|3|4)[- ]digit (?:security )?code` (it
     replaces `three digit code`) and `(?:number|code) on the back of
     (?:your|the) card` are added. "The number on the back of your card"
     arms `cvv`, not `card`; "six digit code" arms nothing.
   - `us_ssn_last4`: one phrase, `last (?:four|4)(?: digits)?(?: of)?(?:
     (?:your|the))? (?:social(?: security)?(?: number)?|ssn)`, replaces
     `last four of your social` and `last 4 of your ssn` (it is the
     `us_ssn` context exclusion). "Last four digits of your Social Security
     number" now arms `us_ssn_last4`; in 0.2 it armed `us_ssn` and
     `us_itin`. "Last four digits of your phone number" arms nothing.
3. **Retry prefixes ignore punctuation.** A prefix is a run of words; in the
   turn they may be apart by any run of whitespace and `. , ! ? ; :`, and
   leading separators are skipped. "Sorry, I didn't get that!" is a retry.
   A prefix still matches only at the **start** of the turn (Stugum's
   "anywhere in the turn" is not adopted), and must end at a non-letter,
   non-digit. The entries are now written without punctuation, and two are
   added: `sorry i didn't get that`, `sorry i didn't catch that`, `i'm sorry
   i didn't get that`, `i'm sorry i didn't catch that`. The schema refuses
   `. , ! ? ; :` in an entry.
4. **`promptedWithoutShape` is removed** from `card` and from the schema. It
   was vestigial: a prompted value that passes no shape is the first
   prompted class at `low` for **every** class, as 0.2 already did. A 0.3
   file that sets it fails the schema.
5. **`specVersion` is `"0.3"`** in both spec files and schemas. An
   implementation of 0.2 refuses them.

Declined, as in #11: the engine-facing class ids and labels (`us_ssn`,
`card`, `account_number`) stay canonical, and there is no `address` class.
Stugum keeps its own mappings for those.

## Changes from 0.1

Version 0.2 settles txp-labs/sensitive-data-scanner#15, raised by Stugum after
it adopted 0.1. Stugum mirrors this contract, so every change is listed here;
each one has vectors in `vectors/answer-windows.jsonl` or `vectors/itin.jsonl`.

1. **Keypad answers may be keyed in parts.** `neverJoinChannels` is removed
   from `join_same_speaker_turns`, and `answerWindowChannels: [dtmf]`
   replaces it. A `dtmf` part joins the same speaker's next turn (`0101`,
   then `80#` is one DOB) only while no turn of another speaker has come
   between them, and a value with a `dtmf` part ends at the next turn of
   another speaker. All the other join conditions still apply.
2. **A menu or question turn ends the pending value.** A new field,
   `menuOrQuestionTurns` in `join_same_speaker_turns`, lists patterns (`?`,
   `press`, `reply`, `say`, `enter`, `type`, `select`, `choose`, `dial`,
   `menu`). A bot or agent turn matching one is not a backchannel: like a
   prompt, it ends any value another speaker is still giving. After an
   incomplete `0230` and "Thanks. Reply 1 for more.", the `1` is not part of
   the DOB.
3. **A new class, `us_itin`** (severity `high`, the same as `us_ssn`):
   - shape rules `area_9xx` and `group_50_65_70_88_90_92_94_99`;
   - the SSN prompt phrases plus `\bitin\b` and `taxpayer identification
     number`, so an SSN prompt arms `us_ssn` and `us_itin`;
   - context words `itin`, `taxpayer identification`, `taxpayer id` and the
     SSN words, with the last-four exclusion (which now also names `itin`);
   - `standalone: formatted`;
   - `testNumbers`: the IRS advertising range, `987654320` to `987654329`.
   - A new unprompted rule, **ITIN**, runs after SSN and before DOB.
   - A structurally valid ITIN is a complete unprompted value for
     `stopWhenClassComplete`, like an SSN.
4. **`987654320` left `us_ssn.dummyValues`**: a 9xx area is never an SSN,
   so it could never match there. It is in `us_itin.testNumbers`.
5. **Schema changes:** `testNumbers` entries may have any number of digits
   (they were 13-19); the shape rule enum gains the two ITIN rules; the
   `join_same_speaker_turns` fields change as in 1 and 2.
6. **`specVersion` is `"0.2"`** in both spec files. An implementation of 0.1
   refuses them.

The TypeScript package's compiled `dist/` is now committed, so it can be
consumed by git commit; that is a packaging change, not a contract change.

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
