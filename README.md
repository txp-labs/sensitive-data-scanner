# sensitive-data-scanner

Find card numbers, US Social Security numbers and other sensitive data in your
own cloud storage and logs, **without the data ever leaving your account**.

> **Status: pre-release.** The first code lands here shortly (AWS: S3,
> CloudWatch Logs, Amazon Connect and Lex transcripts). Nothing in this repo is
> ready to deploy yet. Watch the repo or see the milestones for progress.

## What it does

The scanner runs **inside the cloud account it scans**. It reads the stores you
name (buckets and prefixes, log groups), looks for sensitive data, and writes
**findings only** to a results store in the same account:

- the kind of data (card number, US SSN, date of birth, and more)
- where it was found: account, region, object and version, or log group, stream
  and time
- how many, and how confident the detection is

**It never records the values themselves.** No card number, SSN or other
detected value is written to its results, its logs or its error messages; a test
suite enforces this. A reviewer follows the location link and opens the item
with their own access.

It is built for places where sensitive data turns up by accident, above all
**contact-center transcripts**, where a caller reads a card number aloud
("four two four two, four two four two…") or splits it across two turns.

## How detection works

Detection uses [Microsoft Presidio](https://github.com/microsoft/presidio)
(MIT). Presidio supplies pattern, checksum and context recognizers for card
numbers, SSNs and many other entity types. This project adds:

- **Transcript normalization:** spoken digits, number words, "double"/"triple",
  and numbers split across consecutive turns of one speaker, before
  recognition
- **Source adapters** that read each store and extract the text: AWS first,
  Azure and Google Cloud to follow
- **The findings contract:** a documented, versioned schema for results, so any
  tool can consume them

## Security model

- It runs in your account, with read-only access to the stores you choose and
  write access to its own results store only.
- There is no inbound network access. Anything that consumes results reads them
  from your results store.
- Releases are signed. Every release is reproducible from its tag in this
  repository.
- To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open
  a public issue.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

We welcome issues now. **Pull requests from outside contributors open once our
Contributor License Agreement has completed legal review.** See
[CONTRIBUTING.md](CONTRIBUTING.md).

Maintained by [txp-labs](https://github.com/txp-labs). It powers the
sensitive-data checks in Mermera, and works on its own too.
