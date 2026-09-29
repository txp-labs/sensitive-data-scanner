# Contributing

Thank you for helping. This project finds sensitive data in real customer
environments, so correctness and safety come first.

## Right now

- **Issues are welcome**: bugs, missed detections, false positives, new source
  adapters you need. Please never paste real sensitive data into an issue; use
  made-up values.
- **Pull requests from outside contributors will open once our Contributor
  License Agreement has completed legal review.** Until then, please open an
  issue describing the change, and we'll pick it up with you.
- **Security problems:** see [SECURITY.md](SECURITY.md). Don't file them as
  issues.

## Contributor License Agreement

Before we can merge your first pull request, you'll be asked to agree to our
Contributor License Agreement. It takes one comment on the pull request, once:

- **Individuals:** [cla/INDIVIDUAL.md](cla/INDIVIDUAL.md)
- **On behalf of an employer:** your employer signs the
  [Corporate CLA](cla/CORPORATE.md) once, then lists who may contribute.

**In plain words:** you keep the copyright in your contribution. You give
txp-labs a broad, permanent license to use it, including under other licenses
in the future, plus a patent license for it. It is a license, **not** a
transfer of ownership. The agreement text is the binding version; this summary
is only a guide.

## Ground rules for changes

- **No values in output, ever.** Any change to detection, adapters or logging
  keeps the rule that detected values never appear in findings, logs or errors.
  The test suite enforces it, and a change that weakens that test will not be
  merged.
- Detection changes come with test cases: positives, near-misses and made-up
  data only.
- New source adapters take read-only access to the stores the user names, and
  nothing more.
- Keep dependencies few. Every dependency runs inside customers' accounts.
