# Security policy

This scanner runs inside customers' cloud accounts and looks for sensitive data,
so we treat security reports as our highest priority.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request.**

Report it privately through GitHub:
**Security** tab → **Report a vulnerability** (private vulnerability reporting
is enabled on this repository).

Include what you found, how to reproduce it, and the version or commit affected.
We are especially interested in anything that could:

- cause a detected value (a card number, an SSN and the like) to appear in
  results, logs or errors;
- let the scanner read or write outside the stores it has been granted;
- let anyone other than the release signer publish code the scanner will run.

## What to expect

- We acknowledge a report within 3 business days.
- We give an initial assessment within 10 business days.
- We coordinate disclosure with you, and credit you if you wish once a fix is
  released.

## Supported versions

Until 1.0, only the latest release receives security fixes.
