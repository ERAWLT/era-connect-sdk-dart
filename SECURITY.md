# Security policy

`era_connect` is the integration SDK for an air-gapped hardware wallet. It
never holds private keys — but it builds the requests a device signs and
parses the replies a wallet broadcasts, so a defect here can cost real funds.
Please report anything you find privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**), which keeps the whole thread private
until a fix ships. If you would rather use email, write to
**technical@hwlt.io**.

Please include the package version, a minimal reproduction, and what an
attacker gains. We aim to acknowledge within 3 working days and to ship a fix
or a mitigation plan within 30 days. Tell us if you intend to publish; we will
agree a date with you and credit you in the release notes unless you prefer
otherwise.

Do not open a public issue for a suspected vulnerability, and please do not
test against anyone else's device or funds.

## Supported versions

Fixes land on the latest minor release line, published from `main`. Older
lines are not patched — upgrade to the current version.

## What is in scope

- Anything that lets a crafted QR/UR payload escape the parser's limits:
  memory exhaustion, mis-parsed CBOR, fountain-decoder confusion, gzip
  inflation past its ceiling.
- A reply the SDK accepts as answering a request it does not answer:
  request-id binding, tag handling, signature-shape checks.
- A `verify*` helper returning `ok` for a transaction that differs from the
  one the caller passed in.
- Address or path derivation producing a value that does not match the key
  material it was derived from.

## What is out of scope

- Findings in the device firmware itself — report those through the hardware
  wallet's own channel, not here.
- Missing hardening with no exploit path, unless you can show one.
