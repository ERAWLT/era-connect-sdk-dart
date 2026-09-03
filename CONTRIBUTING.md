# Contributing

## Layout

- `lib/` — the package. `lib/era_connect.dart` is the root library; the
  per-chain libraries (`lib/evm.dart`, `lib/btc.dart`, …) and `lib/verify.dart`
  are the narrow import surfaces.
- `lib/src/` — implementation. Nothing here is public API; everything a caller
  needs is re-exported from an entry library.
- `doc/` — the guides. `doc/README.md` is the index.
- `test/` — the suite, including the golden vectors and the parity fixtures.

## Developing

```sh
dart pub get
dart test
dart analyze --fatal-infos
dart format lib test example
```

## What the review looks for

- **Byte-exactness is the contract.** Request CBOR must replay the golden
  vectors byte for byte; a wire-affecting change needs regenerated goldens and
  a matching documentation update.
- **Errors are typed.** Every throw on an SDK path is an `EraSdkError` with a
  stable `code`. Callers branch on the code, so treat the set as API.
- **Scanned input is hostile input.** A new parse path gets its bounds checks
  before its allocations, and property tests alongside its unit tests.
- **The package holds no keys and performs no I/O.** No `dart:io` in `lib/`,
  no network calls, ever.

## Releasing

Bump `version` in `pubspec.yaml`, add the entry to `CHANGELOG.md`, tag
`v<version>` and push the tag — the publish workflow takes it from there.
