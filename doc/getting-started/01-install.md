# 1. Install

`era_connect` integrates the air-gapped ERA hardware wallet into a Dart or
Flutter wallet. The device never touches a cable or a radio: everything crosses
as animated QR codes carrying BC-UR frames, and the SDK owns every byte of
that protocol.

Five pages, in order, take you from an empty project to a verified signature.

## Add the package

```sh
dart pub add era_connect
```

or, by hand:

```yaml
dependencies:
  era_connect: ^0.2.0
```

Requirements: Dart SDK `^3.4.0`. The library is **pure Dart** — no
`dart:io`, no plugins, no platform channels, and it performs no network I/O
ever. It runs unchanged in Flutter (Android, iOS, macOS, Windows, Linux, web),
in a CLI, in a server process and in a test.

## The import surface

Three tiers. Pick the narrowest one that covers your app.

| Import | You get |
|---|---|
| `package:era_connect/era_connect.dart` | The `EraConnect` facade, every chain module, linking (`EraAccounts`), the pull-model hardware call, the `raw` escape hatch, the QR transport, `EraSdkError` |
| `package:era_connect/evm.dart` (and `btc`, `bch`, `solana`, `tron`, `ton`, `cardano`, `sui`, `cosmos`, `xrp`) | One chain module plus the shared plumbing it needs: `SignRequest`, `AnimatedUr`, `UrScanner`, `Ur`, `EraConnectConfig`, `EraSdkError` |
| `package:era_connect/verify.dart` | The verification helpers only — "did the device sign exactly what I sent?" |

Ten chain modules cover **eleven chain families**: Litecoin, Dogecoin and Dash
ride the `btc` module through `crypto-psbt-extend`, sharing Bitcoin's PSBT flow
with a coin id attached.

The root library is the normal choice:

```dart
import 'package:era_connect/era_connect.dart';

final era = EraConnect(const EraConnectConfig(origin: 'MyWallet'));
final request = era.evm.generateSignRequest(/* ... */);
```

`origin` is the label the device shows the user on every request — set it to
your wallet's name. Omit the config and it reads `ERA Connect`.

A subpath library is the choice when you ship one chain and want a minimal
import graph. Each chain class takes the same config directly, no facade:

```dart
import 'package:era_connect/evm.dart';

final evm = EvmChain(const EraConnectConfig(origin: 'MyWallet'));
final request = evm.generateSignRequest(/* ... */);
```

`verify.dart` is deliberately separate so its curve arithmetic is only linked
by apps that use it. Use it. Page 5 explains why.

`EraAccounts`, `EraConnect`, `RawModule` and `generateKeyDerivationCall` live
in the **root** library only — a subpath library carries its chain and the
transport, nothing else.

## What this package does not do

It is headless on purpose. Four jobs stay yours:

| Not in the SDK | You supply |
|---|---|
| Rendering a QR code | A QR widget. `qr_flutter`, `barcode_widget` and `pretty_qr_code` all take a `String` and draw it |
| Reading the camera | A scanner. `mobile_scanner` is the common choice; anything that hands you the decoded text per frame works |
| Building transactions | Your chain tooling. The SDK takes finished bytes — RLP, a PSBT, a compiled Solana message, a Cardano tx CBOR — and never constructs them for you (Bitcoin Cash is the one exception: the device's FORKID signer needs a structured request, so the `bch` module assembles the container from your inputs and outputs) |
| Holding keys | Nobody. The device holds the seed; this SDK is watch-only and has no code path that could produce a private key |

The interface between your app and the SDK is therefore just strings: you hand
a QR widget the frames the SDK produces, and you hand the SDK the frames your
camera decodes.

## Smoke test, no device required

The transport round-trips against itself. This is a complete program; run it
to prove the package is wired into your project correctly.

```dart
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';

void main() {
  final era = EraConnect(const EraConnectConfig(origin: 'MyWallet'));

  // Any UR will do — the raw module is the escape hatch for exactly this.
  final ur = era.raw.ur(
    'bytes',
    Uint8List.fromList(List<int>.generate(600, (i) => i % 251)),
  );
  final animated = era.raw.animate(ur);
  print('${animated.fragmentCount} fragments, single frame: '
      '${animated.isSingleFrame}');

  // Feed the frames straight back into a scanner, as a camera would.
  final scanner = era.scanner(const UrScannerOptions(expectedTypes: ['bytes']));
  var frames = 0;
  while (!scanner.isComplete) {
    scanner.receivePart(animated.nextFrame());
    frames++;
  }
  print('reassembled ${scanner.result().cbor.length} bytes from $frames frames');
}
```

Expect more frames than fragments: the encoder is a fountain, and the decoder
takes whatever combination arrives.

---

Next: **[2. Link the device](02-link-device.md)** — scan the wallet export once
and derive every address locally.
