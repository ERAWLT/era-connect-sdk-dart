# era_connect

Put the **ERA air-gapped hardware wallet** behind a Dart or Flutter wallet.
The device never touches a cable or a radio: sign requests leave your app as
animated QR frames, signatures come back the same way.

Account linking and transaction signing for **eleven chain families** — EVM
(all networks), Bitcoin, Litecoin, Dogecoin, Dash, Bitcoin Cash, Solana, Tron,
TON, Cardano, Sui, Cosmos and XRP.

- **Headless.** You render the QR and own the camera; this package owns every
  byte of the protocol — BC-UR fountain encoding, the Keystone-compatible
  registry, the CBOR layouts, the reply checks.
- **Pure Dart.** No plugins, no `dart:io` in the library. Flutter on every
  target, plus CLI and web.
- **Zero I/O.** No network calls, ever. Nothing leaves the process.
- **No keys, ever.** The device signs; this package builds requests, reads
  replies and derives public addresses. There is no signer here to misuse.
- **Hardened where it matters.** A scanned QR is attacker-controlled input, so
  it is treated that way: bounds precede allocations, the scanner refuses
  hostile frames, every reply must echo its request id, and compressed replies
  inflate under a hard ceiling.

## Install

```sh
dart pub add era_connect
```

## Sixty seconds to a signature

```dart
import 'package:era_connect/era_connect.dart';

final era = EraConnect(EraConnectConfig(origin: 'MyWallet')); // shown on device

// 1. LINK — scan the device's "connect" QR once.
// walletUrTypes pins every shape a wallet export can arrive in.
final scanner = era.scanner(
    UrScannerOptions(expectedTypes: walletUrTypes.toList()));
// feed camera frames: scanner.receivePart(text) until scanner.isComplete
final accounts = era.parseAccounts(scanner.result());

final evm = accounts.evm()!;
evm.deriveAddress(0); // 0x… — derived locally, no device round-trip

// 2. SIGN — build the transaction with your chain tooling, hand over the bytes.
final request = era.evm.generateSignRequest(EvmSignRequestProps(
  signData: rawRlpBytes,
  dataType: EvmDataType.transaction,
  path: evm.pathFor(0),
  xfp: evm.xfp,
  chainId: 1,
));

// 3. DISPLAY — animate the request as QR frames.
final animated = request.toAnimated();
// render animated.nextFrame() on a timer (~125 ms per frame)

// 4. SCAN the reply. The request-id echo is enforced for you.
final replyScanner = request.scanner();
// feed camera frames …
final signature = replyScanner.parse();

// 5. VERIFY before broadcasting — see package:era_connect/verify.dart
```

Full walkthrough: [doc/getting-started](doc/getting-started/01-install.md).

## Chain support

Ten modules cover eleven families — Litecoin, Dogecoin and Dash ride the
Bitcoin module, since the device signs them through the same PSBT flow.

| Chain | Signing | Library |
|---|---|---|
| EVM (all networks) | transactions, `personal_sign`, EIP-712 | `package:era_connect/evm.dart` |
| Bitcoin | PSBT v0; messages (script types depend on firmware) | `package:era_connect/btc.dart` |
| Litecoin, Dogecoin, Dash | the Bitcoin PSBT flow with a coin id | `package:era_connect/btc.dart` |
| Bitcoin Cash | structured envelope, FORKID sighash, CashAddr | `package:era_connect/bch.dart` |
| Solana | transactions (incl. versioned), off-chain messages | `package:era_connect/solana.dart` |
| Tron | any contract — the raw `raw_data` is what gets signed | `package:era_connect/tron.dart` |
| TON | BoC root-hash signing, TON Connect proofs | `package:era_connect/ton.dart` |
| Cardano | witness sets, soft-derived vkey binding | `package:era_connect/cardano.dart` |
| Sui | intent-message signing, local address derivation | `package:era_connect/sui.dart` |
| Cosmos (~35 zones incl. Ethermint) | Amino, Direct, ADR-036 | `package:era_connect/cosmos.dart` |
| XRP | the XRP Toolkit `ur:bytes` convention | `package:era_connect/xrp.dart` |

`package:era_connect/era_connect.dart` re-exports all of it behind the
`EraConnect` facade. The per-chain libraries exist so an app that signs one
chain does not import ten.

## Verify before you broadcast

The reply's request-id echo proves *which* request was answered.
`package:era_connect/verify.dart` proves *what* was signed — it recomputes the
digest, checks the signature against the key the request named, and compares
the returned transaction with the one you sent.

```dart
import 'package:era_connect/verify.dart';

final check = verifyEvmSignature(/* … */);
if (!check.ok) throw StateError(check.reason!);
```

On two paths there is **no request id at all** — Bitcoin PSBT and XRP — so the
content check is the only binding you have. Verification is mandatory there,
not advisory. Details in [doc/advanced/verification.md](doc/advanced/verification.md).

## Documentation

- [Getting started](doc/getting-started/01-install.md) — five pages, install
  to verified signature
- [Chain guides](doc/README.md#chain-guides) — one per family: props, replies,
  verification, broadcasting
- [Verification](doc/advanced/verification.md) · [QR tuning](doc/advanced/qr-tuning.md) ·
  [Flutter integration](doc/advanced/flutter.md) ·
  [Key-derivation calls](doc/advanced/key-derivation-call.md) ·
  [WalletConnect](doc/advanced/walletconnect.md)
- API reference: the dartdoc on pub.dev

## Security

Found a flaw? Please report it privately — see [SECURITY.md](SECURITY.md).

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
