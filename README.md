# era_connect

Air-gapped **ERA hardware wallet** integration for Dart and Flutter wallets:
account linking and transaction signing over animated QR codes (BC-UR /
Keystone-compatible registry), for **every chain the device ships** — EVM
(all networks), Bitcoin (+ Litecoin, Dogecoin, Dash, Bitcoin Cash), Solana,
Tron, TON, Cardano, Sui, Cosmos (~35 zones) and XRP.

This is the Dart port of
[`@hwlt/era-connect`](https://www.npmjs.com/package/@hwlt/era-connect) —
**byte-for-byte compatible** with it on every wire format, pinned by
committed cross-SDK parity fixtures.

- **Headless.** You render the QR and own the camera; the SDK owns every byte
  of the protocol. Pure Dart — works in Flutter (all platforms), CLI and web.
- **Zero I/O.** No network calls, ever. No `dart:io` in the library.
- **Verified against the device.** The fountain encoder reproduces the
  canonical BCR-2020-005 frames bit-for-bit; every request byte-matches the
  TypeScript SDK that is proven on hardware.
- **Hardened where it matters.** The scanner refuses hostile QR frames
  (stream binding needs a second distinct fragment), every reply must echo
  the request id byte-for-byte, gzip replies inflate under a hard ceiling,
  and the `verify` library proves the device signed *exactly* what you sent.

## Install

```sh
dart pub add era_connect
```

## 60 seconds to a signature

```dart
import 'package:era_connect/era_connect.dart';

final era = EraConnect(EraConnectConfig(origin: 'MyWallet')); // shown on device

// 1. LINK — scan the device's "connect" QR.
final scanner = era.scanner(
    UrScannerOptions(expectedTypes: ['crypto-multi-accounts']));
// feed camera frames: scanner.receivePart(text) until scanner.isComplete
final accounts = era.parseAccounts(scanner.result());
final evm = accounts.evm()!;
evm.deriveAddress(0); // 0x… — derived locally, no device round-trip

// 2. SIGN — build the tx with your chain tooling, hand the raw bytes over.
final request = era.evm.generateSignRequest(EvmSignRequestProps(
  signData: rawRlpBytes,
  dataType: EvmDataType.transaction,
  path: evm.pathFor(0),
  xfp: evm.xfp,
  chainId: 1,
));

// 3. DISPLAY — animate the request as QR frames.
final animated = request.toAnimated();
// render animated.nextFrame() on a timer (150–250 ms per frame works well)

// 4. SCAN the reply; the request-id echo is enforced for you.
final replyScanner = request.scanner();
// feed camera frames …
final signature = replyScanner.parse();

// 5. VERIFY before broadcasting.
// import 'package:era_connect/verify.dart';
// final check = verifyEvmSignature(…);
// if (!check.ok) throw StateError(check.reason!);
```

## Chain support

Every chain family the current device firmware ships has a dedicated module:

| Chain | Sign transaction | Library |
|---|---|---|
| EVM (all chains) | `eth-sign-request` (tx / personal_sign / EIP-712) | `package:era_connect/evm.dart` |
| Bitcoin | `crypto-psbt` (PSBT v0); messages per firmware | `package:era_connect/btc.dart` |
| Litecoin, Dogecoin, Dash | `crypto-psbt-extend` (same flow as Bitcoin) | `package:era_connect/btc.dart` |
| Bitcoin Cash | structured envelope (FORKID signing, CashAddr) | `package:era_connect/bch.dart` |
| Solana | `sol-sign-request` (tx + off-chain messages) | `package:era_connect/solana.dart` |
| Tron | structured envelope (any contract via `rawData`) | `package:era_connect/tron.dart` |
| TON | `ton-sign-request` (BoC root-hash signing, TON Connect proofs) | `package:era_connect/ton.dart` |
| Cardano | `cardano-sign-request` (witness-set replies) | `package:era_connect/cardano.dart` |
| Sui | `sui-sign-request` / hash variant | `package:era_connect/sui.dart` |
| Cosmos (~35 zones incl. Ethermint) | `cosmos-sign-request` / `evm-sign-request` | `package:era_connect/cosmos.dart` |
| XRP | `ur:bytes` (XRP Toolkit convention) | `package:era_connect/xrp.dart` |

The root `package:era_connect/era_connect.dart` exports all of it behind the
[EraConnect] facade; per-chain libraries keep a minimal import surface, and
`package:era_connect/verify.dart` holds the verification helpers.

## Verification

The reply's request-id echo proves *which* request was answered — the
`verify` library proves *what* was signed. Run the chain's helper between
parsing and broadcasting; it is **mandatory** on the paths that carry no
request id at all (Bitcoin PSBT, XRP):

```dart
import 'package:era_connect/verify.dart';

verifyEvmSignature(…);   verifySignedPsbt(…);    verifyBchSignedTx(…);
verifySolanaSignature(…); verifyTronSignature(…); verifyTonSignature(…);
verifyCardanoSignature(…); verifySuiSignature(…);
verifyCosmosSignature(…);  verifyXrpSignature(…);
```

Every helper returns `ok/checked/reason` and fails closed on a substituted
payload, a tampered value or a signature by the wrong key.

## Documentation

The protocol guides are shared with the TypeScript SDK — same wire formats,
same flows, same device:
[github.com/ERAWLT/era-connect-sdk/docs](https://github.com/ERAWLT/era-connect-sdk/tree/main/docs)
(per-chain guides, device specifics vs. the Keystone registry, QR tuning,
verification). Dart-specific API details live in this package's dartdoc.

## License

Apache-2.0 — see LICENSE and NOTICE.
