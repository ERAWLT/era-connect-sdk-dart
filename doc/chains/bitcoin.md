# Bitcoin (and Litecoin, Dogecoin, Dash)

`package:era_connect/btc.dart`, or `era.btc` on the `EraConnect` facade. Two
independent flows live here: **PSBT signing** and **message signing**. They
share nothing but the module.

| | PSBT | Message |
|---|---|---|
| Request | `crypto-psbt` (310), or `crypto-psbt-extend` for LTC/DOGE/DASH | `btc-sign-request` (8101) |
| Reply | `crypto-psbt` / `crypto-psbt-extend` | `btc-signature` (8102) |
| Request id | **none, in either direction** | 16 bytes, tag-37 wrapped on the request and echoed back |
| Anti-replay | `verifySignedPsbt` — the content comparison IS the binding | the request-id echo, checked for you |

Bitcoin Cash does **not** ride this path. Its consensus sighash needs an
envelope of its own — see [bch.md](bch.md).

## 1. Build the request

### PSBT

`BtcChain.generatePsbtSignRequest(BtcPsbtSignRequestProps)`.

| Prop | Type | Required | What it is |
|---|---|---|---|
| `psbt` | `Uint8List` | yes | raw PSBT **v0** bytes (BIP-174), built by your Bitcoin library |
| `coin` | `PsbtCoin?` | no | `PsbtCoin.btc` (default), `ltc`, `doge`, `dash` |

The UR payload is a bare CBOR byte string of the PSBT — no map, no origin
label, no request id. Everything the device needs is inside the PSBT.

**PSBT v0 is required.** The device's signer reads the global `UNSIGNED_TX`
field (key type `0x00`), which is the one place a v0 file carries the
transaction being signed. A v2 PSBT describes the transaction as per-input and
per-output fields instead and has no such global, so the signer has nothing to
sign. The request path itself only checks that the bytes are not empty; the
structural reader behind `verifySignedPsbt` is where a non-v0 file gets named as
one — "no global unsigned transaction — not a PSBT v0", or "unsupported PSBT
version" for a non-zero `PSBT_GLOBAL_VERSION`. If your library emits v2, convert
before sending.

### Message

`BtcChain.generateMessageSignRequest(BtcMessageSignRequestProps)`.

| Prop | Type | Required | What it is |
|---|---|---|---|
| `message` | `Uint8List` | yes | the raw message bytes |
| `path` | `String` | yes | full signing path, e.g. `m/84'/0'/0'/0/0` |
| `xfp` | `int` (u32) or `String` (8 hex) | yes | the account's source fingerprint — `BtcAccountView.xfp` |
| `address` | `String` | yes | the address whose key sits at `path` |
| `requestId` | `Uint8List` (16 bytes) or `String` (UUID) | no | minted from a CSPRNG when absent |
| `origin` | `String?` | no | overrides the SDK-level origin label for this request |

`xfp` is not optional here. The device resolves the signing key from the
keypath's fingerprint plus the path, and a request that names neither the right
account nor the right address gets no usable answer.

### What the device will sign a message with

This is firmware-dependent, and the difference is visible in the reply, so
handle both:

| Firmware | Signs | Refuses | Reply carries |
|---|---|---|---|
| 2.1.0 and newer | BIP-44 (`1…`), BIP-49 (`3…`) and BIP-84 (`bc1q…`) addresses, each with the matching BIP-137 header | Taproot (`bc1p…`) — BIP-137 defines no header range for it | the raw 65-byte signature |
| older | legacy P2PKH (`1…`) only | every segwit address, answered with an **empty** signature | the ASCII of a base64 string |

The SDK accepts both reply encodings and normalizes them, so your code does not
branch on firmware — but your *UX* may want to, because on older firmware a
native-segwit account cannot sign a message at all.

### Display

`request.toAnimated()` fragments at 180 payload bytes; render `nextFrame()` at
125 ms (8 fps). The device answers with 150-byte fragments at 400 ms
(2.5 fps) — receiving is slower than sending, so budget scan timeouts on the
reply leg. Both numbers live in `DeviceProfile`.

```dart
import 'dart:async';
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';
import 'package:era_connect/verify.dart';

/// Send a PSBT v0 to the device and return the signed (NOT finalized) one.
Future<Uint8List> signPsbt({
  required EraConnect era,
  required Uint8List psbt, // v0, from your Bitcoin library
  required void Function(String qrFrame) render,
  required Stream<String> cameraFrames,
}) async {
  final request = era.btc.generatePsbtSignRequest(
    BtcPsbtSignRequestProps(psbt: psbt),
  );

  final animated = request.toAnimated();
  final ticker = Timer.periodic(
    Duration(milliseconds: DeviceProfile.phoneToDevice.frameIntervalMs),
    (_) => render(animated.nextFrame()),
  );

  final scanner = request.scanner();
  try {
    await for (final frame in cameraFrames) {
      if (scanner.receivePart(frame) is ScanComplete) break;
    }
  } finally {
    ticker.cancel();
  }

  final reply = scanner.parse(); // BtcPsbtResult

  // MANDATORY on this path: nothing else binds the reply to the request.
  final check = verifySignedPsbt(VerifySignedPsbtArgs(
    sentPsbt: psbt,
    signedPsbt: reply.psbt,
  ));
  if (!check.ok) throw StateError(check.reason!);

  return reply.psbt;
}
```

## 2. Parse the reply

### PSBT

`BtcPsbtResult.psbt` is the **signed but not finalized** PSBT. The device adds
per-input signature fields (`PSBT_IN_PARTIAL_SIG`, or the Taproot signature
fields) and returns the same file otherwise untouched. It does not build
`scriptSig` / witness data — finalizing is your library's job.

The parser accepts both reply shapes: a bare CBOR byte string (`crypto-psbt`)
and the extend map `{1: psbt, 2: coinId}` (`crypto-psbt-extend`). An empty or
non-byte-string payload is `malformed-reply`.

### Message

`BtcMessageSignatureResult`:

| Field | Type | Notes |
|---|---|---|
| `requestId` | `Uint8List` | the echoed id, already compared for you |
| `signature` | `Uint8List` | raw 65-byte BIP-137 signature: header ‖ `r` ‖ `s` |
| `signatureBase64` | `String` | the base64 form verifiers and dApps expect |
| `publicKey` | `Uint8List?` | present when the reply carries one |

Checked for you: the UR type, the CBOR map, the request-id echo byte for byte,
and that the payload resolves to exactly 65 bytes in either wire encoding.

An **empty** signature is a typed refusal, not a malformed reply: the SDK
throws `EraSdkError` with code `empty-signature`. That is the device saying it
cannot sign a message for this address kind — Taproot on 2.1.0+, anything but
legacy P2PKH on older firmware. Catch it and say so; do not retry.

## 3. Verify and broadcast

### verifySignedPsbt — mandatory, not advisory

```dart
verifySignedPsbt(VerifySignedPsbtArgs(
  sentPsbt: psbt,
  signedPsbt: reply.psbt,
  requireEveryInputSigned: true, // default
));
```

| Argument | Type | Required | Purpose |
|---|---|---|---|
| `sentPsbt` | `Uint8List` | yes | the PSBT you sent |
| `signedPsbt` | `Uint8List` | yes | the PSBT that came back |
| `requireEveryInputSigned` | `bool` | no (default `true`) | `true` for a plain send where every input is yours; `false` for a dApp `signPsbt` hand-back that legitimately carries inputs you cannot sign |

The PSBT path carries **no request id in either direction**, so there is no echo
to check — comparing the content is the only thing that ties the reply to the
request. Skipping it re-opens replay: an old signed PSBT re-presented to your
camera would sail through as an answer to the transaction on screen.

What the comparison proves:

- The global unsigned transaction is compared **byte for byte**, which pins the
  input set and its order, every output script and amount, the version and the
  locktime in one shot — and therefore the txid. The device only *adds* per-input
  signature fields, so a legitimate reply always matches.
- An input that comes back **finalized** must have been sent that way, with
  byte-identical `finalScriptSig` / `finalScriptWitness` values. Those fields
  carry the complete script that will be broadcast, they live per input rather
  than in the global map, and the device echoes them — it never authors them. A
  finalized field that appeared in flight is refused.
- With `requireEveryInputSigned: true`, an input left unsigned is refused here,
  with a reason, instead of failing opaquely inside your finalizer later.

Then finalize and broadcast with your own stack: extract the network
transaction from the finalized PSBT and submit it. `parsePsbt` (exported from
`package:era_connect/verify.dart`) is available if you want to inspect
`ParsedPsbt.unsignedTx`, `version`, `inputs` or `outputs` yourself; it is a
structural reader for the guard, not a replacement for a Bitcoin library.

### verifyBtcMessageHeader

```dart
verifyBtcMessageHeader(VerifyBtcMessageHeaderArgs(
  address: address,
  signature: reply.signature,
));
```

| Argument | Type | Required | Purpose |
|---|---|---|---|
| `address` | `String` | yes | the address the request asked the device to sign with |
| `signature` | `Uint8List` | yes | the raw 65-byte signature from the reply |

BIP-137 puts the address type in the recovery header, and every verifier
downstream derives the address from that header before comparing. A header from
the wrong range produces a signature that *looks* fine — 65 bytes, valid
base64 — and fails everywhere it is presented. This check is the only place that
difference is visible:

| Address | Header range |
|---|---|
| legacy P2PKH (`1…`, `m…`, `n…`) | 27–34 |
| P2SH / nested segwit (`3…`, `2…`) | 35–38 |
| native segwit P2WPKH (`bc1q…`) | 39–42 |
| Taproot (`bc1p…`) | `Unverifiable` — BIP-137 does not cover it (BIP-322 is the scheme) |

Anything the helper cannot classify returns `Unverifiable` rather than a
verdict: a guard that invents a range for a string it does not understand is
worse than one that declines to judge.

## Litecoin, Dogecoin and Dash

Same PSBT flow, same reply handling, same `verifySignedPsbt` — one extra prop:

```dart
final request = era.btc.generatePsbtSignRequest(BtcPsbtSignRequestProps(
  psbt: psbt,
  coin: PsbtCoin.doge,
));
```

`coin` switches the request to `crypto-psbt-extend`, whose payload is
`{1: psbt, 2: coinId}` — the same PSBT plus the coin the device should sign it
for (LTC 2, DOGE 3, DASH 5). The reply may come back as either
`crypto-psbt-extend` or plain `crypto-psbt`; `request.scanner()` accepts both.

Build the PSBT with the coin's own derivation paths — the device derives the
signing key from the paths inside the file:

| Coin | `PsbtCoin` | Account path |
|---|---|---|
| Litecoin | `PsbtCoin.ltc` | `m/84'/2'/0'/…` |
| Dogecoin | `PsbtCoin.doge` | `m/44'/3'/0'/…` |
| Dash | `PsbtCoin.dash` | `m/44'/5'/0'/…` |

Message signing (`btc-sign-request`) is Bitcoin only.
