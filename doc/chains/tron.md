# Tron

`package:era_connect/tron.dart`, or `era.tron` on the `EraConnect` facade.

| | |
|---|---|
| Request | `keystone-sign-request` (6101) — CBOR `{1: gzip(protobuf), 2: origin}` |
| Reply | `keystone-sign-result` (6102) — the same envelope, carrying a complete transaction |
| Request id | no CBOR id; a `signId` UUID string inside the protobuf does that job |
| Signs | any contract, because the request carries raw `raw_data` |

## The envelope, and the one that does not work

The device speaks the **structured** `keystone-sign-request` (6101): a
gzip-compressed protobuf wrapped in CBOR. The registry's generic
`tron-sign-request` (5101) is not accepted by the device and gets no response at
all — a request built that way looks like a hung scan, not an error. This module
emits only the structured envelope; do not hand-roll the generic one.

## `rawData` is the signing truth

The device signs `sha256(rawData)`, which *is* the Tron txID, and returns the
transaction built around that same `raw_data`. What it signs is never derived
from the fields you display.

Two consequences:

- **Any contract signs.** A `TriggerSmartContract` for a swap, a staking
  operation, a permission update — if your Tron tooling can serialize it into
  `Transaction.raw_data`, this path signs it. Nothing here is transfer-only.
- **The display fields are screen-only.** `token`, `to`, `value` and the rest
  decide what the user reads on the device; they decide nothing about what is
  signed. Deriving them from anything other than the same `raw_data` you send is
  how a confirmation screen ends up describing a different transaction from the
  one being approved.

## 1. Build the request

`TronChain.generateSignRequest(TronSignRequestProps)`.

| Prop | Type | Required | What it is |
|---|---|---|---|
| `rawData` | `Uint8List` | yes | serialized `Transaction.raw_data` — the signing source of truth; must not be empty |
| `path` | `String` | yes | full signing path, e.g. `m/44'/195'/0'/0/0` |
| `xfp` | `int` (u32) or `String` (8 hex) | yes | the account's source fingerprint — `TronAccountView.xfp` |
| `latestBlock` | `TronLatestBlock` | yes | the reference block; see below |
| `display` | `TronSignDisplay?` | no | on-device display only; safe to omit for an opaque dApp transaction |
| `timestamp` | `int?` | no | request timestamp in Unix milliseconds; defaults to 0 |
| `requestId` | `Uint8List` (16 bytes) or `String` (UUID) | no | minted from a CSPRNG when absent |
| `origin` | `String?` | no | overrides the SDK-level origin label for this request |

### latestBlock needs a live, full block id

`TronLatestBlock`:

| Field | Type | Required | What it is |
|---|---|---|---|
| `hash` | `String` | yes | the **full 64-hex block id** of a live now-block |
| `number` | `int` | yes | the block height |
| `timestamp` | `int` | yes | the block timestamp in Unix milliseconds |

The device slices `ref_block_hash` out of the block id itself, so it needs the
whole thing: a 16-hex `ref_block_hash` slice is refused with `invalid-props`.
Source it from a now-block query made just before the request goes out — Tron
transactions expire against that reference, and a stale anchor produces a
signature for a transaction the network will no longer accept.

### The display fields

`TronSignDisplay` — every field optional, every field cosmetic:

| Field | Type | Shown as |
|---|---|---|
| `token` | `String?` | the token symbol |
| `contractAddress` | `String?` | the TRC-20 contract, for a token transfer |
| `from` | `String?` | sender, base58 |
| `to` | `String?` | recipient, base58 |
| `value` | `String?` | the human-readable amount string |
| `memo` | `String?` | a memo line |
| `fee` | `int?` | fee in SUN; must fit a positive int32 |
| `decimals` | `int?` | token decimals; defaults to 6 |

### Display and scan budget

`request.toAnimated()` fragments at 180 payload bytes; render `nextFrame()` at
125 ms (8 fps). The device answers with 150-byte fragments at 400 ms
(2.5 fps) — receiving is slower than sending, so budget scan timeouts on the
reply leg. Both numbers live in `DeviceProfile`.

```dart
import 'dart:async';
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';
import 'package:era_connect/verify.dart';

/// Sign any Tron transaction: the contract inside rawData is the device's
/// business, not this function's.
Future<String> signTron({
  required EraConnect era,
  required TronAccountView account,
  required Uint8List rawData, // serialized Transaction.raw_data
  required TronLatestBlock latestBlock, // from a live now-block query
  TronSignDisplay? display,
  required void Function(String qrFrame) render,
  required Stream<String> cameraFrames,
}) async {
  final owner = account.deriveAddress(0);

  final request = era.tron.generateSignRequest(TronSignRequestProps(
    rawData: rawData,
    path: account.pathFor(0),
    xfp: account.xfp,
    latestBlock: latestBlock,
    display: display,
  ));

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

  final reply = scanner.parse(); // TronSignatureResult, signId echo enforced

  final check = verifyTronSignature(VerifyTronSignatureArgs(
    rawData: rawData,
    from: owner,
    latestBlock: latestBlock,
    signedTx: reply.signedTx,
  ));
  if (!check.ok) throw StateError(check.reason!);

  return reply.rawTx; // broadcast as-is
}
```

A transfer that should read nicely on the device adds display metadata:

```dart
final display = TronSignDisplay(
  token: 'TRX',
  from: owner,
  to: recipient,
  value: '12.500000',
  decimals: 6,
);
```

## 2. Parse the reply

`TronSignatureResult`:

| Field | Type | Notes |
|---|---|---|
| `requestId` | `Uint8List` | the id the reply's `signId` resolved to |
| `txId` | `String` | `sha256(raw_data)` hex, as computed by the device |
| `rawTx` | `String` | hex of the fully assembled signed transaction — broadcast as-is |
| `signedTx` | `SignedTronTx` | the frame split into `rawData` and `signatures` (65 bytes each, `r ‖ s ‖ recovery`) |

Checked for you: the UR type, the CBOR map, the compressed payload against an
8 KiB ceiling and the inflated protobuf against 64 KiB (`limit-exceeded` — Tron
is the only chain whose reply is compressed, so it is the only one where a few
hundred scanned bytes could ask for an arbitrary allocation), that `rawTx` is
present and splits into a transaction frame, and — when the request's own
scanner is used — that the protobuf's `signId` echoes the request id
(`request-id-mismatch`).

**That `signId` echo is the only anti-replay binding on this path.** There is no
CBOR request id to fall back on, and the device's own bytes are broadcast
verbatim, so a stale reply accepted without the check would finalize a payment
the user approved at some other time. Use `request.scanner()`; if you parse
standalone with `era.tron.parseSignature(...)`, pass
`ExpectedReply(requestId: id)` — without it there is nothing to compare against
and the check silently does not happen.

## 3. Verify and broadcast

```dart
verifyTronSignature(VerifyTronSignatureArgs(
  rawData: rawData,
  from: ownerAddress,
  latestBlock: latestBlock,
  signedTx: reply.signedTx,
));
```

| Argument | Type | Required | Purpose |
|---|---|---|---|
| `rawData` | `Uint8List` | yes | the `raw_data` bytes the request carried |
| `from` | `String` | yes | the base58 owner address the transaction spends from |
| `signedTx` | `SignedTronTx` or `String` | yes | the reply's split frame, or its `rawTx` hex |
| `latestBlock` | `TronLatestBlock?` | no | the reference block the request carried; enables the rebuild-path window check |

The reply is a finished transaction that will be broadcast verbatim, so the
helper checks it on both counts.

**Whose key signed it.** Every signature in the frame is recovered over
`sha256(signedTx.rawData)` and reduced to a Tron address; each must equal
`from`. A signature by any other key fails.

**What it moves.** If `signedTx.rawData` equals the request's `rawData` byte for
byte, that is the strong form and the check is done. When it differs — a
firmware that rebuilds `raw_data` from the semantic fields — the helper falls
back to comparing the fields that decide where the money goes: the contract must
be the same kind, and for `TransferContract`, `TransferAssetContract` and
`TriggerSmartContract` the owner, recipient/contract, amount or call data and
call value must match. Any other contract kind without byte equality is
**refused**, not waved through: there would be nothing left binding it to what
the user approved. With `latestBlock` supplied, the rebuilt transaction's
timestamp must also match the reference block, and its expiry must fall inside
the window the device's builders produce.

`VerifyResult` is a value, never an exception: `Verified`, `Unverifiable` or
`Failed`, with `ok`, `checked` and `reason`.

### Broadcast

`rawTx` is a complete, network-ready transaction frame — hex in, hex out.
Submit it unchanged through your Tron node or indexer (the hex-broadcast
endpoint, or your client's equivalent). Do not re-serialize it: the signature
covers the device's own `raw_data` bytes, and a round trip through another
protobuf writer can change them.
