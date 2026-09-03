# EVM

`package:era_connect/evm.dart`, or `era.evm` on the `EraConnect` facade. One
module covers every EVM network — the chain is a number in the request, not a
separate code path.

| | |
|---|---|
| Request | `eth-sign-request` (401) |
| Reply | `eth-signature` (402); `evm-signature` is accepted as well |
| Request id | bare CBOR byte string; the device echoes it (tag-37 wrapped) and the SDK compares the **bytes**, so the tag is irrelevant |
| Signs | RLP transactions, EIP-712 typed data, `personal_sign` messages |

## 1. Build the request

`EvmChain.generateSignRequest(EvmSignRequestProps)`.

| Prop | Type | Required | What it is |
|---|---|---|---|
| `signData` | `Uint8List` | yes | RLP transaction bytes, EIP-712 JSON as UTF-8, or raw message bytes |
| `dataType` | `int` | yes | one of the `EvmDataType` values below |
| `path` | `String` | yes | full signing path, e.g. `m/44'/60'/0'/0/0` |
| `xfp` | `int` (u32) or `String` (8 hex) | yes | the account's source fingerprint — `EvmAccountView.xfp`, or `EraAccounts.xfpFor(accountPath)` |
| `chainId` | `int?` | for transactions | required when `dataType` is `transaction` or `typedTransaction` |
| `address` | `Uint8List` (20 bytes) or `String` (`0x…`) | no | the signer address; pass it — the verification helper needs it, and the device shows it |
| `requestId` | `Uint8List` (16 bytes) or `String` (UUID) | no | minted from a CSPRNG when absent |
| `origin` | `String?` | no | overrides the SDK-level origin label the device shows for this one request |

### The three dataTypes

| Constant | Wire value | `signData` carries |
|---|---|---|
| `EvmDataType.transaction` | 1 | RLP transaction bytes |
| `EvmDataType.typedData` | 2 | EIP-712 typed-data JSON, UTF-8 encoded |
| `EvmDataType.personalMessage` | 3 | raw message bytes; the device applies the EIP-191 prefix itself — do not pre-prefix |
| `EvmDataType.typedTransaction` | 4 | typed (EIP-2718) transaction bytes; handled identically to `transaction` |

### The transaction kind is sniffed, not declared

The device decides legacy vs EIP-2930 vs EIP-1559 from the **leading byte of
`signData`** (`0x01`, `0x02`, or an RLP list header), not from `dataType`. That
is why 1 and 4 are the same request. Encode the transaction correctly with your
own EVM tooling; you cannot steer the device's parser with `dataType`.

### chainId is bounded by the device's parser

The device reads `chainId` as an unsigned 32-bit value. A larger id would
truncate on the way in and produce a valid signature **for a different chain**,
so the SDK refuses anything above `0xffffffff` with `invalid-props` rather than
letting that happen. `chainId` is also what derives the legal width of the reply
(see the `v` table below), which is the second reason it is mandatory for
transactions.

### Blind-sign threshold

Over 32 KiB of `signData` the device stops decoding the transaction and shows a
blind-sign screen. The SDK does not refuse it; it flags it:
`request.warnings` contains `blind-sign-threshold`. Surface that in your UI —
the user is about to approve a hash, not a transaction.

### Display

`request.toAnimated()` fragments at 180 payload bytes; render `nextFrame()` at
125 ms (8 fps). The device answers with 150-byte fragments at 400 ms
(2.5 fps) — **receiving is slower than sending**, so budget scan timeouts on the
reply leg, not the request leg. Both numbers live in `DeviceProfile`.

```dart
import 'dart:async';
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';
import 'package:era_connect/verify.dart';

/// Build, display, scan back, verify. Returns the signature only when it is
/// the device's answer to THIS request over THESE bytes.
Future<EvmSignatureResult> signEvmTransaction({
  required EraConnect era,
  required EvmAccountView account,
  required int addressIndex,
  required Uint8List rlp, // encoded by your EVM tooling
  required int chainId,
  required void Function(String qrFrame) render,
  required Stream<String> cameraFrames,
}) async {
  final address = account.deriveAddress(addressIndex);

  final request = era.evm.generateSignRequest(EvmSignRequestProps(
    signData: rlp,
    dataType: EvmDataType.transaction,
    path: account.pathFor(addressIndex),
    xfp: account.xfp,
    chainId: chainId,
    address: address,
  ));
  if (request.warnings.contains('blind-sign-threshold')) {
    // Tell the user the device cannot decode a payload this large.
  }

  final animated = request.toAnimated();
  final ticker = Timer.periodic(
    Duration(milliseconds: DeviceProfile.phoneToDevice.frameIntervalMs),
    (_) => render(animated.nextFrame()),
  );

  final scanner = request.scanner(); // pinned to the reply types
  try {
    await for (final frame in cameraFrames) {
      if (scanner.receivePart(frame) is ScanComplete) break;
    }
  } finally {
    ticker.cancel();
  }

  final signature = scanner.parse(); // UR type + request-id echo enforced

  final check = verifyEvmSignature(VerifyEvmSignatureArgs(
    signData: rlp,
    dataType: EvmDataType.transaction,
    signature: signature.signature,
    address: address,
  ));
  if (!check.ok) throw StateError(check.reason!);
  return signature;
}
```

## 2. Parse the reply

`request.scanner()` returns a scanner pinned to `eth-signature` /
`evm-signature`; `parse()` assembles and validates in one call. Standalone:
`era.evm.parseSignature(ur, ExpectedReply(requestId: id))` — without
`expect.requestId` the echo is read but **not** checked, which is why the
request's own scanner is the preferred path.

Checked for you, in order: the UR type (frames of any other type never reach
the fountain decoder), the CBOR map shape, the request-id echo byte for byte
(`request-id-mismatch`), the signature width, and that `v` folds to a plausible
recovery id.

`EvmSignatureResult`:

| Field | Type | Notes |
|---|---|---|
| `requestId` | `Uint8List` | the echoed id |
| `signature` | `Uint8List` | raw `r ‖ s ‖ v` exactly as sent; may exceed 65 bytes |
| `r`, `s` | `Uint8List` | the 32-byte scalars |
| `v` | `BigInt` | the recovery value **as sent** — see below |
| `recoveryId` | `int` | `v` folded to 0 or 1, whichever form it arrived in |

### The `v` the device returns

| Request | `v` on the wire |
|---|---|
| Typed transaction (`0x01` / `0x02` prefix) | 0 or 1 |
| Legacy transaction | already EIP-155 encoded: `parity + chainId * 2 + 35` |
| `personalMessage` / `typedData` | 27 or 28 |

Do **not** re-apply the EIP-155 formula to a legacy `v`; the device already
did. That is also why the reply width depends on `chainId`: for chain 137 a
legacy `v` is 309 or 310 (two bytes); on a chain with a large id (Aurora, for
instance) it is four. The
request computes the exact ceiling from the `chainId` it carried, so a genuine
reply on a large-id chain is accepted and an implausibly wide one is not.
`foldRecoveryId(BigInt)` is exported if you need the same folding elsewhere.

Failures arrive as `EraSdkError` with a stable `code`: `wrong-ur-type`,
`malformed-cbor`, `malformed-reply`, `request-id-mismatch`.

## 3. Verify and broadcast

```dart
verifyEvmSignature(VerifyEvmSignatureArgs(
  signData: rlp,
  dataType: EvmDataType.transaction,
  signature: reply.signature,
  address: address,
  reEncodedSignData: rlpAboutToBeBroadcast, // optional
));
```

| Argument | Type | Required | Purpose |
|---|---|---|---|
| `signData` | `Uint8List` | yes | the exact bytes the request carried |
| `dataType` | `int` | yes | the `EvmDataType` the request was built with |
| `signature` | `Uint8List` | yes | `r ‖ s ‖ v` from the reply (multi-byte `v` handled) |
| `address` | `Uint8List` or `String` | yes | the address the request was built for |
| `reEncodedSignData` | `Uint8List?` | no | the signing payload re-derived from the transaction you are **about to broadcast** |

What it proves: for a transaction the digest is `keccak256(signData)`; for
`personalMessage` it is the EIP-191 digest
(`0x19 ‖ "Ethereum Signed Message:\n" ‖ len ‖ message`). The public key is
recovered from `r ‖ s` and the folded recovery id, reduced to an address, and
compared to `address`. A pass therefore means: this signature was produced by
the key behind that address, over exactly these bytes.

`reEncodedSignData` closes the other half — that the payload is still the one in
your hands. Recovery alone proves the device signed something you asked for; if
your transaction was rebuilt after the request went out (a fee bump, a nonce
refresh), the two objects differ and the check fails closed with
"the transaction to broadcast is not the one the device signed".

Results are values, never exceptions: `VerifyResult` is `Verified`,
`Unverifiable` or `Failed`, with `ok`, `checked` and `reason`.

### EIP-712 is the one path that cannot be recomputed

`dataType: typedData` returns `Unverifiable` — `ok == true`,
`checked == false`, with a reason string. The EIP-712 digest is the hash of the
**structure** (domain separator plus hashed types), not of the JSON bytes you
sent, and the device is what computes it. There is nothing client-side to
recover against.

What still binds an EIP-712 reply to the request is the UR-type pin and the
request-id echo, plus your own review of the JSON before it went out. Treat
`checked == false` as a distinct UI state from a verified transaction; do not
render it as "verified".

### Broadcasting

The SDK hands you scalars, not a transaction — assembly belongs to your EVM
tooling. Feed `r`, `s` and `v` (as sent, unmodified) into your encoder, RLP the
signed transaction, and submit it through your own node or provider. For a
message signature the `0x`-hex of `signature` is what a dApp expects back.
