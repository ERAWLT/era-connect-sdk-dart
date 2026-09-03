# TON

`ton-sign-request` (7201) out, `ton-signature` (7202) back. The device holds one
Ed25519 key per account and signs a 32-byte digest. Which digest depends on the
request kind — and both are recomputable offline, so every reply is checkable
before it leaves your app.

```dart
import 'package:era_connect/era_connect.dart'; // facade + linking
import 'package:era_connect/verify.dart';      // verifyTonSignature, bocRootHash
```

`package:era_connect/ton.dart` pulls in the chain module alone if you do not
want the rest of the SDK linked.

## The two request kinds

| `dataType` | Constant | `signData` you supply | Digest the device signs |
|---|---|---|---|
| 1 (default) | `TonDataType.transaction` | the serialised Bag of Cells | representation hash of the BoC's **root cell** |
| 2 | `TonDataType.tonProof` | the TON Connect proof payload, verbatim | `sha256(0xFF 0xFF ‖ "ton-connect" ‖ sha256(signData))` |

The proof digest, byte for byte: two `0xFF` bytes, the eleven ASCII bytes of
`ton-connect`, then the 32-byte `sha256` of your payload — 45 bytes in all,
hashed once more with `sha256`. Pass the payload the dApp handed you; the
hashing is the device's job and the verifier's, never yours. Pre-hashing it
produces a signature that verifies against nothing.

A transaction request signs the root cell **only**. Everything the user is
agreeing to — destination, amount, body, state init — has to be inside the cell
tree you serialise, because a cell's representation hash commits to its
children by hash and depth. A value hanging off a cell that is not reachable
from the root is not signed.

### The wallet contract version changes the address, not the key

`m/44'/607'/0'` is the account; V4R2 and V5R1 share it. The contract version
moves the ADDRESS, never the key: the same key signs for either, so nothing
about the request changes with it — only the address you display and send from.
`accounts.ton()` gives you the raw 32-byte public key and leaves address
assembly to your TON library. Derive it for the contract version your wallet
actually deploys, or you will show the user an address that is not the one the
funds land on.

## 1. Build the request

`TonSignRequestProps`:

| Prop | Type | Required | Notes |
|---|---|---|---|
| `requestId` | `Object?` — `Uint8List` (16) or UUID `String` | no | minted from the CSPRNG when absent |
| `signData` | `Uint8List` | yes | BoC bytes, or the proof payload. Empty throws `invalid-props` |
| `dataType` | `int?` | no | a `TonDataType` value; defaults to `transaction` |
| `path` | `String` | yes | the account path, e.g. `m/44'/607'/0'` |
| `xfp` | `Object` — u32 `int` or 8-hex `String` | yes | `accounts.ton()!.xfp` |
| `address` | `String?` | no | user-friendly bounceable text (`UQ…`/`EQ…`), shown on the device |
| `origin` | `String?` | no | overrides the config origin for this request |

On the wire: `{1: 37(<36 ASCII bytes>), 2: signData, 3: dataType,
4: 304(keypath), 5: address, 6: origin}`.

### The request id travels as ASCII

TON's id is tag 37 wrapping the **36 ASCII bytes of the hyphenated UUID
string** (`9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d`), not 16 raw bytes. That is
what the TON ecosystem emits and what the device echoes back verbatim, so the
SDK emits it too. You never format it yourself: hand the builder 16 bytes, a
UUID string, or nothing at all. Coming back, the parser accepts the 36-byte
ASCII echo and also a bare 16-byte binary echo, and normalises either to the 16
bytes in `TonSignatureResult.requestId`.

```dart
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';

/// [boc] is the serialised external message from your TON tooling.
SignRequest<TonSignatureResult> buildTonTransfer(
  EraConnect era,
  EraAccounts accounts,
  Uint8List boc,
  String bounceableAddress,
) {
  final ton = accounts.ton()!; // linked earlier from the device's export
  return era.ton.generateSignRequest(TonSignRequestProps(
    signData: boc,
    dataType: TonDataType.transaction, // the default; spelled out here
    path: ton.accountPath,             // m/44'/607'/0'
    xfp: ton.xfp,
    address: bounceableAddress,        // display only
  ));
}
```

A TON Connect proof is the same call with two fields changed:

```dart
final proof = era.ton.generateSignRequest(TonSignRequestProps(
  signData: proofPayload,        // exactly what the dApp sent
  dataType: TonDataType.tonProof,
  path: ton.accountPath,
  xfp: ton.xfp,
));
```

Display it as animated QR: `request.toAnimated()`, then push
`animated.nextFrame()` into your QR widget on a timer. The defaults match the
device's own pipeline — 180 payload bytes per fragment (~200 on the wire) every
125 ms, 8 fps (`DeviceProfile.phoneToDevice`).

## 2. Parse the reply

The reply is `{1: <echoed id>, 2: <64-byte signature>}`. `TonSignatureResult`
carries the id normalised to 16 bytes and the raw Ed25519 signature.

```dart
TonSignatureResult collect(
  SignRequest<TonSignatureResult> request,
  Iterable<String> cameraFrames,
) {
  final scanner = request.scanner(); // pinned to ton-signature
  for (final frame in cameraFrames) {
    if (scanner.receivePart(frame) is ScanComplete) break;
  }
  return scanner.parse(); // UR type + request-id echo enforced here
}
```

The device answers at 150-byte fragments every 400 ms — 2.5 fps
(`DeviceProfile.deviceToPhone`). Receiving is slower than sending; budget the
scan timeout off the device's rate, not your own.

`parse()` throws `EraSdkError` and never returns a half-checked result:

| `code` | Meaning |
|---|---|
| `wrong-ur-type` | the frame is not a `ton-signature` |
| `malformed-cbor` | the payload is not readable CBOR |
| `malformed-reply` | no id echo at key 1, no signature at key 2, or a signature that is not 64 bytes |
| `request-id-mismatch` | it answers a different sign request — a stale QR from a cancelled flow |

Parsing outside the request object works too —
`era.ton.parseSignature(ur, ExpectedReply(requestId: id))` — but then the
expected id is yours to pass. Omit it and nothing binds the reply to the
request.

## 3. Verify and broadcast

The echo proves *which* request was answered. `verifyTonSignature` proves
*what* was signed: it recomputes the digest from the same `signData` you sent
and checks the Ed25519 signature against the key you linked.

```dart
import 'package:era_connect/verify.dart';

void guardTon(
  EraAccounts accounts,
  Uint8List boc,
  TonSignatureResult reply,
) {
  final verdict = verifyTonSignature(VerifyTonSignatureArgs(
    signData: boc,                     // the bytes you sent, not a re-build
    dataType: TonDataType.transaction,
    signature: reply.signature,
    publicKey: accounts.ton()!.publicKey,
  ));
  if (!verdict.ok) throw StateError(verdict.reason!);
}
```

`VerifyTonSignatureArgs` takes `signData`, `dataType`, `signature` and the
32-byte `publicKey`. The result is `ok` / `checked` / `reason`; on this chain a
pass is always `checked: true`, because both digests are computable here.

Re-serialising the message to obtain `signData` defeats the check — a different
cell layout hashes differently, and you would be verifying your second build
rather than the one the user approved. Keep the exact bytes.

`bocRootHash(boc)` is exported as well, for assembling the signed external
message yourself. It reads generic BoCs of ordinary level-0 cells and takes the
first root, with caps that a wallet payload never approaches: 256 cells,
128 data bytes and 4 references per cell, forward-only references (the standard
topological order), and header integers bounded at 2^53 - 1 because web builds
cannot represent more. A BoC outside that shape comes back as
`Failed('signData is not a readable BoC: …')` — the check fails closed, it does
not wave the reply through.

Then attach the 64-byte signature to the external message with your TON library
and broadcast it. The SDK performs no network I/O.
