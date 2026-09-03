# Sui

Two request types, one reply type: `sui-sign-request` (7101) or
`sui-sign-hash-request` (7103) out, `sui-signature` (7102) back. Ed25519 over a
32-byte BLAKE2b digest.

```dart
import 'package:era_connect/era_connect.dart'; // facade + linking + suiIntentDigest
import 'package:era_connect/verify.dart';      // verifySuiSignature
```

`package:era_connect/sui.dart` is the chain module on its own.

## The intent message and its digest

Sui never signs transaction bytes directly. It signs an **intent message**: a
three-byte BCS intent prefix — scope, version, app id (`00 00 00` for
transaction data on Sui, scope `03` for a personal message) — followed by the
BCS transaction bytes. The digest is `BLAKE2b-256` of that whole thing.

Build the intent message with your Sui tooling and hand it over whole; the SDK
does not assemble it. `suiIntentDigest(intentMessage)` computes the digest if
you need it (it is exactly what the hash variant carries, and what the verifier
recomputes).

| Builder | UR type | `signData` on the wire | Use it when |
|---|---|---|---|
| `generateSignRequest` | `sui-sign-request` | the intent message, as a CBOR **byte string** | you have the full intent message — the device can show what it signs |
| `generateSignHashRequest` | `sui-sign-hash-request` | the 32-byte digest, as a **hex text string** | you only hold the digest |

The hash variant is a hex STRING, not bytes — that is the device's contract,
and the SDK encodes it for you. It is also blind signing: nothing on the device
can describe a bare digest to the user. Prefer the intent-message form whenever
you have the message.

## Fully hardened derivation

Sui paths are SLIP-10 Ed25519, so **every** component is hardened:
`m/44'/784'/0'/0'/0'`. The builder refuses a path with a soft component
(`invalid-props`, "Sui signing paths are fully hardened") rather than emitting a
request the device cannot answer. Ed25519 has no public child derivation, which
is why the device exports each signer as its own entry and `accounts.sui()`
returns a LIST — each element is a signer, not an account to derive under.

## 1. Build the request

`SuiSignRequestProps`:

| Prop | Type | Required | Notes |
|---|---|---|---|
| `requestId` | `Object?` — `Uint8List` (16) or UUID `String` | no | minted from the CSPRNG when absent |
| `intentMessage` | `Uint8List` | yes | the complete BCS intent message. Empty throws `invalid-props` |
| `path` | `String` | yes | fully hardened, e.g. `m/44'/784'/0'/0'/0'` |
| `xfp` | `Object` — u32 `int` or 8-hex `String` | yes | `signer.xfp` |
| `address` | `Object?` — `Uint8List` (32) or `0x` hex `String` | no | device display; any other length throws |
| `origin` | `String?` | no | overrides the config origin |

`SuiSignHashRequestProps` is the same list with `messageHash` (`Uint8List`,
exactly 32 bytes) in place of `intentMessage`.

On the wire: `{1: 37(<16 raw bytes>), 2: signData, 3: [304(keypath)],
4: [address bytes], 5: origin}` — the keypath and the address each travel
inside a one-element array.

```dart
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';

/// [intentMessage] comes from your Sui tooling: intent prefix + BCS tx bytes.
SignRequest<SuiSignatureResult> buildSuiTransaction(
  EraConnect era,
  EraAccounts accounts,
  Uint8List intentMessage,
) {
  final signer = accounts.sui().first; // each entry IS a signer
  return era.sui.generateSignRequest(SuiSignRequestProps(
    intentMessage: intentMessage,
    path: signer.path, // m/44'/784'/0'/0'/0'
    xfp: signer.xfp,
    address: signer.address, // 0x… — derived locally, see below
  ));
}

/// The digest-only variant, when the intent message is not at hand.
SignRequest<SuiSignatureResult> buildSuiHashRequest(
  EraConnect era,
  SuiAccountView signer,
  Uint8List intentMessage,
) {
  return era.sui.generateSignHashRequest(SuiSignHashRequestProps(
    messageHash: suiIntentDigest(intentMessage), // 32 bytes
    path: signer.path,
    xfp: signer.xfp,
  ));
}
```

Addresses derive locally from the linked key — `signer.address`, or
`suiAddressFromPublicKey(publicKey)` for a key you hold yourself. Both compute
`0x` + `BLAKE2b-256(0x00 ‖ publicKey)`, the `0x00` being the Ed25519 scheme
flag. No device round-trip is involved, so you can show addresses while the
wallet is in a drawer.

Display with `request.toAnimated()`: 180 payload bytes per fragment (~200 on
the wire) every 125 ms, 8 fps (`DeviceProfile.phoneToDevice`).

## 2. Parse the reply

`{1: <echoed id>, 2: <64-byte signature>, 3: <32-byte public key>}`:

| Field | Type | Notes |
|---|---|---|
| `requestId` | `Uint8List` | the echo, 16 bytes |
| `signature` | `Uint8List` | 64-byte Ed25519 |
| `publicKey` | `Uint8List` | 32 bytes — the key the device says it signed with |

```dart
SuiSignatureResult collect(
  SignRequest<SuiSignatureResult> request,
  Iterable<String> cameraFrames,
) {
  final scanner = request.scanner(); // pinned to sui-signature
  for (final frame in cameraFrames) {
    if (scanner.receivePart(frame) is ScanComplete) break;
  }
  return scanner.parse();
}
```

The device answers at 150-byte fragments every 400 ms — 2.5 fps
(`DeviceProfile.deviceToPhone`), slower than you send; budget the scan timeout
from its rate. Refusals:

| `code` | Meaning |
|---|---|
| `wrong-ur-type` | not a `sui-signature` frame |
| `malformed-cbor` | unreadable CBOR |
| `malformed-reply` | missing echo, a signature that is not 64 bytes, or no 32-byte public key at key 3 |
| `request-id-mismatch` | it answers another request |

## 3. Verify and broadcast

The reply names its own public key, which on its own proves nothing — a
signature always verifies against the key that made it. Pass
`expectedPublicKey` from the linked signer and the check becomes a binding to
your wallet.

```dart
import 'package:era_connect/verify.dart';

void guardSui(
  SuiAccountView signer,
  Uint8List intentMessage,
  SuiSignatureResult reply,
) {
  final verdict = verifySuiSignature(VerifySuiSignatureArgs(
    intentMessage: intentMessage,     // or messageHash: for the hash variant
    signature: reply.signature,
    publicKey: reply.publicKey,
    expectedPublicKey: signer.publicKey,
  ));
  if (!verdict.ok) throw StateError(verdict.reason!);
}
```

`VerifySuiSignatureArgs` takes exactly one of `intentMessage` or `messageHash`
(neither → `Failed('provide intentMessage or messageHash')`), plus the
`signature` and `publicKey` from the reply and the optional
`expectedPublicKey`. The helper hashes the intent message with `BLAKE2b-256`,
or takes the 32-byte hash as given, and verifies Ed25519. A key mismatch fails
before any curve arithmetic runs.

Verifying the hash variant proves the device signed **that digest** and nothing
about what the digest means — the digest is all you sent. That is the cost of
blind signing, and the reason to send the intent message when you can.

To submit, assemble Sui's serialised signature — the scheme flag `0x00`, the
64-byte signature, then the 32-byte public key, base64-encoded — and pass it
with the transaction bytes to your Sui client.
