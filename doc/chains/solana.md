# Solana

`package:era_connect/solana.dart`, or `era.solana` on the `EraConnect` facade.

| | |
|---|---|
| Request | `sol-sign-request` (1101) |
| Reply | `sol-signature` (1102) |
| Request id | bare CBOR byte string; the device echoes it (tag-37 wrapped) and the SDK compares the **bytes** |
| Signs | compiled transaction messages (legacy and versioned) and off-chain messages |

## 1. Build the request

`SolanaChain.generateSignRequest(SolSignRequestProps)`.

| Prop | Type | Required | What it is |
|---|---|---|---|
| `signData` | `Uint8List` | yes | the compiled transaction **message** bytes, or raw message bytes |
| `path` | `String` | yes | the 3-level hardened account path, `m/44'/501'/idx'` |
| `xfp` | `int` (u32) or `String` (8 hex) | yes | the account's source fingerprint — `SolanaAccountView.xfp` |
| `publicKey` | `Uint8List?` | one of the two | the 32-byte Ed25519 signer key |
| `address` | `String?` | one of the two | the same key in base58 form |
| `signType` | `int?` | no | a `SolSignType` value; defaults to `transaction` |
| `requestId` | `Uint8List` (16 bytes) or `String` (UUID) | no | minted from a CSPRNG when absent |
| `origin` | `String?` | no | overrides the SDK-level origin label for this request |

`publicKey` or `address` — one is required. An address that is not base58, or
that does not decode to 32 bytes, is `invalid-props`.

### The bytes are signed verbatim, which is why versioned transactions work

The device signs `signData` as it arrives. It does not parse the message, does
not re-serialize it, and does not append anything. A v0 message with address
lookup tables goes through the same path as a legacy one, because from the
signer's point of view there is no difference — this is the whole reason
versioned transactions need no special handling here.

The corollary: whatever you send is exactly what gets signed, so build the
message with your own Solana tooling and hand over its serialized form. Do not
send a fully serialized *transaction* (with its signature array) where a
compiled message is expected.

### signType

| Constant | Wire | Meaning |
|---|---|---|
| `SolSignType.transaction` | key 7 **omitted** | the device's default; `signData` is a compiled message |
| `SolSignType.message` | key 7 = 2 | off-chain message |

Off-chain messages are signed verbatim too: **no prefix, no domain header is
applied by the device**. If your protocol expects the Solana off-chain message
format, construct those bytes yourself and send the result — otherwise you get a
signature over the raw bytes you passed, which most verifiers will not accept.

### The derivation-path rule

`path` must be the 3-level hardened account path `m/44'/501'/idx'`, and the SDK
refuses anything else with `invalid-props`. Ed25519 has no public child
derivation, so there is no `…/0/0` to reach from an account key: the device
pre-derives hardened accounts and **each exported entry is itself a signer**.
`SolanaAccountView.path` gives you the exact string, `publicKey` the key at it,
and `address` its base58 form (which on Solana *is* the public key).

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

/// Sign a compiled Solana message and return the 64-byte signature.
Future<Uint8List> signSolanaMessage({
  required EraConnect era,
  required SolanaAccountView signer,
  required Uint8List compiledMessage, // from your Solana tooling
  required void Function(String qrFrame) render,
  required Stream<String> cameraFrames,
}) async {
  final request = era.solana.generateSignRequest(SolSignRequestProps(
    signData: compiledMessage,
    path: signer.path, // m/44'/501'/idx'
    xfp: signer.xfp,
    publicKey: signer.publicKey,
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

  final reply = scanner.parse(); // SolSignatureResult

  final check = verifySolanaSignature(VerifySolanaSignatureArgs(
    signData: compiledMessage,
    signature: reply.signature,
    publicKey: signer.publicKey,
    // The message you are about to send — catches a blockhash refresh that
    // happened while the device was being tapped.
    broadcastMessageBytes: compiledMessage,
  ));
  if (!check.ok) throw StateError(check.reason!);

  return reply.signature;
}
```

An off-chain message is the same call with one more prop:

```dart
final request = era.solana.generateSignRequest(SolSignRequestProps(
  signData: messageBytes,
  signType: SolSignType.message,
  path: signer.path,
  xfp: signer.xfp,
  publicKey: signer.publicKey,
));
```

## 2. Parse the reply

`SolSignatureResult`:

| Field | Type | Notes |
|---|---|---|
| `requestId` | `Uint8List` | the echoed id, already compared for you |
| `signature` | `Uint8List` | the 64-byte Ed25519 signature |

Checked for you: the UR type (frames of any other type never reach the fountain
decoder), the CBOR map, the request-id echo byte for byte
(`request-id-mismatch`), and that the signature is exactly 64 bytes. Two wire
encodings are accepted — CBOR bytes, and a hex text string that older firmware
sends — so your code sees one shape either way.

Standalone: `era.solana.parseSignature(ur, ExpectedReply(requestId: id))`;
without `expect.requestId` the echo is read but not checked, which is why the
request's own scanner is the preferred path.

## 3. Verify and broadcast

```dart
verifySolanaSignature(VerifySolanaSignatureArgs(
  signData: compiledMessage,
  signature: reply.signature,
  publicKey: signer.publicKey,
  broadcastMessageBytes: messageAboutToBeSent, // optional
));
```

| Argument | Type | Required | Purpose |
|---|---|---|---|
| `signData` | `Uint8List` | yes | the exact bytes the request carried |
| `signature` | `Uint8List` | yes | the 64-byte signature from the reply |
| `publicKey` | `Uint8List` | yes | the 32-byte signer key the request was built for |
| `broadcastMessageBytes` | `Uint8List?` | no | the message bytes you are **about to broadcast** |

What it proves: the Ed25519 signature verifies over `signData` under
`publicKey`. A pass means this signature was produced by that key, over exactly
those bytes — not by a substituted key, and not over a substituted message.

`broadcastMessageBytes` matters more here than on most chains. A Solana message
embeds a recent blockhash, and refreshing it between building the request and
sending the transaction produces two different objects — one signed, one about
to be sent. The helper compares them byte for byte first and fails closed with
"the message to broadcast is not the one the device signed" rather than letting
you submit a transaction whose signature cannot match.

`VerifyResult` is a value, never an exception: `Verified`, `Unverifiable` or
`Failed`, with `ok`, `checked` and `reason`.

### Broadcast

Assemble the transaction with your own Solana tooling: place the 64-byte
signature in the signature array at the signer's index in the message's account
keys, serialize, and submit through your RPC client. The SDK deliberately stops
at the signature — it never builds or sends a transaction.
