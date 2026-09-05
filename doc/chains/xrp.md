# XRP

The odd one out. XRP rides the untyped `ur:bytes` convention in **both**
directions: JSON transaction in, canonical signed binary out. No chain-specific
UR type, no request id anywhere — which is why `verifyXrpSignature` is not
optional on this chain. It is the only thing binding a reply to what you asked
for.

```dart
import 'package:era_connect/era_connect.dart'; // facade + linking
import 'package:era_connect/verify.dart';      // verifyXrpSignature
```

`package:era_connect/xrp.dart` is the chain module on its own.

## The device signs with `m/44'/144'/0'/0/0`. Always.

One key, no index, no choice. A transaction whose `SigningPubKey` is not that
key's 33-byte compressed public key is **invalid** — the device will not
produce a usable signature for it, and the ledger would reject the result
anyway, because on XRPL the signing key is part of the signed payload.

So `SigningPubKey` is not decoration you can leave to a library default: it is
the field that has to name the device's key, in hex, before you send the
request. Get the key once at link time and keep it.

```dart
import 'package:era_connect/era_connect.dart';

/// Ask the device for the XRP key explicitly, if your wallet export did not
/// carry it: display `call.toAnimated()`, scan the account export back.
HardwareCallRequest requestXrpKey(EraConnect era) {
  return era.generateKeyDerivationCall(KeyDerivationCallProps(
    schemas: [
      // secp256k1 + SLIP-10 are the defaults, which is what XRP wants.
      KeyDerivationSchema(path: "m/44'/144'/0'/0/0", chainType: 'XRP'),
    ],
  ));
}

/// The answer names the FULL signing path, so its entry is the leaf key, not
/// an account to derive children from — match on `path` and read the key.
String signingPubKeyOf(EraAccounts accounts) {
  final key = accounts.keys
      .firstWhere((k) => k.path == "m/44'/144'/0'/0/0");
  return bytesToHex(key.publicKey!); // 33-byte compressed secp256k1
}
```

An export that volunteers the **account** at `m/44'/144'/0'` instead is what
`accounts.xrp()` wraps: `signingPath` names the same `0/0` key and
`derivePublicKey(0)` produces it.

## 1. Build the request

`XrpSignRequestProps` has exactly one field:

| Prop | Type | Required | Notes |
|---|---|---|---|
| `transaction` | `Object` — `Map<String, dynamic>` or a JSON `String` | yes | the UNSIGNED transaction |

A map is JSON-encoded for you; a string is parsed to validate and then sent
verbatim, whitespace and key order included — the bytes on the wire are the
bytes you passed.

Before building, the SDK mirrors the device's own acceptance gate so a refusal
happens here, with a reason, instead of silently on the hardware:

| Requirement | Failure |
|---|---|
| valid JSON | `invalid-props`, "transaction is not valid JSON" |
| `TransactionType` is a string | `invalid-props`, "needs a TransactionType" |
| `Account` is a string starting with `r` (classic address; X-addresses are not accepted) | `invalid-props`, "needs a classic r… Account" |
| `SigningPubKey` is a non-empty string | `invalid-props`, naming `m/44'/144'/0'/0/0` |
| `Fee` and `Sequence` are present | `invalid-props`, "needs Fee and Sequence" |

```dart
SignRequest<XrpSignatureResult> buildXrpPayment(
  EraConnect era,
  String signingPubKeyHex,
) {
  final request = era.xrp.generateSignRequest(XrpSignRequestProps(
    transaction: {
      'TransactionType': 'Payment',
      'Account': 'rMYQaEBLwyvSmDoRnH2tsqGE2LK4S3Rdap',
      'Destination': 'rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf',
      'Amount': '1000', // drops
      'Fee': '12',
      'Sequence': 1,
      'SigningPubKey': signingPubKeyHex,
    },
  ));
  assert(request.requestId == null); // honestly absent on this wire
  return request;
}
```

The UR is `ur:bytes` whose CBOR payload is a byte string holding the UTF-8 JSON
text. `request.requestId` is `null`, and that is not an omission the SDK could
fix: the protocol carries no id in either direction on this chain.

Display with `request.toAnimated()`: 180 payload bytes per fragment (~200 on
the wire) every 125 ms, 8 fps (`DeviceProfile.phoneToDevice`).

## 2. Parse the reply

`ur:bytes` again, this time holding the canonical signed XRPL binary
transaction:

| Field | Type | Notes |
|---|---|---|
| `signedTx` | `Uint8List` | the signed binary — submit it verbatim as `tx_blob` hex |

```dart
XrpSignatureResult collect(
  SignRequest<XrpSignatureResult> request,
  Iterable<String> cameraFrames,
) {
  final scanner = request.scanner(); // pinned to ur:bytes
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
| `wrong-ur-type` | the frame is not `ur:bytes` (rejected by the scanner before assembly, too) |
| `malformed-cbor` | the payload is not readable CBOR |
| `malformed-reply` | the CBOR carries no signed-transaction bytes |

Note what is NOT in that table: nothing checks that this reply answers this
request. `ur:bytes` is the type every raw payload uses, and there is no id to
echo. A signed transaction from an earlier flow, re-presented to the camera,
parses perfectly.

## 3. Verify — mandatory here — and broadcast

`verifyXrpSignature` is the whole binding. Run it on every reply, always,
before the blob reaches a node.

```dart
import 'package:era_connect/verify.dart';

void guardXrp(XrpSignatureResult reply, String signingPubKeyHex) {
  final verdict = verifyXrpSignature(VerifyXrpSignatureArgs(
    signedTx: reply.signedTx,
    expectedSigningPubKey: signingPubKeyHex, // the key your request carried
  ));
  if (!verdict.ok) throw StateError(verdict.reason!);
  if (!verdict.checked) {
    // Unverifiable: no verdict was reached. Decide deliberately.
  }
}
```

What the verifier walks, in order:

1. splits the signed binary into its top-level canonical fields;
2. locates `SigningPubKey` (field header `0x73`) and `TxnSignature` (`0x74`) —
   either missing is a failure;
3. compares `SigningPubKey` against `expectedSigningPubKey`, so a transaction
   signed by some other key is refused even if its own signature is perfect;
4. rebuilds the signing payload — the `STX\0` prefix followed by every field
   except `TxnSignature`, in the original order — and hashes it with SHA-512,
   keeping the first half;
5. decodes the DER signature strictly (exact lengths, positive integers,
   minimal encoding) into compact form and verifies it against that digest over
   secp256k1.

Three outcomes, and the middle one is the one to read carefully:

| Result | `ok` | `checked` | Meaning |
|---|---|---|---|
| `Verified` | true | true | the digest, the key and the signature all agree |
| `Unverifiable` | true | **false** | the transaction carries a field type this walker does not decode; no verdict was reached |
| `Failed` | false | false | the walk failed, a required field is missing, the key is not yours, or the signature does not verify |

The walker decodes the field types Payment-class transactions use — UInt16,
UInt32, Hash256, Amount (native and issued), Blob, AccountID, and nested
STObject / STArray. An exotic field type returns `Unverifiable` rather than a
false verdict, because a payload it cannot split is a payload whose signing
digest it cannot rebuild — claiming "invalid" there would be a lie in the other
direction. Inner nesting is capped at 32 levels: a hostile reply nesting
thousands comes back `Failed`, not as a crashed isolate.

`Unverifiable` means *nothing was checked*. Do not treat it as a pass because
`ok` is true — that field distinguishes "acceptable" from "verified", and on a
chain with no request id, an unverified reply has nothing else holding it to
your request. Show it to the user, or refuse it.

Then submit `signedTx` as hex to `submit` on your XRPL node.
