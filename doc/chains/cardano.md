# Cardano

`cardano-sign-request` (2202) out, `cardano-signature` (2203) back. You send a
whole transaction; the device sends back a witness set. Nothing else of the
transaction changes, so the merge on your side is mechanical — and the
verification step can bind every returned key to the account you linked.

```dart
import 'package:era_connect/era_connect.dart'; // facade + linking + CardanoWitness
import 'package:era_connect/verify.dart';      // verifyCardanoSignature
```

`package:era_connect/cardano.dart` is the chain module on its own.

## What is sent and what is signed are not the same bytes

`signData` is the **full transaction CBOR array** —
`[body, witness_set, is_valid, auxiliary_data]` — exactly as your Cardano
tooling serialises it. The device takes the FIRST array element, the
transaction body, and signs `BLAKE2b-256` of its encoded extent.

That asymmetry is deliberate: the device needs the whole array to show the user
what the transaction does, but the signature covers the body alone, which is
what the ledger hashes as the transaction id. It also means the encoding
matters. Two CBOR encodings of the same logical body hash differently, so keep
the bytes you sent and verify against those, never against a re-serialisation.

One signature per **unique path** across `utxos` + `certKeys`. Ten inputs on
one address produce one witness, not ten.

## 1. Build the request

`CardanoSignRequestProps`:

| Prop | Type | Required | Notes |
|---|---|---|---|
| `requestId` | `Object?` — `Uint8List` (16) or UUID `String` | no | minted from the CSPRNG when absent |
| `signData` | `Uint8List` | yes | the full tx CBOR array. Empty throws `invalid-props` |
| `utxos` | `List<CardanoUtxoRef>` | yes | at least one, or `invalid-props` |
| `certKeys` | `List<CardanoCertKeyRef>?` | no | stake/withdrawal keys the tx additionally needs a witness from |
| `origin` | `String?` | no | overrides the config origin |

`CardanoUtxoRef` — one input the device must sign for:

| Field | Type | Required | Notes |
|---|---|---|---|
| `transactionHash` | `Uint8List` | yes | 32 bytes, the tx that created the UTXO. Any other length throws |
| `index` | `int` | yes | output index; non-negative, bounded at 2^53 - 1 (web builds cannot carry more) |
| `path` | `String` | yes | the FULL signing path, e.g. `m/1852'/1815'/0'/0/0` |
| `xfp` | `Object` — u32 `int` or 8-hex `String` | yes | see below |
| `amount` | `String?` | no | lovelace as a decimal string — device display |
| `address` | `String?` | no | the UTXO's bech32 address — device display |

`CardanoCertKeyRef` — `path`, `xfp`, and an optional 28-byte `keyHash` for
display and matching.

On the wire: `{1: 37(<16 raw bytes>), 2: signData, 3: [2201(utxo)…],
4: [2204(certKey)…], 5: origin}`. Unlike TON, the request id here is the plain
16 bytes inside tag 37.

### Where `xfp` comes from

The Cardano account entry in the device's export ships a **path-only origin**:
its `crypto-keypath` carries no source fingerprint of its own. `EraAccounts`
resolves that by falling back to the wrapper's master fingerprint, so
`accounts.cardano()!.xfp` is always the value your refs must carry. Do not
substitute a fingerprint from another account's entry — a keypath the device
cannot match is a request it cannot sign.

```dart
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';

/// [txCbor] is the full `[body, witnessSet, isValid, auxData]` array.
SignRequest<CardanoSignatureResult> buildCardanoSpend(
  EraConnect era,
  EraAccounts accounts,
  Uint8List txCbor,
  Uint8List inputTxHash,
) {
  final ada = accounts.cardano()!;
  return era.cardano.generateSignRequest(CardanoSignRequestProps(
    signData: txCbor,
    utxos: [
      CardanoUtxoRef(
        transactionHash: inputTxHash, // 32 bytes
        index: 0,
        path: ada.pathFor(0, 0),      // m/1852'/1815'/0'/0/0 — payment 0
        xfp: ada.xfp,
        amount: '2000000',
        address: 'addr1q…',
      ),
    ],
    certKeys: [
      // the stake key, for a delegation certificate or a withdrawal
      CardanoCertKeyRef(path: ada.pathFor(2, 0), xfp: ada.xfp),
    ],
  ));
}
```

`CardanoAccountView.pathFor(role, index)` builds the paths: role 0 payment,
1 change, 2 stake. `deriveKey(role, index)` gives you the same child's 32-byte
verification key locally, no device round-trip — CIP-1852 account keys support
soft (public) derivation.

Display with `request.toAnimated()` and your QR widget: 180 payload bytes per
fragment (~200 on the wire) every 125 ms, 8 fps
(`DeviceProfile.phoneToDevice`). A transaction with many inputs is a long
animation; the fountain repeats until the device has every fragment.

## 2. Parse the reply

`{1: <echoed id>, 2: <witness set CBOR>}`. `CardanoSignatureResult` gives you
both the raw bytes and the parsed pairs:

| Field | Type | Notes |
|---|---|---|
| `requestId` | `Uint8List` | the echo, 16 bytes |
| `witnessSet` | `Uint8List` | the witness-set CBOR **verbatim** — `{0: #6.258([[vkey, sig]…])}` |
| `witnesses` | `List<CardanoWitness>` | each a 32-byte `vkey` and a 64-byte `signature` |

The set tag (258) is optional; a bare array parses too.

```dart
CardanoSignatureResult collect(
  SignRequest<CardanoSignatureResult> request,
  Iterable<String> cameraFrames,
) {
  final scanner = request.scanner(); // pinned to cardano-signature
  for (final frame in cameraFrames) {
    if (scanner.receivePart(frame) is ScanComplete) break;
  }
  return scanner.parse();
}
```

The device answers at 150-byte fragments every 400 ms — 2.5 fps
(`DeviceProfile.deviceToPhone`), slower than you send. Refusals:

| `code` | Meaning |
|---|---|
| `wrong-ur-type` | not a `cardano-signature` frame |
| `malformed-cbor` | unreadable CBOR |
| `malformed-reply` | no id echo, no witness set, no vkey witnesses at key 0, or a pair that is not `[32-byte key, 64-byte signature]` |
| `request-id-mismatch` | it answers another request |

`parseWitnessSet(bytes)` is exported if you need the pairs out of a witness set
you obtained some other way.

## 3. Verify and broadcast

`verifyCardanoSignature` recomputes `BLAKE2b-256` of the encoded first element
of your `signData` and checks every returned pair against it. Give it
`account` + `signerPaths` as well and it does the part that actually matters:
it binds each returned vkey to YOUR wallet.

```dart
import 'package:era_connect/verify.dart';

void guardCardano(
  EraAccounts accounts,
  Uint8List txCbor,
  CardanoSignatureResult reply,
  List<String> signerPaths, // the unique paths your request carried
) {
  final ada = accounts.cardano()!;
  final verdict = verifyCardanoSignature(VerifyCardanoSignatureArgs(
    signData: txCbor,
    witnessSet: reply.witnessSet, // or witnesses: reply.witnesses
    account: VerifyCardanoAccount(
      publicKey: ada.publicKey,
      chainCode: ada.chainCode,
      accountPath: ada.accountPath,
    ),
    signerPaths: signerPaths,
  ));
  if (!verdict.ok) throw StateError(verdict.reason!);
}
```

With the account and the paths supplied, the check is two-way:

- each signer path must extend the account path with **exactly two soft
  components** — anything else is refused outright, because a hardened tail
  cannot be derived from a public key and so could not be checked at all;
- each path is soft-derived from the linked account key + chain code, and the
  resulting vkey must appear in the witness set (`no witness for the requested
  signer path …` otherwise);
- and every witness must map back to a requested path, so a reply carrying an
  extra key is refused with `the witness set carries a key your request did not
  ask for`.

Omit `account`/`signerPaths` and the helper only proves the reply is internally
consistent — every pair verifies against its own vkey. Any key can produce that,
including one that is not yours. Pass them.

Then merge `witnessSet` into the transaction's `witness_set` field (element 1
of the array) with your Cardano tooling and submit. The witness bytes are
returned verbatim precisely so this merge does not have to re-encode anything.
