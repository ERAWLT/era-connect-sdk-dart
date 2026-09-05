# Cosmos

Two builders, because the Cosmos ecosystem is two key systems wearing the same
SDK. Vanilla zones sign secp256k1 over `sha256` of a SignDoc with
`m/44'/118'` keys: `cosmos-sign-request` (4101) out, `cosmos-signature` (4102)
back. Ethermint zones sign over `keccak256` with Ethereum-style `m/44'/60'`
keys and travel as `evm-sign-request` (4101, the Ethermint shape) →
`evm-signature` (4102).

```dart
import 'package:era_connect/era_connect.dart'; // facade + linking
import 'package:era_connect/verify.dart';      // verifyCosmosSignature, CosmosDigest
```

`package:era_connect/cosmos.dart` is the chain module on its own.

## Sign-doc modes

`CosmosDataType` — the value you put in `dataType`, and what `signData` must
be:

| Value | Constant | Sign mode | `signData` |
|---|---|---|---|
| 1 | `CosmosDataType.amino` | `SIGN_MODE_LEGACY_AMINO_JSON` | the canonical Amino JSON, UTF-8 bytes |
| 2 | `CosmosDataType.direct` | `SIGN_MODE_DIRECT` | the protobuf-encoded `SignDoc` |
| 3 | `CosmosDataType.textual` | `SIGN_MODE_TEXTUAL` | the textual sign doc (rare) |
| 4 | `CosmosDataType.message` | ADR-036 arbitrary message | the ADR-036 sign doc |

`signData` is signed as-is: the bytes you send are the bytes hashed. Canonical
Amino JSON means sorted keys and no whitespace — produce it with your Cosmos
tooling and pass the same buffer to the verifier afterwards, never a
re-serialisation.

## Representative zones

| Zone | bech32 prefix | Derivation | Builder |
|---|---|---|---|
| Cosmos Hub | `cosmos` | `m/44'/118'/0'/0/0` | `generateSignRequest` |
| Osmosis | `osmo` | `m/44'/118'/0'/0/0` | `generateSignRequest` |
| Celestia | `celestia` | `m/44'/118'/0'/0/0` | `generateSignRequest` |
| Juno | `juno` | `m/44'/118'/0'/0/0` | `generateSignRequest` |
| Stargaze | `stars` | `m/44'/118'/0'/0/0` | `generateSignRequest` |
| Axelar | `axelar` | `m/44'/118'/0'/0/0` | `generateSignRequest` |
| dYdX | `dydx` | `m/44'/118'/0'/0/0` | `generateSignRequest` |
| Terra | `terra` | `m/44'/330'/0'/0/0` | `generateSignRequest` |
| Kava | `kava` | `m/44'/459'/0'/0/0` | `generateSignRequest` |
| Secret Network | `secret` | `m/44'/529'/0'/0/0` | `generateSignRequest` |
| Injective | `inj` | `m/44'/60'/0'/0/0` | `generateEthermintSignRequest` |
| Evmos | `evmos` | `m/44'/60'/0'/0/0` | `generateEthermintSignRequest` |
| Dymension | `dym` | `m/44'/60'/0'/0/0` | `generateEthermintSignRequest` |

The prefix is a property of the zone, not of the key: one key produces
`cosmos1…`, `osmo1…` and `juno1…` addresses from the same
`ripemd160(sha256(compressed pubkey))` payload. So the SDK derives the
address but never guesses the prefix — you name it per call:

```dart
final cosmos = accounts.cosmos()!;            // m/44'/118'/0'
cosmos.deriveAddress(0, prefix: 'cosmos');    // 'cosmos1…'
cosmos.deriveAddress(0, prefix: 'osmo');      // 'osmo1…' — the same key
```

`cosmosAddressFromPublicKey(publicKey33, prefix)` is exported from the root
library too, for a compressed key you derived some other way.

## 1. Build the request (vanilla zones)

`CosmosSignRequestProps`:

| Prop | Type | Required | Notes |
|---|---|---|---|
| `requestId` | `Object?` — `Uint8List` (16) or UUID `String` | no | minted from the CSPRNG when absent |
| `signData` | `Uint8List` | yes | the SignDoc bytes. Empty throws `invalid-props` |
| `dataType` | `int` | yes | a `CosmosDataType` value |
| `path` | `String` | yes | the FULL signing path, e.g. `m/44'/118'/0'/0/0` |
| `xfp` | `Object` — u32 `int` or 8-hex `String` | yes | from the linked account entry |
| `address` | `String?` | no | the bech32 signer address — device display |
| `origin` | `String?` | no | overrides the config origin |

On the wire: `{1: 37(<16 raw bytes>), 2: signData, 3: dataType,
4: [304(keypath)], 5: [address], 6: origin}` — keypath and address each inside
a one-element array.

`accounts.cosmos()` is the linked account, and it derives everything a
request needs — the signing path, the fingerprint, the child key and the
bech32 address under the zone's prefix:

```dart
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';

SignRequest<CosmosSignatureResult> buildCosmosTx(
  EraConnect era,
  EraAccounts accounts,
  Uint8List signDoc,
  String prefix, // 'cosmos', 'osmo', 'celestia', …
) {
  final cosmos = accounts.cosmos()!; // m/44'/118'/0'
  return era.cosmos.generateSignRequest(CosmosSignRequestProps(
    signData: signDoc,
    dataType: CosmosDataType.direct,
    path: cosmos.pathFor(0), // "m/44'/118'/0'/0/0"
    xfp: cosmos.xfp,
    address: cosmos.deriveAddress(0, prefix: prefix),
  ));
}
```

`cosmos()` and `AccountChain.cosmos` both mean `m/44'/118'` and nothing else.
An account exported under another coin type — Terra's 330, Kava's 459,
Secret's 529 — is not a family this SDK classifies: `cosmos()` returns null
and the entry's `chain` reads `AccountChain.unknown`. Take those out of
`accounts.keys` by path, derive the `0/index` child with your own BIP-32
library from the entry's `publicKey` + `chainCode`, and hand the result to
`cosmosAddressFromPublicKey`:

```dart
// Terra, m/44'/330' — the same key system under a coin type this SDK does
// not classify, so every step is explicit.

// 1. take the entry out of `keys` by path.
final entry = accounts.keys.firstWhere((k) => k.path == "m/44'/330'/0'");
final xfp = accounts.xfpFor(entry.path); // throws, never a silent zero

// 2. derive the 0/index child with YOUR BIP-32 library, from the account
//    key material the export carries. `bip32` here is whatever package you
//    already use; this SDK derives children only for families it classifies.
final child = bip32
    .fromPublicKey(entry.publicKey!, entry.chainCode!)
    .derive(0)
    .derive(index)
    .publicKey; // 33 compressed bytes

// 3. hand that to the address helper with the zone's own prefix.
final address = cosmosAddressFromPublicKey(child, 'terra');

final request = era.cosmos.generateSignRequest(CosmosSignRequestProps(
  signData: signDoc,
  dataType: CosmosDataType.direct,
  path: '${entry.path}/0/$index',
  xfp: xfp,
  address: address,
));
```

`cosmosAddressFromPublicKey` comes from the root library, and works for any
compressed secp256k1 key — the prefix is the only thing that varies between
zones.

`xfpFor` throws `account-not-found` rather than returning a zero fingerprint,
which would produce a request the device refuses with no explanation.

Display with `request.toAnimated()`: 180 payload bytes per fragment (~200 on
the wire) every 125 ms, 8 fps (`DeviceProfile.phoneToDevice`).

## 1b. Build the request (Ethermint family)

Injective, Evmos, Dymension and their relatives keep Cosmos sign docs but
Ethereum keys and an Ethereum digest. `generateEthermintSignRequest` takes
`EthermintSignRequestProps` — same fields as above, with three differences that
matter:

- `dataType` accepts **only** `amino` or `direct`. Anything else throws
  `invalid-props` ("Ethermint requests are Amino or Direct only").
- the value is **remapped on the wire**: amino (1) travels as 2, direct (2) as
  3, because this request rides the EVM sign-data numbering, not the Cosmos
  one. You still pass `CosmosDataType` values; the builder translates.
- `address` is the `0x…` string, and it travels as its **ASCII bytes** — a
  42-byte byte string, not text. Again, the builder does that for you.

The full wire shape is `{1: 37(<16 raw bytes>), 2: signData, 3: <remapped
dataType>, 4: 0, 5: 304(keypath), 6: <ASCII of the 0x address>, 7: origin}`.
Key 4 is `customChainId`, pinned to 0 — the chain is resolved from the SignDoc
itself. Note key 5: the keypath here is a bare value, NOT wrapped in an array
as it is on the vanilla request.

```dart
SignRequest<CosmosSignatureResult> buildInjectiveTx(
  EraConnect era,
  EraAccounts accounts,
  Uint8List aminoJson,
) {
  final evm = accounts.evm()!; // m/44'/60'/0' — the same account EVM signing uses
  return era.cosmos.generateEthermintSignRequest(EthermintSignRequestProps(
    signData: aminoJson,
    dataType: CosmosDataType.amino, // remapped to 2 on the wire
    path: evm.pathFor(0),           // m/44'/60'/0'/0/0
    xfp: evm.xfp,
    address: evm.deriveAddress(0),  // 0x… ; travels as ASCII
  ));
}
```

## 2. Parse the reply

Both reply types parse into `CosmosSignatureResult`:

| Field | Type | Notes |
|---|---|---|
| `requestId` | `Uint8List` | the echo, 16 bytes |
| `signature` | `Uint8List` | 64-byte compact secp256k1, `r ‖ s` — no recovery byte |
| `publicKey` | `Uint8List?` | 33-byte compressed, when the reply carries one |

`cosmos-signature` carries the public key at key 3. **`evm-signature` does
not** — `publicKey` comes back null on the Ethermint path, and you must supply
the key yourself when verifying (derive it from the linked account).

```dart
CosmosSignatureResult collect(
  SignRequest<CosmosSignatureResult> request,
  Iterable<String> cameraFrames,
) {
  final scanner = request.scanner(); // pinned to this request's reply type
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
| `wrong-ur-type` | not the reply type this request expects |
| `malformed-cbor` | unreadable CBOR |
| `malformed-reply` | missing echo, a signature that is not 64 bytes, or a public key that is not 33 |
| `request-id-mismatch` | it answers another request |

`era.cosmos.parseSignature(ur, ExpectedReply(requestId: id))` parses either
type standalone; the request's own `scanner()` is pinned to the one type that
can legitimately answer it.

## 3. Verify and broadcast

One helper, two digest families. Get this wrong and a good signature reads as
bad — or worse, a signature over an Ethermint digest gets accepted as a Cosmos
one.

```dart
import 'package:era_connect/verify.dart';

void guardCosmos(
  Uint8List signDoc,
  CosmosSignatureResult reply,
  Uint8List accountPublicKey, // 33 compressed bytes: cosmos.derivePublicKey(0)
  bool ethermint,
) {
  final verdict = verifyCosmosSignature(VerifyCosmosSignatureArgs(
    signData: signDoc,
    digest: ethermint ? CosmosDigest.keccak256 : CosmosDigest.sha256,
    signature: reply.signature,
    publicKey: reply.publicKey ?? accountPublicKey, // evm-signature carries none
    expectedPublicKey: accountPublicKey,
  ));
  if (!verdict.ok) throw StateError(verdict.reason!);
}
```

| Arg | Purpose |
|---|---|
| `signData` | the exact SignDoc bytes you sent |
| `digest` | `CosmosDigest.sha256` for vanilla zones, `CosmosDigest.keccak256` for Ethermint |
| `signature` | the 64-byte compact signature from the reply |
| `publicKey` | 33-byte compressed key the signature is checked against |
| `expectedPublicKey` | optional binding: the key you derived from the linked account |

Pass `expectedPublicKey`. Without it, a `cosmos-signature` reply that carries
its own key verifies against itself, which any key can do. With it, a reply
signed by a key that is not yours fails before the curve arithmetic runs.

Then wrap the 64 bytes as your zone expects — the `signatures` field of a
protobuf `TxRaw`, or the Amino `StdSignature`, base64 — and broadcast it. The
SDK performs no network I/O.
