# Bitcoin Cash

`package:era_connect/bch.dart`, or `era.bch` on the `EraConnect` facade.

| | |
|---|---|
| Request | `keystone-sign-request` (6101) — CBOR `{1: gzip(protobuf), 2: origin}` |
| Reply | `keystone-sign-result` (6102) — the same envelope, carrying a complete transaction |
| Request id | no CBOR id; a `signId` UUID string inside the protobuf does that job |
| Signs | P2PKH inputs, paying P2PKH or P2SH CashAddr outputs |

## Why this chain is not a PSBT

Bitcoin Cash's consensus sighash is BIP-143 with `SIGHASH_FORKID` (`0x41`) —
the replay protection that separated the chains. The device's PSBT signer does
not apply FORKID, so a BCH transaction signed down the `crypto-psbt` path
produces signatures the BCH network rejects. A dedicated FORKID signer sits
behind the structured envelope instead.

The consequence for you: this is the **one chain where the SDK is more than a
transport**. Everywhere else you build the transaction and the SDK ships your
bytes. Here you describe inputs and outputs, and the container is built — by
the SDK for the request, and by the device for the signed result. Nothing in
this flow is a serialized transaction you authored, which is exactly why the
verification step rebuilds the whole binding from the reply.

## 1. Build the request

`BchChain.generateSignRequest(BchSignRequestProps)`.

| Prop | Type | Required | What it is |
|---|---|---|---|
| `inputs` | `List<BchTxInput>` | yes | the UTXOs being spent; at least one |
| `outputs` | `List<BchTxOutput>` | yes | every output, change included; at least one |
| `fee` | `int` or `BigInt` | yes | fee in satoshis, positive; must equal `sum(inputs) - sum(outputs)` exactly |
| `xfp` | `int` (u32) or `String` (8 hex) | yes | the account's source fingerprint — `BchAccountView.xfp` |
| `dustThreshold` | `int?` | no | shown on the device; defaults to 546, must fit a non-negative int32 |
| `memo` | `String?` | no | shown on the device |
| `timestamp` | `int?` | no | Unix milliseconds for the device log; `0` (the default) omits it |
| `requestId` | `Uint8List` (16 bytes) or `String` (UUID) | no | minted from a CSPRNG when absent |
| `origin` | `String?` | no | overrides the SDK-level origin label for this request |

`BchTxInput` — P2PKH only, that is what the signer handles:

| Field | Type | Required | What it is |
|---|---|---|---|
| `txid` | `String` | yes | display-order (big-endian) txid of the UTXO, 64 hex chars |
| `index` | `int` | yes | output index of the UTXO |
| `value` | `int` or `BigInt` | yes | UTXO value in satoshis — part of the BIP-143 preimage, so it must be exact |
| `publicKey` | `Uint8List` or hex `String` | yes | the 33-byte compressed key that owns the UTXO |
| `path` | `String` | yes | full derivation path of that key, e.g. `m/44'/145'/0'/0/0` |

`BchTxOutput`:

| Field | Type | Required | What it is |
|---|---|---|---|
| `address` | `String` | yes | CashAddr (P2PKH or P2SH), with or without the `bitcoincash:` prefix |
| `value` | `int` or `BigInt` | yes | output value in satoshis |
| `isChange` | `bool?` | no | marks the output as change **on the device screen only** |
| `changeAddressPath` | `String?` | no | shown alongside the change output; `address` is still what gets paid |

### The fee must equal inputs minus outputs

`fee` is what the device **displays**. The fee the network actually takes is
`sum(inputs) - sum(outputs)`, decided by the container. If the two disagree, the
confirmation screen states a number that is not what will happen — so the SDK
refuses the request with `invalid-props` and a message naming both figures,
rather than letting the user approve a lie. Compute your change output and your
fee from the same arithmetic and this never fires.

### Amounts

Satoshi values are `int` or `BigInt`, must be positive, and must not exceed
21 000 000 coins. An `int` past 2^53 - 1 is refused as a non-integer amount:
web builds cap integers at 2^53, and an amount that cannot round-trip exactly
must not reach a signing request.

### CashAddr handling

The SDK **decodes and re-encodes** every output address; the caller's spelling
never reaches the wire. That is a safety property, not tidiness:

- The decoder takes every spec-legal spelling — bare, prefixed, all-uppercase
  (the QR alphanumeric form) — and refuses mixed case. It is ASCII-guarded
  before any case folding, so a Unicode look-alike cannot fold into a charset
  character.
- The device's own parser reads only the lowercase form: it prepends a
  lowercase prefix before decoding, which turns an uppercase body into a
  mixed-case string it then rejects — **and that rejection fails open into a
  zero public-key hash**, i.e. a signed burn output. Re-encoding canonically is
  what keeps an all-uppercase address from becoming a burn.
- Only 20-byte P2PKH and P2SH payloads are accepted; the version byte, the hash
  length and the 40-bit BCH checksum are all verified.

The prefix is preserved in kind: if your string carried `bitcoincash:`, so does
the encoded form. The codec is exported for your own use —
`decodeCashAddr`, `encodeCashAddr`, `CashAddrType`, `CashAddrPayload`,
`cashaddrPrefix`.

### Fixed signer parameters

The device builds the container with these pinned; the verifier refuses a reply
that deviates:

| Parameter | Value |
|---|---|
| Transaction version | 1 |
| Locktime | 0 |
| Input sequence | `0xfffffffd` |
| Sighash type | `SIGHASH_ALL \| SIGHASH_FORKID` (`0x41`) |
| Input script | `push(signature ‖ 0x41) push(compressed pubkey)` |

### Display

`request.toAnimated()` fragments at 180 payload bytes; render `nextFrame()` at
125 ms (8 fps). The device answers with 150-byte fragments at 400 ms
(2.5 fps) — receiving is slower than sending, so budget scan timeouts on the
reply leg. Both numbers live in `DeviceProfile`.

```dart
import 'dart:async';

import 'package:era_connect/era_connect.dart';
import 'package:era_connect/verify.dart';

/// Spend one UTXO to a recipient plus change, then verify the signed
/// transaction against the request before it is broadcast.
Future<String> signBchSpend({
  required EraConnect era,
  required BchAccountView account,
  required String utxoTxid,
  required int utxoIndex,
  required int utxoValue,
  required String recipient, // CashAddr
  required int amount,
  required int fee,
  required void Function(String qrFrame) render,
  required Stream<String> cameraFrames,
}) async {
  final inputs = [
    BchTxInput(
      txid: utxoTxid,
      index: utxoIndex,
      value: utxoValue,
      publicKey: account.derivePublicKey(0),
      path: account.receivePath(0),
    ),
  ];
  final outputs = [
    BchTxOutput(address: recipient, value: amount),
    BchTxOutput(
      address: account.deriveAddress(0, change: true),
      value: utxoValue - amount - fee, // inputs - outputs must equal the fee
      isChange: true,
      changeAddressPath: account.changePath(0),
    ),
  ];

  final request = era.bch.generateSignRequest(BchSignRequestProps(
    inputs: inputs,
    outputs: outputs,
    fee: fee,
    xfp: account.xfp,
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

  final reply = scanner.parse(); // BchSignatureResult

  final check = verifyBchSignedTx(VerifyBchSignedTxArgs(
    rawTx: reply.rawTx,
    inputs: [
      for (final i in inputs)
        VerifyBchInput(
          txid: i.txid,
          index: i.index,
          value: i.value,
          publicKey: i.publicKey,
        ),
    ],
    outputs: [
      for (final o in outputs) VerifyBchOutput(address: o.address, value: o.value),
    ],
    txId: reply.txId,
  ));
  if (!check.ok) throw StateError(check.reason!);

  return reply.rawTx; // broadcast as-is
}
```

## 2. Parse the reply

`BchSignatureResult`:

| Field | Type | Notes |
|---|---|---|
| `requestId` | `Uint8List` | the id the reply's `signId` resolved to |
| `txId` | `String` | display-order txid, as computed by the device |
| `rawTx` | `String` | hex of the **complete, signed** transaction — broadcast as-is |

Checked for you: the UR type, the CBOR map, the compressed payload against an
8 KiB ceiling and the inflated protobuf against 64 KiB (`limit-exceeded` —
a few hundred scanned bytes must not be able to ask for an arbitrary
allocation), that `rawTx` is present and is even-length hex, and — when the
request's own scanner is used — that the protobuf's `signId` echoes the request
id (`request-id-mismatch`).

That `signId` echo is the only anti-replay binding on this envelope, and it is
only half the story: it proves *which* request was answered, not that the
transaction inside pays what you asked. The verifier below is what proves the
second half, and on this chain it is not optional — the reply is a finished
transaction that will be broadcast verbatim.

Standalone parsing (`era.bch.parseSignature(ur, ExpectedReply(requestId: id))`)
performs the echo check only when you pass the id.

## 3. Verify and broadcast

```dart
final check = verifyBchSignedTx(VerifyBchSignedTxArgs(
  rawTx: reply.rawTx,
  // The same inputs and outputs the request named, restated for the checker.
  inputs: [
    for (final i in inputs)
      VerifyBchInput(
        txid: i.txid,
        index: i.index,
        value: i.value,
        publicKey: i.publicKey,
      ),
  ],
  outputs: [
    for (final o in outputs)
      VerifyBchOutput(address: o.address, value: o.value),
  ],
  txId: reply.txId,
));
```

| Argument | Type | Required | Purpose |
|---|---|---|---|
| `rawTx` | `String` | yes | the reply's signed transaction hex |
| `inputs` | `List<VerifyBchInput>` | yes | `txid`, `index`, `value`, `publicKey` — exactly as the request named them |
| `outputs` | `List<VerifyBchOutput>` | yes | `address`, `value` — exactly as the request named them |
| `txId` | `String?` | no | the reply's `txId`, checked against the hash of the bytes when given |

The helper decodes the transaction and rebuilds every binding the request had:

- The pinned signer parameters (version 1, locktime 0, sequence `0xfffffffd`).
- Input and output counts against the request.
- Each output's value, and its script derived from the requested CashAddr —
  so a substituted destination or a shaved amount fails.
- Each input's outpoint against the requested `txid` / `index`.
- Each input's `scriptSig` shape, and that the public key pushed is the one the
  request named — a different key cannot spend the UTXO you meant to spend.
- The sighash byte is `0x41`, and the BIP-143 FORKID sighash is **recomputed**
  from the request's own input values and ECDSA-verified against the pushed key.
- Optionally that `txId` is the double-SHA256 of `rawTx`, reversed.

Recomputing the sighash from the request's values is also what makes a value
lie visible: if `value` in the request did not match the real UTXO, the preimage
differs, the signature fails here — and would have been rejected by the network
for the same reason.

`decodeBchRawTx(rawTx)` and `computeBchSighash(...)` are exported if you want to
inspect the decoded transaction yourself.

### Broadcast

`rawTx` is a complete, network-ready transaction. Submit the hex through your
BCH node or indexer unchanged — there is nothing left to finalize.
