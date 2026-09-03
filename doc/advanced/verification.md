# Verification

> "Did the device sign exactly what I sent?"

A signature that arrives through a camera is unauthenticated input. It came
from a screen you pointed a lens at, and the SDK has no channel back to the
device to ask whether that screen was the right one. Two independent bindings
answer the two halves of the question, and they answer different halves:

| Binding | Answers | Enforced by |
|---|---|---|
| **Request-id echo** | *Which* request was answered | The SDK, on `SignRequest.scanner().parse()` |
| **Verify helper** | *What* was signed | You, by calling it — `package:era_connect/verify.dart` |

Neither substitutes for the other. The echo proves the reply belongs to the
request you built a moment ago and not to a cancelled flow, a photograph, or
another phone in the room — but it says nothing about the bytes underneath.
The verify helper recomputes the digest the device signs and checks the
signature against the key you expect — but on its own it cannot tell a fresh
reply from a stale one that happens to carry a valid signature over an old
payload.

**Some chains have only the second.** For those the helper is not a hardening
step you may skip; it is the entire binding.

```dart
import 'package:era_connect/verify.dart';
```

## Where the request id lives, per chain

The shape is dictated by the wire, not by taste. The SDK emits what the device
parses and compares the echo as **bytes** after stripping CBOR tags, because a
device may answer a bare byte string with a tagged one.

| Chain | Request id on the wire | Reply binding |
|---|---|---|
| EVM | bare byte string (key 1) | echo enforced |
| Solana | bare byte string (key 1) | echo enforced |
| Bitcoin — message | byte string wrapped in **tag 37** | echo enforced |
| Cardano | byte string wrapped in **tag 37** | echo enforced |
| Cosmos and Ethermint | byte string wrapped in **tag 37** | echo enforced |
| Sui | byte string wrapped in **tag 37** | echo enforced |
| TON | **tag 37** over the **ASCII bytes of the hyphenated UUID string** — not 16 raw bytes | echo enforced |
| Tron | none in CBOR — a `signId` string inside the protobuf | `signId` compared |
| Bitcoin Cash | none in CBOR — a `signId` string inside the protobuf | `signId` compared |
| Bitcoin — PSBT | **none, in either direction** | content only |
| XRP | **none, in either direction** | content only |

The id is minted when the `SignRequest` is constructed, so the object that
renders the QR is the object that validates the echo. A reply carrying a
different id raises `EraSdkError('request-id-mismatch', …)` from `parse()`.

On Tron and Bitcoin Cash the `signId` echo is the only anti-replay binding
there is, and the reply is a complete, broadcastable transaction — so the
content check is required there too, for a different reason: the echo proves
the reply answers this request, and nothing proves the transaction inside it
pays who you asked.

## The helpers

Everything exported from `package:era_connect/verify.dart`:

| Helper | Arguments | What it proves | Mandatory |
|---|---|---|---|
| `verifyEvmSignature` | `VerifyEvmSignatureArgs` | Recovers the signer from the keccak digest of `signData` and requires it to equal the request's address. `reEncodedSignData` additionally pins the payload you are about to broadcast to the one that was signed. | Strongly advised |
| `verifySignedPsbt` | `VerifySignedPsbtArgs` | The returned PSBT's unsigned transaction is byte-identical to the one sent — which pins inputs, order, outputs, amounts, version, locktime and therefore the txid. Refuses inputs that came back finalized without having been sent that way, and (by default) a partially signed reply. | **Yes** — no request id exists on this path |
| `verifyBtcMessageHeader` | `VerifyBtcMessageHeaderArgs` | The BIP-137 recovery header matches the address kind that was asked for. A wrong-range header yields a signature that looks well-formed and verifies nowhere. | Advised whenever you sign messages |
| `verifyBchSignedTx` | `VerifyBchSignedTxArgs` | Rebuilds the whole transaction from the reply: every outpoint, every output script and value, and every input signature against a recomputed BIP-143 `SIGHASH_FORKID` preimage. Optionally checks the reply's `txId` against the raw bytes. | **Yes** — the reply is broadcast verbatim |
| `verifySolanaSignature` | `VerifySolanaSignatureArgs` | Ed25519 verification of the reply against `signData` and the signer key. `broadcastMessageBytes` pins the message you are about to send — this matters most here, where a blockhash refresh between build and send silently makes two different objects. | Strongly advised |
| `verifyTronSignature` | `VerifyTronSignatureArgs` | Every signature recovers to the owner address, and the transaction moves what was approved: byte equality with the request's `raw_data` when possible, otherwise a field-level comparison of recipient, amount and contract plus the validity window against the reference block. | **Yes** — the reply is broadcast verbatim |
| `verifyTonSignature` | `VerifyTonSignatureArgs` | Recomputes the exact digest the device signs — the BoC **root cell's representation hash** for a transaction, or `sha256(0xFFFF ‖ "ton-connect" ‖ sha256(payload))` for a proof — and verifies it against the linked key. | Strongly advised |
| `verifyCardanoSignature` | `VerifyCardanoSignatureArgs` | BLAKE2b-256 of the encoded **first element** of the transaction CBOR array (the body), then every `[vkey, signature]` pair against it. With `account` and `signerPaths` it also requires each vkey to be the soft-derived child of *your* account at the request's own path — and refuses a witness set carrying a key you did not ask for. | Strongly advised; pass `account` + `signerPaths` |
| `verifySuiSignature` | `VerifySuiSignatureArgs` | BLAKE2b-256 of the intent message (or the 32-byte `messageHash` variant) and Ed25519 verification. `expectedPublicKey` binds the reply to the linked account. | Strongly advised |
| `verifyCosmosSignature` | `VerifyCosmosSignatureArgs` | secp256k1 verification of the 64-byte compact signature over the SignDoc bytes. Pick the digest with `CosmosDigest.sha256` (vanilla zones) or `CosmosDigest.keccak256` (Ethermint: Injective, Evmos, Dymension). `expectedPublicKey` binds it to the linked key. | Strongly advised |
| `verifyXrpSignature` | `VerifyXrpSignatureArgs` | Splits the returned binary into canonical fields, removes `TxnSignature`, hashes the remainder behind the `STX\0` prefix with SHA-512-half, and verifies the DER signature against `SigningPubKey` — which must also equal the key your request carried. | **Yes** — no request id exists on this path |

Two kinds of "mandatory" appear in that column, and the difference matters.
**Bitcoin PSBT and XRP** carry no request id at all, so the helper is the *only*
thing binding the reply to the request — skip it and there is no binding left.
**Bitcoin Cash and Tron** do have an id, and it is checked for you, but their
replies are complete transactions that get broadcast verbatim: the echo proves
the reply answers this request, and only the helper proves the transaction
inside it pays who you asked.

Supporting types, exported alongside them:

| Symbol | Use |
|---|---|
| `VerifyResult`, `Verified`, `Unverifiable`, `Failed` | The sealed result type and its three cases |
| `verified`, `failed(reason)`, `unverifiable(reason)` | The constructors, for your own checks |
| `parsePsbt`, `ParsedPsbt`, `PsbtKeyValue`, `PsbtInputType` | A hardened PSBT v0 reader: the global unsigned transaction verbatim, plus per-input key/value maps |
| `decodeBchRawTx`, `DecodedBchTx`, `DecodedBchInput`, `DecodedBchOutput`, `computeBchSighash` | The BCH transaction reader and sighash preimage, if you need to inspect a reply yourself |
| `bocRootHash` | The TON representation hash of a BoC's root cell |
| `VerifyBchInput`, `VerifyBchOutput`, `VerifyCardanoAccount`, `CosmosDigest` | Argument-side types |

Helpers **return a verdict rather than throwing** on anything the device sent:
a mismatch, a signature by the wrong key, a reply too malformed to read — all
of it comes back as `Failed`, with a reason. (Malformed *arguments* are your
own bug and still throw: a `signature` that is not bytes, an `address` that is
not hex.)

## `VerifyResult`

```dart
sealed class VerifyResult {
  bool get ok;         // acceptable to proceed
  bool get checked;    // something was actually verified
  String? get reason;  // null only when verified
}
```

Three cases, and the difference between them is the whole point:

| Case | `ok` | `checked` | Meaning |
|---|---|---|---|
| `Verified` | `true` | `true` | The digest was recomputed and the signature verified against the expected key. |
| `Unverifiable` | `true` | **`false`** | Nothing about this input is checkable client-side. The check did not fail — it did not happen. |
| `Failed` | `false` | `false` | The check ran and the reply did not survive it. Do not broadcast. |

`Unverifiable` is `ok` because refusing it would refuse legitimate work. There
are exactly three ways to get one:

- **EIP-712 typed data** (`EvmDataType.typedData`) — the digest is the hash of
  the *structure*, computed only on the device. The UR-type pin and the
  request-id echo are the whole binding, and what the user read on the device
  screen is the real defence.
- **A Bitcoin address kind with no BIP-137 header range** to compare against.
- **An XRP transaction carrying a field type the walker does not cover** —
  reported as unverifiable rather than as a false verdict.

**The hole:** a caller that branches on `ok` alone treats "nothing was checked"
as "everything is fine". On EVM that is defensible, because a request id still
binds the reply. On **XRP it is not** — there is no request id, so an
`Unverifiable` there means *nothing whatsoever* binds those bytes to your
request. Branch on the type, or on `checked`, wherever the chain has no id:

```dart
switch (check) {
  case Verified():
    broadcast();
  case Unverifiable(:final reason):
    // On XRP and Bitcoin PSBT: refuse. Elsewhere: surface it, decide with
    // the user, and never log it as a pass.
    showInconclusive(reason);
  case Failed(:final reason):
    throw StateError(reason);
}
```

## In the flow

Verification sits between `parse()` and your broadcaster, and it uses the
request you still hold in memory — not anything the reply told you.

```dart
import 'package:era_connect/era_connect.dart';
import 'package:era_connect/verify.dart';

final era = EraConnect(const EraConnectConfig(origin: 'MyWallet'));
final evm = accounts.evm()!;          // from linking, see the getting-started guide

final request = era.evm.generateSignRequest(EvmSignRequestProps(
  signData: unsignedRlp,
  dataType: EvmDataType.transaction,
  path: evm.pathFor(0),
  xfp: evm.xfp,
  chainId: 1,
  address: evm.deriveAddress(0),
));

// … display request.toAnimated(), then feed camera frames …
final scanner = request.scanner();
final reply = scanner.parse();          // request-id echo enforced here

final check = verifyEvmSignature(VerifyEvmSignatureArgs(
  signData: unsignedRlp,                // what you asked for
  dataType: EvmDataType.transaction,
  signature: reply.signature,
  address: evm.deriveAddress(0),
  reEncodedSignData: rlpAboutToBroadcast, // what you are about to send
));
if (!check.ok) throw StateError(check.reason!);
```

The `reEncodedSignData` argument closes a gap the recovery alone leaves open.
Recovering against `signData` proves the device signed something you asked
for; re-deriving the payload from the transaction object your broadcaster is
holding proves it is *still* that transaction. Payloads legitimately change
between build and send — a refreshed nonce, a new blockhash — and without this
the two can drift apart unnoticed. `verifySolanaSignature` has the same
argument under the name `broadcastMessageBytes`.

## The two paths where it is not optional

**Bitcoin PSBT.** The `crypto-psbt` request is a bare CBOR byte string: no map,
no request id, no origin. A signed PSBT from an earlier session is a valid
`crypto-psbt` reply forever, and the scanner cannot tell it from a fresh one.

```dart
final request = era.btc.generatePsbtSignRequest(
  BtcPsbtSignRequestProps(psbt: unsignedPsbt),
);
final scanner = request.scanner();
// … display request.toAnimated(), feed camera frames into scanner …
final signed = scanner.parse();                    // BtcPsbtResult

final check = verifySignedPsbt(VerifySignedPsbtArgs(
  sentPsbt: unsignedPsbt,
  signedPsbt: signed.psbt,
));
if (!check.ok) throw StateError(check.reason!);
// signed.psbt is signed, NOT finalized — finalize with your own stack.
```

Set `requireEveryInputSigned: false` only for hand-backs where a PSBT
legitimately carries inputs you cannot sign; on a plain send, leave the default
on, so a partial reply is refused here with a reason instead of failing later
inside a finaliser.

**XRP.** The request is an untyped `ur:bytes` carrying the transaction JSON;
the reply is an untyped `ur:bytes` carrying the signed binary. Nothing in
either frame names the other.

```dart
final signed = scanner.parse();                    // XrpSignatureResult

final check = verifyXrpSignature(VerifyXrpSignatureArgs(
  signedTx: signed.signedTx,
  expectedSigningPubKey: signingPubKeyHex,         // from your request JSON
));
if (!check.checked) throw StateError(check.reason ?? 'unverified');
```

Note the `checked` test rather than `ok`: on this chain an inconclusive result
is indistinguishable from no check at all.

The device always signs XRP with `m/44'/144'/0'/0/0`. A transaction whose
`SigningPubKey` is not that key's public key is invalid — the network will
reject it, and so will this helper. Put that key's compressed hex in the
request JSON and compare against the same value here.

## What verification does not cover

- **The user's intent.** The device shows an address and an amount; the person
  holding it approves or refuses. Everything here proves the bytes survived the
  round trip unchanged, not that they were the right bytes to begin with.
- **A hostile camera.** If the only well-formed UR in view is an attacker's, it
  assembles. The type pin, the request-id echo and these helpers are what make
  that assembled reply useless.
- **EIP-712 semantics.** `Unverifiable`, by construction. What the device
  rendered is the record.
