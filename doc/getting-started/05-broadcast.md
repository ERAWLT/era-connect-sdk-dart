# 5. Verify, then broadcast

You have a signature. One check stands between it and the network.

## Why the echo is not enough

The request-id echo answers *which request was answered*. It does not answer
*what was signed*. Those are different questions, and only the second one keeps
money where you put it: a reply can carry a valid id and a signature over
something you never showed the user.

And the id itself is not uniform. Its shape is fixed per chain by the wire
format, not chosen by you:

| Request id on the wire | Chains |
|---|---|
| Tag-37 wrapped byte string | Bitcoin **messages**, Cardano, Cosmos (including Ethermint), Sui, TON |
| Bare byte string | EVM, Solana |
| No CBOR id — a `signId` string inside the protobuf does the job | Tron, Bitcoin Cash |
| **None at all, in either direction** | Bitcoin **PSBT**, XRP |

TON is the odd one even among the tagged chains: its id travels as the ASCII
bytes of the hyphenated UUID string, not as sixteen raw bytes. The SDK handles
that; you only need to know it when reading a trace.

The last row is the one that changes your code. On Bitcoin PSBT and XRP there
is nothing to echo, so **verifying the returned content is the only binding
that exists**. Skipping the check there re-opens replay of a stale signed
payload. It is not a hardening step; it is the anti-replay mechanism.

## The verify library

```dart
import 'package:era_connect/verify.dart';
```

That one import carries the helpers, their argument objects, and every type
those objects DECLARE — `EvmDataType` and `TonDataType` for the `dataType`
fields, `CardanoWitness` for `witnesses`, `TronLatestBlock` and `SignedTronTx`
for the Tron args — plus `EraSdkError`, which the two parsers it exposes
(`parsePsbt`, `bocRootHash`) throw. Nothing on a verification path needs a
second import; the request and reply objects around it come from the chain
module, as always.

Every helper returns a `VerifyResult` and never throws on a mismatch. It is
sealed, with three cases:

| Case | `ok` | `checked` | Meaning |
|---|---|---|---|
| `Verified` | `true` | `true` | Recomputed and matched — cryptographically, or byte for byte |
| `Unverifiable` | `true` | `false` | Nothing is verifiable client-side for this input. The UR-type pin and the request-id echo are the whole binding |
| `Failed` | `false` | `false` | The check ran and did not match. Do not broadcast |

```dart
final verdict = verifyEvmSignature(VerifyEvmSignatureArgs(
  signData: rlpEncodedTransaction,        // the exact bytes the request carried
  dataType: EvmDataType.transaction,
  signature: signature.signature,         // raw r || s || v from the reply
  address: evm.deriveAddress(0),          // the signer you built the request for
));

if (!verdict.ok) {
  throw StateError('refusing to broadcast: ${verdict.reason}');
}
```

`Unverifiable` is a real answer, not a failure. EIP-712 typed data is the
example: the digest is a hash of the *structure*, which only the device
computes, so there is nothing to recompute here. Treat `checked == false` as
"proceed on the binding you already have", and never present it to a user as
"verified".

### Verify what you are about to send, not only what you sent

Two helpers take a second payload for this, because between building and
sending, a payload can legitimately change in your own state — a blockhash
refresh, a re-encode:

```dart
verifyEvmSignature(VerifyEvmSignatureArgs(
  signData: signedBytes,
  dataType: EvmDataType.transaction,
  signature: signature.signature,
  address: signerAddress,
  reEncodedSignData: bytesAboutToBeBroadcast,   // must equal signData
));

verifySolanaSignature(VerifySolanaSignatureArgs(
  signData: compiledMessage,
  signature: signature.signature,
  publicKey: signer.publicKey,
  broadcastMessageBytes: messageAboutToBeBroadcast,
));
```

Recovering against `signData` proves the device signed something you asked for.
The second payload closes the other half: that it is the transaction still in
your hands.

### Bitcoin, where the check is the binding

```dart
final signed = scanner.parse();      // BtcPsbtResult

final verdict = verifySignedPsbt(VerifySignedPsbtArgs(
  sentPsbt: psbtWeSent,
  signedPsbt: signed.psbt,
));
if (!verdict.ok) throw StateError(verdict.reason!);

// Then finalize and broadcast with your Bitcoin stack — the device returns a
// signed, NOT finalized PSBT.
```

The comparison is byte-for-byte on the unsigned transaction, which pins the
input set and order, the outputs, their amounts, the version and the locktime
in one shot — and therefore the txid. The device only *adds* per-input
signature fields, so a genuine reply always matches.

Set `requireEveryInputSigned: false` for dApp `signPsbt` hand-backs, where a
PSBT legitimately carries inputs you cannot sign. Leave it at its default
(`true`) for a plain send, where a partially signed reply should fail here with
a reason rather than later inside a finalizer.

### XRP, the other chain with no id

```dart
final verdict = verifyXrpSignature(VerifyXrpSignatureArgs(
  signedTx: signature.signedTx,
  expectedSigningPubKey: signingPubKeyHexFromYourRequest,
));
if (!verdict.ok) throw StateError(verdict.reason!);
```

The device signs XRP with `m/44'/144'/0'/0/0` and nothing else, so the
`SigningPubKey` in your request JSON must be that key's public key — a
transaction carrying any other key is invalid on the ledger. The check strips
`TxnSignature`, rehashes the remainder with the XRPL signing tag, and verifies
the DER signature against exactly that key.

## Then broadcast

What comes back, and what to do with it:

| Chain | Reply carries | Broadcast |
|---|---|---|
| EVM | `signature`, `r`, `s`, `v`, `recoveryId` | Assemble the signed transaction with your EVM library. `v` is **as sent** — parity for typed transactions, 27/28 for messages, already EIP-155-encoded for legacy. Do not re-apply the EIP-155 formula |
| Bitcoin, Litecoin, Dogecoin, Dash | `psbt` — signed, **not finalized** | Finalize and broadcast with your Bitcoin stack |
| Bitcoin (message) | `signature` (raw 65-byte BIP-137), `signatureBase64` | Nothing to broadcast. Hand the base64 to whoever asked |
| Bitcoin Cash | `rawTx` hex, `txId` | Broadcast `rawTx` as-is |
| Solana | 64-byte Ed25519 `signature` | Attach to the compiled message and submit |
| Tron | `rawTx` hex, `txId`, `signedTx` split | Broadcast `rawTx` as-is |
| TON | 64-byte Ed25519 `signature` | Attach to the BoC with your TON library |
| Cardano | `witnessSet` CBOR, parsed `witnesses` | Merge the witness set into your transaction |
| Sui | 64-byte `signature`, signer `publicKey` | Assemble the serialized signature your Sui library expects |
| Cosmos / Ethermint | 64-byte compact `signature`, `publicKey` (absent on the `evm-signature` shape) | Attach to the SignDoc and submit |
| XRP | `signedTx` — canonical signed binary | Submit verbatim |

## Per-chain helper, per-chain guide

| Chain | Verify with | Guide |
|---|---|---|
| EVM | `verifyEvmSignature` | [EVM](../chains/evm.md) |
| Bitcoin + LTC/DOGE/DASH | `verifySignedPsbt` (**mandatory** — no request id) | [Bitcoin](../chains/bitcoin.md) |
| Bitcoin messages | `verifyBtcMessageHeader` | [Bitcoin](../chains/bitcoin.md) |
| Bitcoin Cash | `verifyBchSignedTx` | [Bitcoin Cash](../chains/bch.md) |
| Solana | `verifySolanaSignature` | [Solana](../chains/solana.md) |
| Tron | `verifyTronSignature` | [Tron](../chains/tron.md) |
| TON | `verifyTonSignature` | [TON](../chains/ton.md) |
| Cardano | `verifyCardanoSignature` | [Cardano](../chains/cardano.md) |
| Sui | `verifySuiSignature` | [Sui](../chains/sui.md) |
| Cosmos / Ethermint | `verifyCosmosSignature` (`CosmosDigest.sha256`, or `keccak256` for Ethermint zones) | [Cosmos](../chains/cosmos.md) |
| XRP | `verifyXrpSignature` (**mandatory** — no request id) | [XRP](../chains/xrp.md) |

Several helpers take an optional *expected key* — `expectedPublicKey` on Sui
and Cosmos, `account` plus `signerPaths` on Cardano. Pass it. Without it the
check proves the reply is internally consistent; with it, the check proves the
reply came from **your** linked wallet.

**[Verification](../advanced/verification.md)** covers what each helper
recomputes, what it deliberately does not, and how to read an `Unverifiable`
verdict in a UI.

---

That is the whole loop: link once, build a request, animate it, scan the reply,
verify, broadcast. From here, the
**[chain guides](../README.md#chain-guides)** carry the per-chain request
fields and reply shapes.
