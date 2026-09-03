# Backing a WalletConnect wallet with the device

A WalletConnect session makes your app a signer for someone else's dApp. The
dApp sends a ready payload; you get it in front of the device, get a signature
back, and answer the JSON-RPC request. The device is the security boundary —
the person holding it approves or refuses what it renders.

## The forwarding model

**Wrap the dApp's payload verbatim. Do not rebuild it.**

The SDK does not construct transactions. For every method below, the bytes the
dApp sent (decoded from hex or base64 into `Uint8List`, and no further) go
straight into `signData` — or into the chain module's payload field — and the
device parses them. Three consequences worth stating plainly:

- **Do not gate on whether your app understands the payload.** An unfamiliar
  calldata, an unknown contract, a transaction type your decoder does not
  cover: forward it. The device decides what it can render and sign, and says
  so if it cannot. An app-side allowlist rejects transactions that would have
  worked.
- **Do not re-serialise.** Re-encoding a typed-data JSON or re-RLP-ing a
  transaction can change the bytes the device hashes, and then the signature
  answers a payload the dApp never sent.
- **Do not route WalletConnect through builders meant for your own send flow.**
  Structured, transfer-shaped request builders exist for transactions your app
  composed; a dApp's payload is arbitrary and belongs on the raw path.

What you *do* rebuild is the **display**: everything you show the user before
the QR goes up must be derived from the payload bytes themselves, never from
labels the dApp supplied. See [Revalidate before you display](#revalidate-before-you-display).

## Method mapping

`era` is an `EraConnect` instance; `evm`, `sol` and so on are views from the
linked `EraAccounts`.

### `eip155`

| Method | SDK call | `signData` | Result to the dApp |
|---|---|---|---|
| `eth_sendTransaction` | `era.evm.generateSignRequest(EvmSignRequestProps(dataType: EvmDataType.transaction, chainId: …))` | The unsigned RLP you serialise from the dApp's tx params with your own EVM tooling | The transaction hash, after **you** broadcast the assembled transaction |
| `eth_signTransaction` | same | same | The signed serialised transaction, `0x` hex — you assemble `r`, `s`, `v` into it |
| `personal_sign` | `EvmDataType.personalMessage` | The raw message bytes (hex-decode the dApp's parameter). The device applies the EIP-191 prefix | `0x` hex of `r ‖ s ‖ v` |
| `eth_sign` | `EvmDataType.personalMessage` | as above | `0x` hex |
| `eth_signTypedData`, `_v3`, `_v4` | `EvmDataType.typedData` | The dApp's JSON as UTF-8 bytes, **verbatim** | `0x` hex |

Use `EvmDataType.typedTransaction` for EIP-2718 typed transaction bytes; the
device treats it identically to `transaction`.

`chainId` is required for transactions and is read as an unsigned 32-bit
value — a larger id is refused locally rather than silently truncated into a
signature for a different chain. Pass the session's chain, not a default.

`EvmSignatureResult.v` is the recovery value **as the device sent it**: parity
for typed transactions, 27/28 for messages, already EIP-155-encoded for legacy
transactions. Do not re-apply the EIP-155 formula. `recoveryId` is the same
value folded to 0/1.

### `solana`

| Method | SDK call | `signData` | Result |
|---|---|---|---|
| `solana_signTransaction` | `era.solana.generateSignRequest(SolSignRequestProps(...))` — default `SolSignType.transaction` | The compiled transaction **message** bytes (legacy or versioned) | `{ signature: <base58> }` |
| `solana_signAndSendTransaction` | same | same | `{ signature: <base58> }` — the transaction signature, after you submit |
| `solana_signMessage` | `signType: SolSignType.message` | The raw message bytes. The device signs them **verbatim**, with no off-chain prefix | `{ signature: <base58> }` |

The Solana path is the 3-level hardened account path `m/44'/501'/idx'` — the
exported account is the signer, because Ed25519 has no public child derivation.
Anything else is refused with `invalid-props`.

### `bip122`

| Method | SDK call | Payload | Result |
|---|---|---|---|
| `signPsbt` | `era.btc.generatePsbtSignRequest(BtcPsbtSignRequestProps(psbt: …))` | The base64 PSBT decoded to bytes | The **signed, not finalized** PSBT — base64 of `result.psbt` |
| `signMessage` | `era.btc.generateMessageSignRequest(BtcMessageSignRequestProps(...))` | The raw message bytes plus the address and its path | `result.signatureBase64` |

Two things are mandatory here rather than advisable:

- `verifySignedPsbt` — the `crypto-psbt` path carries **no request id in either
  direction**, so comparing the returned PSBT against the one you sent is the
  only anti-replay binding that exists. See
  [Verification](verification.md#the-two-paths-where-it-is-not-optional).
- `requireEveryInputSigned: false` on this path specifically. A dApp's PSBT
  legitimately carries inputs you cannot sign, and the default would refuse the
  reply.

Message signing is firmware-dependent. Firmware 2.1.0 and later signs BIP-44,
BIP-49 and BIP-84 addresses with the matching BIP-137 header and refuses only
Taproot, for which BIP-137 defines no header range. Older firmware signs legacy
P2PKH only and answers a segwit address with an empty signature, surfaced as
`EraSdkError('empty-signature', …)`. Handle that code: it means "this address
kind, this firmware", not "the device is broken".

### `tron`

| Method | SDK call | Payload | Result |
|---|---|---|---|
| `tron_signTransaction` | `era.tron.generateSignRequest(TronSignRequestProps(...))` | `rawData`: the dApp's `raw_data_hex`, hex-decoded | The transaction echoed back with `signature: [<hex>]` |

Tron rides the structured `keystone-sign-request` (6101) envelope. The
registry's generic `tron-sign-request` (5101) gets **no answer from the
device** — do not emit it.

`latestBlock` is required and must carry the **full 64-hex block id** of a live
now-block; the device slices `ref_block_hash` from it, and
`verifyTronSignature` uses it for the validity-window check. Source it fresh
per request.

The `display` fields are for the device screen only, and a dApp transaction is
often opaque — omit them rather than guessing. The reply is a complete
transaction broadcast verbatim, so `verifyTronSignature` is required before you
hand anything back.

Arbitrary message signing is outside this module: it builds transaction
requests from `raw_data`.

### `cosmos`

| Method | SDK call | `signData` | Result |
|---|---|---|---|
| `cosmos_signDirect` | `era.cosmos.generateSignRequest(CosmosSignRequestProps(dataType: CosmosDataType.direct, ...))` | The protobuf-encoded SignDoc bytes | The namespace's `{ signature: { pub_key, signature } }` envelope; `result.signature` is the 64-byte compact signature, base64-encoded |
| `cosmos_signAmino` | `dataType: CosmosDataType.amino` | The canonical Amino JSON as UTF-8 bytes | as above, with the signed doc echoed |

Ethermint zones — Injective, Evmos, Dymension — sign with keccak-256 over
Ethereum-style keys and travel as a different request:
`era.cosmos.generateEthermintSignRequest(EthermintSignRequestProps(...))`, with
`m/44'/60'/…` paths. Verify them with `CosmosDigest.keccak256`; vanilla zones
use `CosmosDigest.sha256`. Picking the wrong one turns a good signature into a
failed verification.

### `sui`

| Method | SDK call | Payload | Result |
|---|---|---|---|
| `sui_signTransaction`, `sui_signTransactionBlock` | `era.sui.generateSignRequest(SuiSignRequestProps(intentMessage: …))` | The **complete BCS intent message** (intent prefix + transaction bytes) as your Sui tooling produces it | The base64 signature the namespace expects, alongside the bytes that were signed |
| `sui_signPersonalMessage` | same, with the personal-message intent | as above | as above |

`era.sui.generateSignHashRequest(SuiSignHashRequestProps(messageHash: …))`
signs a 32-byte digest directly, for flows that hand you a hash rather than a
message.

### `xrpl`

| Method | SDK call | Payload | Result |
|---|---|---|---|
| `xrpl_signTransaction` | `era.xrp.generateSignRequest(XrpSignRequestProps(transaction: …))` | The unsigned transaction JSON — a `Map<String, dynamic>` or a JSON string | `result.signedTx`, the canonical signed XRPL binary; decode it to `tx_json` with your XRPL tooling if the dApp expects that shape |

**The device always signs XRP with `m/44'/144'/0'/0/0`.** A transaction whose
`SigningPubKey` is not that key's public key is invalid — the network rejects
it, and so does `verifyXrpSignature`. Put that key's compressed hex into the
request JSON before forwarding, and reject a dApp payload that names a
different one. The request also needs `TransactionType`, a classic `r…`
`Account`, `Fee` and `Sequence`; the SDK refuses locally, with a reason, rather
than letting the device refuse silently.

There is no request id on this path in either direction. `verifyXrpSignature`
is the binding.

### TON and Cardano

TON Connect and CIP-30 are not WalletConnect JSON-RPC, but the shape is the
same and the modules serve them:

- **TON** — a transaction is a Bag-of-Cells: pass it as `signData` with
  `TonDataType.transaction`, and the device signs the root cell's
  representation hash. A TON Connect proof uses `TonDataType.tonProof`, where
  the device signs `sha256(0xFFFF ‖ "ton-connect" ‖ sha256(payload))`. The
  request id travels as the ASCII bytes of the hyphenated UUID string, which
  the SDK handles for you.
- **Cardano** — `api.signTx` maps to
  `era.cardano.generateSignRequest(CardanoSignRequestProps(...))` with the full
  transaction CBOR as `signData`; the reply is a witness set to merge into the
  transaction. Pass `account` and `signerPaths` to `verifyCardanoSignature` so
  a witness set carrying a key you did not ask for is refused.

### Result shapes

The exact envelope each method expects is defined by the namespace
specification the dApp is using, and the SDK shapes nothing — it returns raw
bytes and typed results. The column above is the common shape; confirm it
against the namespace your session negotiated before you ship, particularly for
the newer namespaces where wallets differ.

## Revalidate before you display

Forwarding the payload verbatim to the device is correct. Trusting the dApp's
*description* of that payload is not. Everything the user reads on your screen
before the QR appears must be re-derived locally from the bytes you are about
to send:

- **Recipient and amount.** Decode them out of the RLP, the compiled message,
  the PSBT outputs, the `raw_data`. A dApp-supplied "to" label costs nothing to
  fake.
- **Calldata.** Decode the selector and arguments yourself. An `approve` with
  an unlimited allowance and a transfer to a lookalike address both look
  ordinary in a summary string.
- **The chain.** The `chainId` you sign for must be the session's chain.
- **The signer.** The `from` address must be one your linked wallet actually
  holds — compare against `deriveAddress`, not against what the dApp asked for.
- **The origin string.** Pass the dApp's name as `origin` on the request so the
  device shows the user *who* is asking. It is per-request:
  `EvmSignRequestProps(origin: session.peer.metadata.name, …)`.

Then verify what came back, before you answer the dApp:
[Verification](verification.md). A signature returned to a dApp is a signature
in the wild; the round trip is the last place you can still refuse it.

## Session hygiene

- **One request, one `SignRequest` object.** The request id is minted at
  construction, and the same object that rendered the QR is the one that
  validates the echo. Reusing an old object across two dApp requests defeats
  that.
- **Advertise only accounts you can sign for.** The namespaces you approve at
  session time are a promise; a method for a chain you did not link fails at
  the worst moment.
- **Reply warnings are yours to surface.** `SignRequest.warnings` carries
  non-fatal advisories — `blind-sign-threshold` means the payload is large
  enough that the device will not decode it and the user will be approving a
  hash. That is worth saying out loud on a dApp request.
