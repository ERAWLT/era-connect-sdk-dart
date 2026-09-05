## 0.2.0

**Behaviour change — `EraAccounts.btc(testnet: true)` now selects an account.**
0.1.0 used the flag only to pick an address encoding, never to choose an entry,
and 0.1.0 is published: on an export carrying both coin types it returned the
**mainnet** account rendered under a testnet HRP, while the account path, the
`xfp` a sign request would carry and the extended key all stayed mainnet; on a
testnet-only export it returned null. The view now selects the first entry
whose first two levels are `m/<purpose>'/1'/…` — SLIP-44 coin type 1 — and
everything it reports comes from that one entry.

- Selection reads the purpose and the coin type and nothing below them, on
  either network, and takes the FIRST entry that matches. An export whose only
  BIP-84 testnet entry is `m/84'/1'/2'` answers with that one, and a five-level
  leaf such as `m/84'/1'/0'/0/0` matches too, so read `accountPath` rather than
  assuming a `0'` account index. Both levels must be **hardened**: a
  `crypto-keypath` can spell a soft level, and `m/84'/1/0'` is a different key,
  not a testnet account.
- There is no fallback between the networks. `btc(testnet: true)` returns
  `null` when the export carries no coin-type-1' account. ERA wallets export
  Bitcoin accounts at coin type 0' only, so that is `null` for every current
  ERA export — the truthful answer, where 0.1.0 handed back a mainnet key
  wearing a testnet address.
- Mainnet is unchanged, precisely: for purposes 44, 49, 84 and 86 `btc()`
  selects the same entry it always did, on every export. For a purpose OUTSIDE
  that set it still returns `null`, as 0.1.0 did — 0.1.0 got that bound as a
  side effect of classifying the path as Bitcoin, and it now lives in the
  selector itself, so the network change could not quietly widen it.
- `xpub()` and `zpub()` follow the selected account instead of always emitting
  mainnet version bytes, so a testnet account serialises as `tpub…`
  (`0x043587cf`) and `vpub…` (`0x045f1cf6`) — the SLIP-132 forms. `zpub()`
  keeps its name and its BIP-84-only rule; on testnet it is the `vpub` form.
- Path classification is deliberately NOT widened. Coin type 1 is SLIP-44's
  "Testnet (all coins)", so `m/84'/1'/0'` is as much a Litecoin testnet account
  as a Bitcoin one and stays `AccountChain.unknown` in `accounts.keys`.
  `btc(testnet: true)` may resolve it only because the caller named the chain.
- `BtcAccountView`'s constructor no longer takes a `testnet` boolean: the
  network is read off the selected entry's own coin type. The parameter made
  it possible to reconstruct by hand the exact wrong answer this release
  removes — a mainnet entry wearing a testnet address. This is a **source
  break**, and 0.1.0 did put the constructor within reach: it exported
  `BtcAccountView` wholesale and `RawAccountEntry` by name, and the latter's
  const constructor takes named parameters, so the view was already
  constructible without any of this release's additions. What makes the break
  acceptable is its shape rather than an absence of callers: under pub's caret
  `^0.1.0` does not resolve to 0.2.0, so no one meets it by upgrading in
  place, and the dropped parameter was POSITIONAL — every 0.1.0 call site
  fails to compile against 0.2.0 instead of quietly changing behaviour.

**Added exports.** The entry libraries gate their surface with hand-written
`show` clauses, and symbols an integrator has to name had drifted off them.
Nothing was removed.

- `package:era_connect/era_connect.dart` — `randomRequestId`, `uuidStringify`,
  `bytesToHex`, `hexToBytes`, `walletUrTypes`, `parseMultiAccountsUr`,
  `pathEquals` and `defaultOrigin`. `parseMultiAccountsUr` is the only producer
  of `RawMultiAccounts` and `RawAccountEntry`, which the library already
  exported and which were therefore impossible to obtain.
- `package:era_connect/verify.dart` — every type its argument objects declare,
  so an app that imports this library alone can name what it hands the
  verifiers: `CardanoWitness` (`VerifyCardanoSignatureArgs.witnesses`),
  `EvmDataType` and `TonDataType` (the `dataType` fields), `TronLatestBlock`
  and `SignedTronTx` (`VerifyTronSignatureArgs`) — plus `EraSdkError`, which
  the exported `parsePsbt` and `bocRootHash` throw and which `on EraSdkError
  catch` could not otherwise name.
- The per-chain libraries — `defaultOrigin`, the value their already-exported
  `EraConnectConfig.origin` defaults to.

## 0.1.0

First release.

Account linking and air-gapped transaction signing over animated QR codes
(BC-UR / Keystone-compatible registry) for eleven chain families: EVM, Bitcoin
(plus Litecoin, Dogecoin and Dash through the same PSBT flow), Bitcoin Cash,
Solana, Tron, TON, Cardano, Sui, Cosmos and XRP.

- `EraConnect` facade with per-chain modules, plus narrow per-chain libraries
  for apps that only need one.
- Linking parses the device's `crypto-multi-accounts` export into typed
  account views that derive addresses locally, with no device round-trip.
- `package:era_connect/verify.dart` proves the device signed exactly what was
  sent — mandatory on the two paths that carry no request id (Bitcoin PSBT
  and XRP).
- Hardened transport: bounds before allocations, hostile-frame refusal in the
  scanner, a request-id echo on every reply that carries one, and a hard
  ceiling on compressed replies.
- Pure Dart: no plugins, no `dart:io` in the library, no network calls.
