# 2. Link the device

Linking happens once. The device shows a **wallet export** QR; you scan it,
parse it into `EraAccounts`, and store it. From then on every address in your
UI is derived locally, in your process, with no device round-trip — the wallet
only comes out again to sign.

## Scan the export

The export arrives as a `crypto-multi-accounts` UR (some exports use
`crypto-account` or `crypto-hdkey`; pin all three and you accept every shape
the device produces). Whether it arrives as one frame or as an animation
depends on how many accounts the device exports; the loop below handles both
without knowing which.

```dart
import 'package:era_connect/era_connect.dart';

final era = EraConnect(const EraConnectConfig(origin: 'MyWallet'));

// walletUrTypes is exactly those three; pin the set rather than a literal so
// a link type added to the SDK does not become a rejected frame in your app.
final scanner = era.scanner(UrScannerOptions(
  expectedTypes: walletUrTypes.toList(),
));

// One call per decoded camera frame. Never throws — see page 4.
void onFrame(String text) {
  final result = scanner.receivePart(text);
  switch (result) {
    case ScanComplete(:final ur):
      final accounts = era.parseAccounts(ur);
      onLinked(accounts);
    case ScanProgress(:final progress):
      showProgress(progress);
    case ScanRejected(:final rejection):
      if (rejection.repeated == 1) log(rejection.code); // see page 4
    case ScanDuplicate():
      break; // the camera re-read a frame; nothing to do
  }
}
```

`parseAccounts` also takes the single-part `ur:` string directly, which is what
you want when you already have it as text:

```dart
final accounts = era.parseAccounts(walletUrString);
```

## Store it, do not re-scan it

```dart
final accounts = era.parseAccounts(walletUrString);

accounts.masterFingerprint;         // 'aabbccdd' — lowercase 8-hex
accounts.device.name;               // 'ERA Wallet', when the export carries it
accounts.device.id;
accounts.device.firmwareVersion;
accounts.sourceUr;                  // the exact string you parsed — persist THIS
```

Persist `sourceUr` (or the string you scanned) and rebuild `EraAccounts` with
`era.parseAccounts(...)` on next launch. It is public key material, not a
secret, and re-parsing is cheap.

## Every exported key

`keys` is the flat list, classified by derivation path — never by the label
the device wrote next to it:

```dart
for (final key in accounts.keys) {
  key.chain;        // AccountChain.evm | btc | bch | solana | tron | ton
                    //   | cardano | sui | cosmos | xrp | unknown
  key.path;         // "m/44'/60'/0'"
  key.xfp;          // the fingerprint a sign request must carry for this account
  key.publicKey;    // 33-byte secp256k1 or 32-byte Ed25519; null if omitted
  key.chainCode;    // null if the export omitted it
  key.name;         // display only
  key.note;         // derivation-scheme label, display only
}
```

`xfp` is per account and is **not** necessarily the master fingerprint. Ask for
it by path and let a wrong path fail loudly:

```dart
final xfp = accounts.xfpFor("m/44'/60'/0'"); // throws account-not-found, never 0
```

A silent zero fingerprint would produce a request the device refuses with no
explanation, so the SDK refuses first.

## Typed per-chain views

Each view wraps one exported account and knows how to turn it into paths and
addresses. The singular getters return `null` when the export carries no such
account; `sui()` and `solana()` return lists, because those chains export one
pre-derived signer per account index.

### EVM

```dart
final evm = accounts.evm()!;
evm.accountPath;          // "m/44'/60'/0'"
evm.xfp;                  // '12345678'
evm.pathFor(0);           // "m/44'/60'/0'/0/0" — the path a sign request needs
evm.deriveAddress(0);     // '0x…' EIP-55 checksummed, derived locally
evm.xpub();               // account-level extended public key
```

### Bitcoin (and Litecoin, Dogecoin, Dash)

The device exports several script types. `btc()` defaults to the BIP-84
native-segwit account; ask for the others by purpose.

```dart
final btc = accounts.btc()!;                      // purpose 84, mainnet
btc.deriveAddress(0);                             // 'bc1q…'
btc.deriveAddress(0, change: true);               // change branch
btc.receivePath(0);                               // "m/84'/0'/0'/0/0"
btc.changePath(0);                                // "m/84'/0'/0'/1/0"
btc.xpub();
btc.zpub();                                       // SLIP-132, BIP-84 only

accounts.btc(purpose: 44);                        // legacy P2PKH, '1…'
accounts.btc(purpose: 49);                        // nested segwit, '3…'
accounts.btc(purpose: 86);                        // taproot account
```

`purpose` is bounded to those four values. Any other integer returns `null`
rather than a view — an arbitrary purpose has no script type and no address
encoding, so a view over it could hand you a plausible-looking `xpub()` and
refuse only later, at the first address.

Three edges worth knowing before you hit them:

- `deriveAddress` on a **purpose 86** view throws `invalid-props`. Taproot
  addresses need the BIP-341 output-key tweak, which is Bitcoin-library work,
  not BIP-32 work — take `xpub()` and derive them with your own stack.
- `zpub()` on any purpose but 84 throws `invalid-props`; SLIP-132 `zpub` is
  defined for the BIP-84 key alone.
- An entry only counts as a Bitcoin account when its purpose AND its coin type
  are **hardened**. A `crypto-keypath` can spell a soft level, and
  `m/84'/1/0'` is not a testnet account — it is a different key entirely.

Litecoin, Dogecoin and Dash sign through the same `btc` module, but their
accounts live under their own coin types — build those PSBTs with the coin's
own paths and derive their addresses with your own library.

#### `testnet` picks an account; it does not re-spell one

`testnet: true` changes **which entry** the view wraps: it looks for an entry
whose first two levels are `m/<purpose>'/1'/…` — SLIP-44's coin type 1,
"Testnet (all coins)" — instead of `m/<purpose>'/0'/…`. Everything the view
then reports comes from that entry, so the account path, the `xfp` a sign
request must carry, the addresses and the extended key all describe one and
the same key.

Only those two levels are examined, on either network, and the FIRST entry
that matches wins. An export whose only BIP-84 testnet entry is
`m/84'/1'/2'` answers with that one, and a five-level leaf such as
`m/84'/1'/0'/0/0` matches too — read `accountPath` rather than assuming a
`0'` account index, and derive from the path the view reports.

```dart
final btc = accounts.btc(testnet: true);          // null if the export has none
btc!.accountPath;                                 // e.g. "m/84'/1'/0'"
btc.deriveAddress(0);                             // 'tb1…'
btc.xpub();                                       // 'tpub…'
btc.zpub();                                       // 'vpub…' — SLIP-132 BIP-84
```

| Purpose | Address | `xpub()` | `zpub()` |
|---|---|---|---|
| 84 | `tb1q…` | `tpub…` | `vpub…` |
| 49 | `2…` | `tpub…` | throws `invalid-props` |
| 44 | `m…` / `n…` | `tpub…` | throws `invalid-props` |
| 86 | `deriveAddress` throws | `tpub…` | throws `invalid-props` |

`zpub()` keeps its name and its rule — BIP-84 only — and returns SLIP-132's
BIP-84 **testnet** key, whose version bytes spell `vpub`.

**There is no fallback between the two networks.** An export that carries no
coin-type-1' account returns `null`, and asking for mainnet on a testnet-only
export returns `null` the same way. A view that answered a testnet request
with the mainnet key under a `tb` prefix would be a confident wrong answer:
the address would be for a chain whose coins that account will never hold,
while the path and the `xfp` inside the sign request stayed mainnet.

**ERA wallets export Bitcoin accounts at coin type 0' only**, so
`accounts.btc(testnet: true)` returns `null` for every current ERA export —
handle the null rather than assuming a testnet account is there. The parameter
stays because the export format carries coin-type-1' accounts and other wallet
profiles do export them.

One more thing the table above does not show: a coin-type-1' entry classifies
as `AccountChain.unknown` in `accounts.keys`, not as `btc`. Coin type 1 is
"Testnet (**all** coins)", so `m/84'/1'/0'` is as much a Litecoin testnet
account as a Bitcoin one, and classification reads the path alone with nothing
to break the tie. `btc(testnet: true)` may resolve that same entry only
because the caller named the chain.

### Bitcoin Cash

```dart
final bch = accounts.bch()!;
bch.deriveAddress(0);                          // bare CashAddr
bch.deriveAddress(0, withPrefix: true);        // 'bitcoincash:q…'
bch.deriveAddress(0, change: true);
bch.derivePublicKey(0);                        // 33 bytes — a sign request names it
bch.receivePath(0);                            // "m/44'/145'/0'/0/0"
bch.changePath(0);
```

`derivePublicKey` matters here: a BCH sign request carries the owning public
key of every input it spends.

### Tron

```dart
final tron = accounts.tron()!;
tron.deriveAddress(0);   // 'T…' base58check
tron.pathFor(0);         // "m/44'/195'/0'/0/0"
```

### Solana

Ed25519 has no public child derivation, so the device pre-derives hardened
accounts and **each exported entry is a signer**:

```dart
for (final signer in accounts.solana()) {
  signer.index;      // the hardened account index
  signer.path;       // "m/44'/501'/0'"
  signer.publicKey;  // 32 bytes
  signer.address;    // base58 — the public key IS the address
}
```

### Sui

Same shape as Solana — fully hardened SLIP-10 entries, one signer each:

```dart
for (final signer in accounts.sui()) {
  signer.path;       // "m/44'/784'/0'/0'/0'"
  signer.publicKey;  // 32 bytes
  signer.address;    // '0x…' = BLAKE2b-256 of 0x00 || publicKey
}
```

### TON

One Ed25519 key per account, shared by the V4R2 and V5R1 wallet contracts. The
contract version changes only the **address**, so address assembly belongs to
your TON library:

```dart
final ton = accounts.ton()!;
ton.publicKey;    // 32 bytes — the signer for both contract versions
ton.accountPath;  // "m/44'/607'/0'"
ton.name;
```

### Cardano

The CIP-1852 account key supports soft public derivation, so payment, change
and stake verification keys come out locally. Bech32 address assembly is
Cardano-tooling work; the view hands you the raw vkeys it needs:

```dart
final cardano = accounts.cardano()!;
cardano.publicKey;         // account-level key material
cardano.chainCode;
cardano.deriveKey(0, 0);   // payment vkey at 0/0
cardano.deriveKey(1, 0);   // change vkey
cardano.deriveKey(2, 0);   // stake vkey
cardano.pathFor(0, 0);     // "m/1852'/1815'/0'/0/0"
```

### Cosmos

`m/44'/118'/0'`, one secp256k1 key, addresses at `0/index`. The bech32 prefix
is a property of the **zone**, not of the key — one key spends as `cosmos1…`,
`osmo1…` and `juno1…` — so there is no correct default and `deriveAddress`
requires one:

```dart
final cosmos = accounts.cosmos()!;
cosmos.accountPath;                          // "m/44'/118'/0'"
cosmos.pathFor(0);                           // "m/44'/118'/0'/0/0"
cosmos.derivePublicKey(0);                   // 33 compressed bytes
cosmos.deriveAddress(0, prefix: 'osmo');     // 'osmo1…'
```

Only `m/44'/118'` classifies as Cosmos. A zone with a coin type of its own —
Terra's 330, Kava's 459, Secret's 529 — comes back from `cosmos()` as null and
sits in `keys` as `AccountChain.unknown`; match it on `path` and derive with
your own BIP-32 library plus `cosmosAddressFromPublicKey`.

Ethermint zones (Injective, Evmos, Dymension) are not here at all: they sign
with `m/44'/60'` keys, so they come back as the **EVM** account.

### XRP

Stricter than the rest: the device signs with `m/44'/144'/0'/0/0` and nothing
else. A transaction whose `SigningPubKey` is not that key's public key is
invalid — the ledger will reject it, and so will the SDK's own request gate.

```dart
final xrp = accounts.xrp()!;         // the ACCOUNT at "m/44'/144'/0'"
xrp.signingPath;                     // "m/44'/144'/0'/0/0" — the only one
bytesToHex(xrp.derivePublicKey(0));  // what SigningPubKey must carry
```

That is the export that volunteers the **account**. Most sync screens do not
volunteer coin type 144 at all, in which case `xrp()` returns null and you ask
for the key explicitly instead — which is the next section.

Read that answer with care: it names the **full signing path**, so its entry
is the leaf key rather than an account — and classification reads the first
two path levels only, so `m/44'/144'/0'/0/0` still classifies as XRP and
`xrp()` wraps it as though it were an account:

```dart
// After a key-derivation call for "m/44'/144'/0'/0/0":
final view = accounts.xrp()!;  // NOT null — and not what you want
view.accountPath;              // "m/44'/144'/0'/0/0" — the leaf, treated as an account
view.signingPath;              // "m/44'/144'/0'/0/0/0/0" — two levels too deep
view.derivePublicKey(0);       // a grandchild of the signing key, not the key
```

So over a pull-model answer, skip the view: take the entry out of `keys` by
path and read `publicKey` directly.

```dart
final key = accounts.keys.firstWhere((k) => k.path == "m/44'/144'/0'/0/0");
final signingPubKey = bytesToHex(key.publicKey!);  // what SigningPubKey carries
```

A transaction built from the view's key instead would carry a `SigningPubKey`
the device never signs with, and the ledger would reject the result.

## Asking for specific derivations (the pull model)

The scan above is the **push** model: the device volunteers whatever its sync
screen exports. The pull model asks for exactly the derivation paths you name
instead — the way to obtain a key the sync screen does not offer, such as the
XRP signing key:

```dart
final call = era.generateKeyDerivationCall(const KeyDerivationCallProps(
  schemas: [
    KeyDerivationSchema(path: "m/44'/144'/0'/0/0"),   // the XRP signing key
    KeyDerivationSchema(path: "m/44'/118'/0'"),       // a Cosmos account
  ],
));

final animated = call.toAnimated();   // display it, exactly like a sign request
final scanner = call.scanner();       // pre-pinned to the export reply types
// feed frames …
final accounts = scanner.parse();     // an EraAccounts, as before
```

A schema carries a curve and an algorithm too, defaulting to secp256k1 with
SLIP-10 — which is what every path above wants. `HardwareCallRequest` displays and scans with the same two methods a
`SignRequest` uses, so it drops into the screens you are about to build.

See **[Key derivation call](../advanced/key-derivation-call.md)** for the
schema options and the device's answer shape.

## When derivation refuses

Two typed refusals come out of these views, both meaning the export is thinner
than the operation needs:

| Code | Meaning |
|---|---|
| `account-not-found` | The entry carries no chain code, so children cannot be derived — or `xfpFor` was given a path the export does not contain |
| `invalid-props` | The entry carries no public key of the required length. The xfp lookup still works; address derivation does not |

Both are `EraSdkError`. Branch on `code`, never on the message.

---

Next: **[3. Display a request](03-display-request.md)** — build a sign request
and animate it onto the screen.
