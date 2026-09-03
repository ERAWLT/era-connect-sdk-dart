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

final scanner = era.scanner(const UrScannerOptions(
  expectedTypes: ['crypto-multi-accounts', 'crypto-account', 'crypto-hdkey'],
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
                    //   | cardano | sui | cosmos | unknown
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
accounts.btc(testnet: true);                      // 'tb1…' / testnet P2PKH
```

Two edges worth knowing before you hit them:

- `deriveAddress` on a **purpose 86** view throws `invalid-props`. Taproot
  addresses need the BIP-341 output-key tweak, which is Bitcoin-library work,
  not BIP-32 work — take `xpub()` and derive them with your own stack.
- `zpub()` on any purpose but 84 throws `invalid-props`; SLIP-132 `zpub` is
  defined for the BIP-84 key alone.

Litecoin, Dogecoin and Dash sign through the same `btc` module, but their
accounts live under their own coin types — build those PSBTs with the coin's
own paths and derive their addresses with your own library.

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

### Cosmos and XRP

Neither has a dedicated view, and both are still fully signable — they just
read their account material out of `keys`.

**Cosmos** entries classify as `AccountChain.cosmos` (`m/44'/118'`). Take the
path and the xfp from the entry and hand the bech32 encoding to your zone's
tooling, because the human-readable prefix is per zone (`cosmos`, `osmo`,
`inj`, …) and no single answer exists in an SDK:

```dart
final cosmos = accounts.keys
    .firstWhere((k) => k.chain == AccountChain.cosmos);
cosmos.path;       // "m/44'/118'/0'"
cosmos.xfp;
cosmos.publicKey;  // encode to <prefix>1… with your Cosmos library
```

**XRP** is simpler and stricter: the device always signs with
`m/44'/144'/0'/0/0` and nothing else. A transaction whose `SigningPubKey` is
not that key's public key is invalid — the ledger will reject it, and so will
the SDK's own request gate. Coin type 144 is not one the classifier maps, so
if the export carries it, it arrives as `AccountChain.unknown` with its path
and key intact. If it does not, ask for it explicitly — which is the next
section.

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
