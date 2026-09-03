# era_connect — documentation

`era_connect` puts the **ERA hardware wallet** behind a Dart or Flutter
wallet. The device never touches a cable or a radio: requests leave your app
as animated QR frames, signatures come back the same way. The SDK owns every
byte of that protocol — BC-UR fountain encoding, the Keystone-compatible
registry, the CBOR layouts, the reply checks — and owns nothing else. You
render the QR, you drive the camera, you broadcast.

Pure Dart, no plugins, no network I/O. Eleven chain families through ten
modules.

```sh
dart pub add era_connect
```

## Getting started

Read in order. About fifteen minutes from an empty project to a signature you
have verified.

1. [Install](getting-started/01-install.md) — the facade, the origin string,
   the config knobs
2. [Link the device](getting-started/02-link-device.md) — scan
   `crypto-multi-accounts` once, derive every address locally afterwards
3. [Display a request](getting-started/03-display-request.md) — build it,
   fragment it, animate it
4. [Scan the signature](getting-started/04-scan-signature.md) — feed camera
   frames; the request-id echo is enforced for you
5. [Verify, then broadcast](getting-started/05-broadcast.md) — prove what was
   signed, then send it with your own stack

## Chain guides

Eleven families, ten modules: Litecoin, Dogecoin and Dash ride the Bitcoin
module over `crypto-psbt-extend`, so they live in the Bitcoin guide.

| Guide | Covers | Library |
|---|---|---|
| [EVM](chains/evm.md) | transactions, `personal_sign`, EIP-712 | `package:era_connect/evm.dart` |
| [Bitcoin](chains/bitcoin.md) | PSBT v0; BIP-137 messages; **Litecoin, Dogecoin, Dash** | `package:era_connect/btc.dart` |
| [Bitcoin Cash](chains/bch.md) | the FORKID envelope, CashAddr, whole-transaction verification | `package:era_connect/bch.dart` |
| [Solana](chains/solana.md) | legacy and versioned transactions, off-chain messages | `package:era_connect/solana.dart` |
| [Tron](chains/tron.md) | any contract, through `raw_data` | `package:era_connect/tron.dart` |
| [TON](chains/ton.md) | BoC root-hash signing, TON Connect proofs | `package:era_connect/ton.dart` |
| [Cardano](chains/cardano.md) | witness sets, soft-derived vkey binding | `package:era_connect/cardano.dart` |
| [Sui](chains/sui.md) | intent messages and the hash variant | `package:era_connect/sui.dart` |
| [Cosmos](chains/cosmos.md) | ~35 zones, Ethermint included | `package:era_connect/cosmos.dart` |
| [XRP](chains/xrp.md) | the `ur:bytes` transaction-JSON convention | `package:era_connect/xrp.dart` |

The root library, `package:era_connect/era_connect.dart`, exports all of it
behind the `EraConnect` facade. A UR type with no module of its own goes
through `era.raw` plus the scanner.

## Advanced

- [Verification](advanced/verification.md) — did the device sign exactly what
  you sent? Two independent bindings, and the chains that only have one
- [QR tuning](advanced/qr-tuning.md) — fragment sizes, frame rates, honest
  progress, scan timeouts, the transport ceilings
- [Key-derivation calls](advanced/key-derivation-call.md) — ask the device for
  specific paths instead of taking what the sync screen offers
- [WalletConnect](advanced/walletconnect.md) — backing a WalletConnect wallet
  with the device: the forwarding model, method mapping, result shapes
- [Flutter and Dart notes](advanced/flutter.md) — camera and QR widget
  responsibilities, tickers, isolates, and the platform caveats
