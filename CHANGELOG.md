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
