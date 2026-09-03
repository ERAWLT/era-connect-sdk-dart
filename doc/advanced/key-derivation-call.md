# Key-derivation calls

Normal linking is a **push**: the user opens the device's sync screen, the
device decides which accounts to export, and your app parses whatever arrived.
That is the right default — it needs nothing from your side but a camera.

A key-derivation call inverts it into a **pull**: your app names the exact
derivation paths, curves and algorithms it wants, and the device answers with
an account export containing those. Use it when the push export does not cover
what you need — a chain the sync screen does not offer, account index 3 when it
exports only 0, or a curve and algorithm pairing you have to be explicit about.

The reply is an ordinary account export, so it closes back into the same
`EraAccounts` you already know how to use.

## Build the call

```dart
import 'package:era_connect/era_connect.dart';

final era = EraConnect(const EraConnectConfig(origin: 'MyWallet'));

final call = era.generateKeyDerivationCall(const KeyDerivationCallProps(
  schemas: [
    KeyDerivationSchema(path: "m/44'/60'/0'"),                 // EVM
    KeyDerivationSchema(
      path: "m/44'/501'/0'",
      curve: DerivationCurve.ed25519,
      chainType: 'SOL',
    ),
    KeyDerivationSchema(
      path: "m/1852'/1815'/0'",
      curve: DerivationCurve.ed25519,
      algo: DerivationAlgorithm.bip32ed25519,                  // Cardano Icarus
      chainType: 'ADA',
    ),
  ],
  origin: 'MyWallet — restore',   // optional per-call override
));
```

`KeyDerivationCallProps`:

| Field | Type | Notes |
|---|---|---|
| `schemas` | `List<KeyDerivationSchema>` | At least one. An empty list throws `EraSdkError('invalid-props', …)`. |
| `origin` | `String?` | Overrides the SDK-level origin label for this call only. |

`KeyDerivationSchema`:

| Field | Type | Default | Notes |
|---|---|---|---|
| `path` | `String` | required | The derivation path to request, e.g. `m/44'/60'/0'`. Parsed and validated locally. |
| `curve` | `DerivationCurve?` | `secp256k1` | Or `DerivationCurve.ed25519`. |
| `algo` | `DerivationAlgorithm?` | `slip10` | Or `DerivationAlgorithm.bip32ed25519`, the Cardano Icarus scheme. |
| `chainType` | `String?` | — | A hint the device may show the user. Display only. |

The call is emitted as a `qr-hardware-call` (1201) wrapping a
`key-derivation-call` (1301), one `1302` schema entry per path, each carrying a
`crypto-keypath` (304), the curve and the algorithm.

## Display it, then scan the answer

`HardwareCallRequest` carries the same surface as a sign request, minus the
request id — this call has none.

```dart
final animated = call.toAnimated();
// render animated.nextFrame() on a timer, exactly as for a sign request

final scanner = call.scanner();   // pinned to the wallet-export reply types
// feed camera frames: scanner.receivePart(frameText)
final accounts = scanner.parse(); // EraAccounts

final evm = accounts.evm()!;
evm.deriveAddress(0);
```

| Member | Type | Purpose |
|---|---|---|
| `ur` | `Ur` | The request UR, if you want to inspect or log it |
| `replyTypes` | `List<String>` | `crypto-multi-accounts`, `crypto-account`, `crypto-hdkey` |
| `toAnimated([options])` | `AnimatedUr` | Fragment and animate for display |
| `scanner()` | `TypedUrScanner<EraAccounts>` | Pre-pinned to `replyTypes`; `parse()` yields the linked wallet |

Because the reply is a plain account export, everything downstream is
unchanged: `accounts.keys`, `accounts.xfpFor(path)`, the per-chain views, local
address derivation. You can store the export and never make this call again.

## Compatibility: plan for silence

**Not every firmware answers this call.** A device that does not recognise it
does not display an error, does not draw a refusal QR, and does not tell your
app anything. It simply shows nothing, and your scanner waits.

That shapes the flow you ship:

- **Treat a scan timeout as "unsupported", not as a failure.** No exception is
  thrown, no rejection is recorded, `lastRejection` stays null — there is
  nothing to catch. The only signal is that time passed and nothing assembled.
- **Keep the ordinary linking path in the product.** The fallback is not a
  debug affordance; it is the path most devices will take. Offer it in the same
  screen the user is already looking at.
- **Do not strand the user on a spinner.** Bound the wait, then say what to do
  next in plain words: open the sync screen on the device and scan that instead.

```dart
Future<EraAccounts> link() async {
  final byCall = await scanWithTimeout(
    era.generateKeyDerivationCall(props),
    const Duration(seconds: 20),
  );
  if (byCall != null) return byCall;

  // Silence means this firmware does not serve the call. Ask for the ordinary
  // export instead — same parser, same result type.
  return scanSyncExport();
}
```

Twenty seconds is a reasonable bound: a device that supports the call starts
drawing its answer as soon as the user approves it, and the reply leg runs at
2.5 fps (see [QR tuning](qr-tuning.md)). Long enough for a person to read the
screen and press a button; short enough not to feel broken.

## Notes

- The call has **no request id**, so there is no echo to check. What binds the
  answer is that it is a wallet export of the right UR type and that its paths
  are the ones you asked for — check them if it matters to you:
  `accounts.keys.map((k) => k.path)`.
- The paths you send are what you get back. The device may export additional
  entries alongside them; classify by path (`AccountKey.chain`), never by the
  `note` label.
- The origin string is shown to the user on the device. Make it the name they
  know your wallet by.
