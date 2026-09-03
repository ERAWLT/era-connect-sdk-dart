# Flutter and Dart notes

The SDK is headless on purpose. It owns every byte of the protocol and nothing
that draws or captures. This page is the part you have to write yourself.

| The SDK owns | You own |
|---|---|
| UR fragmenting, the fountain encoder, frame strings | The QR widget that renders those strings |
| Frame parsing, reassembly, type pinning, dedup, rejections | The camera and the barcode reader that produce them |
| CBOR layouts, request ids, reply checks, verification | Timers, layout, navigation, persistence, broadcasting |

Any QR-rendering package and any barcode-scanning package work. The SDK hands
you a `String` per frame and takes a `String` per frame back.

## Displaying a request

`AnimatedUr` is stateful — each `nextFrame()` advances the fountain — so it
belongs in your `State`, never in `build()`.

```dart
class SignQrView extends StatefulWidget {
  const SignQrView({super.key, required this.request});

  final SignRequest<EvmSignatureResult> request;

  @override
  State<SignQrView> createState() => _SignQrViewState();
}

class _SignQrViewState extends State<SignQrView> {
  late final AnimatedUr _animated = widget.request.toAnimated();
  late String _frame = _animated.nextFrame();
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    if (!_animated.isSingleFrame) {
      _timer = Timer.periodic(
        const Duration(milliseconds: 125),           // 8 fps
        (_) => setState(() => _frame = _animated.nextFrame()),
      );
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => YourQrWidget(data: _frame);
}
```

Two failure modes, both silent:

- **Building the `AnimatedUr` inside `build()`** restarts the stream at frame
  one on every rebuild. The device sees the first fragment over and over and
  never assembles anything, and nothing in your app reports an error.
- **Swapping the widget without a stable `Key`** destroys the `State` and does
  the same thing. If the QR is cross-faded, tabbed, or wrapped in a widget that
  changes type between rebuilds, give it a key that outlives the swap.

A `Ticker` is the better driver when the request can be scrolled off screen: it
stops with the route, so you are not advancing a fountain nobody is looking at.

```dart
class _SignQrViewState extends State<SignQrView>
    with SingleTickerProviderStateMixin {
  late final AnimatedUr _animated = widget.request.toAnimated();
  late final Ticker _ticker = createTicker(_onTick)..start();
  Duration _lastFrameAt = Duration.zero;
  late String _frame = _animated.nextFrame();

  void _onTick(Duration elapsed) {
    if (elapsed - _lastFrameAt < const Duration(milliseconds: 125)) return;
    _lastFrameAt = elapsed;
    setState(() => _frame = _animated.nextFrame());
  }

  @override
  void dispose() {
    _ticker.dispose();
    super.dispose();
  }
}
```

### The frame rate is a display concern

Nothing in the protocol has a clock. The fountain emits an endless stream of
frames, and whichever ones the device's camera happens to catch are the ones it
uses — a missed frame costs latency, never correctness. The 125 ms interval
exists so the camera at the other end gets a whole exposure per frame; slowing
to 6 fps for a dim screen is a legitimate trade, and speeding past 8 fps buys
nothing because the camera cannot keep up.

Two things that are *not* display concerns, because they change the bytes:
`maxFragmentLength`, and lowercasing the frame string. Frames are uppercase so
QR encoders can use alphanumeric mode; a widget that re-cases them silently
produces a denser code. See [QR tuning](qr-tuning.md).

Keep the screen awake while a request is on screen. A display that dims halfway
through an animation strands the device mid-assembly.

## Feeding scanned frames

`UrScanner.receivePart` is synchronous and does not throw on the feed path —
malformed frames come back as typed rejections. It is safe to call directly
from a camera callback.

```dart
class _ScanState extends State<ScanPage> {
  late final TypedUrScanner<EvmSignatureResult> _scanner =
      widget.request.scanner();
  String? _lastFrame;
  bool _finishing = false;

  void _onBarcode(String? text) {
    if (text == null || _finishing || text == _lastFrame) return;
    _lastFrame = text;

    switch (_scanner.receivePart(text)) {
      case ScanComplete():
        _finishing = true;
        _finish();
      case ScanProgress(:final framesReceived, :final framesExpected):
        setState(() => _progress = '$framesReceived of $framesExpected');
      case ScanDuplicate():
        break;
      case ScanRejected(:final rejection):
        // Repeats of the same rejection arrive at camera framerate.
        if (rejection.repeated == 1) _note(rejection.code);
    }
  }
}
```

**Deduplicate before you call in.** A barcode reader delivers the same value on
every preview frame — thirty times a second while the phone sits still. The
scanner already recognises repeats and answers `ScanDuplicate`, but only after
parsing the string; the one-line `text == _lastFrame` guard skips that work
entirely and is the cheapest optimisation available on this path. (The
scanner's own memory of seen frames is capped, so it cannot be filled by
hostile input; that cap is a defence, not a dedup budget you should lean on.)

**Latch the completion.** Frames keep arriving while the route pops. Without
`_finishing`, one scan can navigate twice.

Then parse and verify:

```dart
Future<void> _finish() async {
  final EvmSignatureResult reply;
  try {
    reply = _scanner.parse();        // throws on a bad type or a stale echo
  } on EraSdkError catch (e) {
    return _showError(e.code);       // branch on code, never on message
  }
  final check = await _verifyOffThread(reply);
  if (!check.ok) return _showError(check.reason!);
  await _broadcast(reply);
}
```

`EraSdkError.code` is stable API and comes from a closed set —
`request-id-mismatch`, `wrong-ur-type`, `malformed-reply`, `empty-signature`,
`limit-exceeded` and the rest. `message` is for humans and may change; do not
match on it.

## Keeping heavy work off the UI isolate

Feeding frames is cheap and must stay on the UI isolate — it has to be
synchronous to keep frame ordering. What is not cheap is elliptic-curve work in
pure Dart, and there are two places it shows up:

- **Verification.** `verifyEvmSignature`, `verifyCosmosSignature`,
  `verifyXrpSignature` and `verifyTronSignature` each do a secp256k1 recovery
  or verification; `verifyBchSignedTx` does one per input; the Ed25519 helpers
  (Solana, TON, Sui) do one per signature, and `verifyCardanoSignature` also
  soft-derives a key per signer path. On a low-end phone a single operation is
  a whole frame budget, so this is one visible stutter, not a loop — but it
  lands exactly when the user is watching a success animation.
- **Address derivation in bulk.** One `deriveAddress` is a single BIP-32 child
  derivation. Twenty of them for a gap scan is worth moving.

Verification helpers are pure functions over byte arrays, so they isolate
cleanly:

```dart
import 'package:flutter/foundation.dart' show compute;
import 'package:era_connect/era_connect.dart';
import 'package:era_connect/verify.dart';

class EvmCheck {
  const EvmCheck(this.signData, this.signature, this.address);
  final Uint8List signData;
  final Uint8List signature;
  final String address;
}

// Top-level or static — `compute` cannot take a closure.
VerifyResult runEvmCheck(EvmCheck a) => verifyEvmSignature(
      VerifyEvmSignatureArgs(
        signData: a.signData,
        dataType: EvmDataType.transaction,
        signature: a.signature,
        address: a.address,
      ),
    );

final check = await compute(runEvmCheck, EvmCheck(rlp, reply.signature, address));
```

Both directions cross cheaply: `Uint8List` is a typed-data buffer, and
`VerifyResult` carries nothing but a string.

Outside Flutter, `Isolate.run(() => verifyEvmSignature(...))` does the same with
no wrapper class. Note that `dart:isolate` does not exist on the web; `compute`
handles that for you by running the callback inline, which is correct — a web
build has one thread either way.

## Platform notes

**Pure Dart, everywhere Dart runs.** No plugins, no platform channels, no
`dart:io` in the library. Dependencies are `archive`, `crypto`,
`ed25519_edwards` and `pointycastle` — all pure Dart. That covers Android, iOS,
macOS, Windows, Linux, Flutter web, and plain Dart: CLI tools, test harnesses,
server-side code. The protocol layer is testable without a device or a widget
tree, which is where most of your integration tests should live.

**Zero I/O.** The SDK never opens a socket and never touches the filesystem.
Nothing is cached and nothing is persisted; you decide what to store. The one
thing worth persisting is the linked wallet:

```dart
final accounts = era.parseAccounts(scanner.result());
await store.write(accounts.sourceUr!);        // the single-part `ur:` string

// Next launch — no device, no camera:
final accounts = era.parseAccounts(await store.read());
accounts.evm()!.deriveAddress(0);
```

**Randomness.** Request ids come from `Random.secure()`, which is available on
every Flutter target. On an embedder without one, minting throws
`EraSdkError('no-secure-random', …)`; inject a source rather than working
around it:

```dart
EraConnect(EraConnectConfig(origin: 'MyWallet', randomBytes: myCsprng));
```

**The web integer ceiling.** On the web, Dart `int` is a JavaScript number:
exact only up to 2^53 − 1. The wire formats here allow integers wider than
that, so the SDK **refuses oversized values rather than truncating them**, on
every platform, so that behaviour does not differ between your web build and
your mobile build:

| Where | Bound | Outcome |
|---|---|---|
| EVM `chainId` | unsigned 32-bit | `EraSdkError('invalid-props', …)` |
| UR fragment header fields | u32; message ≤ 64 KiB | the frame is dropped as inconsistent |
| PSBT compact-size lengths | 2^53 − 1 | `malformed-reply` |
| TON BoC header integers | 2^53 − 1 | `malformed-reply` |
| Cardano UTXO index | 2^53 − 1 | `invalid-props` |

Truncation is the worse failure by a distance: a silently narrowed `chainId`
produces a valid signature for a chain the user never approved. A refusal is
loud, local, and fixable.
