# 3. Display a request

You build the transaction with your own chain tooling. The SDK takes the
finished bytes, wraps them in the chain's registry UR, and turns that into QR
frames the device can read.

## Build the request

An EVM transaction, using the account you linked on page 2:

```dart
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';

final era = EraConnect(const EraConnectConfig(origin: 'MyWallet'));
final evm = accounts.evm()!;

final request = era.evm.generateSignRequest(EvmSignRequestProps(
  signData: rlpEncodedTransaction,   // your bytes, from your EVM library
  dataType: EvmDataType.transaction,
  path: evm.pathFor(0),              // "m/44'/60'/0'/0/0"
  xfp: evm.xfp,
  chainId: 1,
  address: evm.deriveAddress(0),     // optional, but it unlocks verification
));
```

Every chain module has the same entry point — `generateSignRequest`, taking a
`Props` object — and returns the same `SignRequest<T>`, differing only in `T`,
the reply it knows how to parse. Per-chain fields are in
**[the chain guides](../README.md#chain-guides)**.

## What a SignRequest holds

```dart
request.ur;          // the Ur to display
request.requestId;   // 16 bytes, minted at construction — null where the
                     //   protocol carries none (Bitcoin PSBT, XRP)
request.replyTypes;  // the UR types that may answer THIS request
request.warnings;    // non-fatal advisories
```

The request id is minted when the object is constructed, not when you scan.
That is the whole point: the object that rendered the QR is the object that
validates the echo, so a reply from an earlier flow left in front of the camera
is refused rather than accepted. **Keep the `SignRequest` alive for the whole
journey** — from display through scanning. Rebuilding it to "refresh" the
screen mints a new id and throws away the binding.

Check `warnings` before you show the screen. Today one advisory exists:

| Warning | Meaning |
|---|---|
| `blind-sign-threshold` | `signData` is over 32 KiB, so the device will skip decoding and blind-sign. Tell the user that; they cannot review what the device does not parse |

## Animate it

```dart
final animated = request.toAnimated();

animated.urType;        // 'eth-sign-request'
animated.fragmentCount; // source fragments the payload was split into
animated.isSingleFrame; // true when the payload fits one QR
animated.nextFrame();   // the next wire frame, uppercase — hand to your QR widget
animated.toString();    // the whole UR as one lowercase 'ur:' string (loggable,
                        //   not what goes on screen)
```

Frames are uppercase deliberately: a QR encoder can then use alphanumeric mode,
which is about 45% denser than byte mode. Do not lowercase them.

Two rules the loop must respect:

- **`nextFrame()` never ends.** It is a fountain encoder: after the source
  fragments it keeps emitting XOR mixtures forever. The device usually needs
  more frames than `fragmentCount` to converge. Loop until the user leaves the
  screen or the device confirms — never until a frame count.
- **A single-frame payload returns the same string on every call.** Check
  `isSingleFrame` and draw it once, statically. Animating one frame only makes
  it harder to scan.

In Flutter, a `Timer.periodic` and a `setState` are the whole implementation:

```dart
class SignQrView extends StatefulWidget {
  const SignQrView({super.key, required this.animated});

  final AnimatedUr animated;

  @override
  State<SignQrView> createState() => _SignQrViewState();
}

class _SignQrViewState extends State<SignQrView> {
  late String _frame = widget.animated.nextFrame();
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    if (widget.animated.isSingleFrame) return;
    _timer = Timer.periodic(
      const Duration(milliseconds: 125),
      (_) => setState(() => _frame = widget.animated.nextFrame()),
    );
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => QrImageView(data: _frame); // your widget
}
```

## The defaults, and when to move them

The phone-to-device leg runs **180 payload bytes per fragment at 125 ms
(8 fps)**. Those are the numbers the device's own camera pipeline is tuned for,
and they are readable from the SDK rather than hardcoded in your UI:

```dart
DeviceProfile.phoneToDevice.payloadBytes;        // 180
DeviceProfile.phoneToDevice.fragmentBytesOnWire; // ~200 after the frame header
DeviceProfile.phoneToDevice.frameIntervalMs;     // 125
```

180 payload bytes become roughly 200 bytes on the wire — the fragment header
costs about 16 bytes — which is the per-frame ceiling hardware-wallet cameras
scan reliably.

Lower the fragment size when the frames are physically hard to read: a small or
dim phone screen, a high QR error-correction level, a device held at an angle,
or a user reporting that the scan stalls. Smaller fragments make each QR
sparser and easier, at the cost of more frames and a longer cycle.

Per request:

```dart
final animated = request.toAnimated(
  const AnimatedUrOptions(maxFragmentLength: 120),
);
```

Or once, for the whole app:

```dart
final era = EraConnect(const EraConnectConfig(
  origin: 'MyWallet',
  maxFragmentLength: 120,
));
```

Raising it above 180 is the wrong direction: denser QR codes fail earlier than
long animations do.

**[QR tuning](../advanced/qr-tuning.md)** covers frame rate against fragment
size, error correction, and what to do when a specific screen or camera
misbehaves.

---

Next: **[4. Scan the signature](04-scan-signature.md)** — read the device's
reply and turn it into a typed result.
