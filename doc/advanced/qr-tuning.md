# QR tuning

Fragment size, frame rate, progress and timeouts. The defaults are the numbers
the device itself uses; change them only with a reason, and change the scan
timeout first.

## The two legs are not symmetric

`DeviceProfile` (exported from the root library) carries the timing and size
constants of the device's own QR pipeline:

```dart
DeviceProfile.phoneToDevice   // fragmentBytesOnWire 200, payloadBytes 180, frameIntervalMs 125
DeviceProfile.deviceToPhone   // fragmentBytesOnWire 150,                   frameIntervalMs 400
```

| Direction | Bytes per frame | Interval | Rate |
|---|---|---|---|
| Phone → device (your request) | 180 payload, ~200 on the wire | 125 ms | 8 fps |
| Device → phone (the reply) | 150 on the wire | 400 ms | 2.5 fps |

**Receiving is more than three times slower than sending.** The device draws
its reply on a small screen at 2.5 fps; your phone reads it with a camera whose
autofocus and exposure are also part of the loop. Every timeout you write for
the reply leg has to be budgeted against 400 ms per frame, not against the
125 ms you send at.

`QrLegProfile.payloadBytes` is null on the device leg: how the device splits
its own payload is its business. Estimate its frame count from the wire size
minus the fountain header — about 134 usable bytes per frame — and round up.

## Sending: fragment size

`AnimatedUr` fragments and animates. The payload budget per fragment is
`defaultFragmentLength`, 180 bytes, and the on-wire frame adds a ~16-byte CBOR
fountain header on top of it — which is where the 200-byte figure comes from.

Three places set it, narrowest wins:

```dart
// 1. For the whole app:
final era = EraConnect(const EraConnectConfig(
  origin: 'MyWallet',
  maxFragmentLength: 140,
));

// 2. For one request:
final animated = request.toAnimated(
  const AnimatedUrOptions(maxFragmentLength: 140),
);

// 3. For a raw UR:
final frames = era.raw.animate(ur, const AnimatedUrOptions(maxFragmentLength: 140));
```

The encoder does not chop at exactly `maxFragmentLength`. It picks the
**largest even split that fits** — the smallest fragment count whose
`ceil(payload / count)` is within the ceiling — and zero-pads the last
fragment to the common length. A 1024-byte request at the default becomes six
fragments of 171 bytes, not five of 180 and one of 124. The receiving side's
header consistency check assumes exactly this relation, so the split is not a
free parameter.

A payload that fits one fragment is emitted as a plain single-part `ur:`
string on every call, never as a `1-1` sequence. Check `isSingleFrame` if you
want to draw a static QR instead of running a timer.

```dart
final animated = request.toAnimated();
animated.isSingleFrame;   // bool
animated.fragmentCount;   // source fragments (1 when single-part)
animated.urType;          // 'eth-sign-request'
animated.nextFrame();     // the next uppercase wire frame
animated.toString();      // the whole UR as one lowercase string — for logs, not for screens
```

Frames come back **uppercase** so your QR encoder can pick alphanumeric mode,
which is about 45% denser than byte mode. If your QR widget lowercases or
re-encodes the string, you lose that and the codes get visibly denser for no
reason.

### When to lower it

Bytewords spends two letters per byte and appends a CRC32, so a default frame
is roughly 420 alphanumeric characters — around QR version 11 at error
correction M. That is a comfortably scannable code on a good camera and a
marginal one on a cheap sensor, a scratched screen protector, or a phone held
at an angle in bad light.

Lower `maxFragmentLength` when:

- test devices show slow or failed acquisition — a fragment of 120 bytes lands
  around version 9, which forgives much more;
- your QR widget renders small (a modal, a watch-sized target);
- you are printing the code rather than displaying it.

The cost is linear: halving the fragment roughly doubles the frame count and
the time for one full pass. That is usually the right trade, because a dense
code that needs five passes is slower than a sparse code that needs one.

Do not raise it above the default. The device's camera is the constraint at
the other end, and it was tuned for ~200 bytes on the wire.

### Loop the animation, do not stop it

The encoder is a fountain: after the first `fragmentCount` frames it keeps
emitting mixed frames indefinitely, and any receiver that missed a frame
recovers from later ones without restarting. Drive `nextFrame()` from a
repeating timer for as long as the request is on screen. Stopping after
`fragmentCount` frames strands a receiver that blinked.

## Receiving: progress you can trust

`UrScanner.receivePart` returns one of four results per frame:

```dart
switch (scanner.receivePart(frameText)) {
  case ScanComplete(:final ur):     // assembled
  case ScanProgress(:final progress, :final framesReceived, :final framesExpected):
  case ScanDuplicate():             // seen this exact frame already
  case ScanRejected(:final rejection):  // rejection.code, .message, .repeated
}
```

`framesExpected` is what the **bound stream declares** in its header, and
`framesReceived` is how many distinct **source** fragments have actually been
recovered. Those are not the number of frames the camera has read, and the
gap between them is not a bug:

- a fountain frame may be an XOR of several source fragments, so one frame can
  advance the counter by more than one, or by none at all;
- duplicates and rejected frames advance nothing;
- until a stream binds, `framesExpected` is 0 and `progress` is 0, however many
  frames have passed the lens.

So render progress as a **fraction that may stall**, never as a countdown or an
ETA. "4 of 7 parts" is honest. "3 seconds remaining" is a guess that will be
wrong, and the ugly failure mode is a bar that reaches 90% and sits there while
the user assumes it has crashed.

`rejection.repeated` counts consecutive identical rejections. A static hostile
or malformed QR in the frame produces the same rejection at camera framerate;
show it once and let the counter grow, rather than logging it ten times a
second.

### Scan timeouts

Budget from the reply leg's 400 ms, not from your own frame rate, and budget
several passes: the first pass usually loses frames to focus and framing.

| Reply payload | ≈ frames | One clean pass | Sensible timeout |
|---|---|---|---|
| A signature reply (~100 B) | 1 — static | instant | a few seconds |
| 1 KiB (witness set, small PSBT) | 8 | ~3 s | 30 s |
| 4 KiB (larger PSBT, compressed result) | 31 | ~12 s | 60 s |
| 16 KiB | 123 | ~49 s | 120 s+, and warn the user it is long |

Most replies are one frame: an `eth-signature` or a `sol-signature` is under
120 bytes and is drawn as a single static QR. The multi-frame cases are signed
PSBTs, Cardano witness sets and the compressed Tron and Bitcoin Cash results.

Two more things stretch the first pass, both by design:

- a stream binds only **provisionally** on its first fragment and is confirmed
  by a second distinct fragment of the same stream. A genuine animation
  confirms on its very next frame;
- a provisional binding is dropped after 32 non-matching frames, so a hostile
  static QR competing for the camera costs a moment, not the session.

## Transport ceilings

`UrLimits` bounds every field a scanned fragment can dictate, before that field
sizes an allocation or a loop. Sixty characters of QR would otherwise be able
to ask your app for gigabytes.

| Limit | Value | Meaning |
|---|---|---|
| `UrLimits.maxMessageBytes` | 65 536 | Largest reassembled UR payload |
| `UrLimits.maxFragmentCount` | 2 048 | Largest declared source-fragment count |
| `UrLimits.maxFragmentBytes` | 4 096 | Largest single fragment (QR v40 tops out at 2 953) |
| `UrLimits.maxUint32` | 4 294 967 295 | Ceiling for `seqNum` and `checksum` |

These are generous headroom over real traffic, not tight protocol bounds — a
cap that refuses a genuine reply is worse than the denial of service it
prevents. A fragment whose header is internally inconsistent (its declared
message length cannot be produced by its declared fragment count and size) is
dropped before the fountain index derivation pays for anything.

The practical consequence for tuning: a request larger than 64 KiB cannot be
assembled at the other end, and a `maxFragmentLength` above 4 096 produces
frames no conforming receiver will accept. Neither is reachable with sane
transactions.
