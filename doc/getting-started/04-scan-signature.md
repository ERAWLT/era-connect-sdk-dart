# 4. Scan the signature

The device signs, then shows its reply as its own animated QR. You feed those
frames back and get a typed result.

## Two scanners

| Call | Returns | Use it for |
|---|---|---|
| `request.scanner()` | `TypedUrScanner<T>` pinned to `request.replyTypes` | Every sign reply. `parse()` assembles, checks the UR type, enforces the request-id echo and returns the chain's result type |
| `era.scanner(options)` | `UrScanner` | Linking, `raw` flows, anything with no `SignRequest` behind it. Assembles a `Ur`; you parse it yourself |

Prefer `request.scanner()` whenever a request exists. It is the only path where
the reply is bound to the request you actually built.

```dart
final scanner = request.scanner();
```

## Feed frames

`receivePart` is synchronous and **never throws** — it is safe to call straight
from a camera callback. Every outcome comes back as a value:

```dart
void onFrame(String text) {
  switch (scanner.receivePart(text)) {
    case ScanComplete():
      final signature = scanner.parse();   // typed, validated — see below
      onSigned(signature);

    case ScanProgress(:final progress, :final framesReceived, :final framesExpected):
      showProgress(progress, '$framesReceived / $framesExpected');

    case ScanRejected(:final rejection):
      // A static bad QR produces this at camera framerate. Log the FIRST one.
      if (rejection.repeated == 1) log(rejection.code, rejection.message);

    case ScanDuplicate():
      break;   // the camera re-read a frame it already had
  }
}
```

`ScanFeedResult` is sealed, so the switch is exhaustive and the compiler will
tell you if a case goes missing.

The same state is readable outside the switch, which is what a progress widget
usually wants:

```dart
scanner.isComplete;       // bool
scanner.progress;         // 0.0 .. 1.0
scanner.urType;           // the bound stream's type, null until one binds
scanner.framesReceived;
scanner.framesExpected;
scanner.lastRejection;    // ScanRejection? — code, message, repeated
```

`ScanRejection.repeated` counts consecutive identical rejections. A sticker on
a wall or a wrong screen in frame produces the same rejection ten times a
second; show it once.

## Budget the time

The device-to-phone leg is the slow one: **150-byte fragments at 400 ms
(2.5 fps)** — a third the rate of what you send.

```dart
DeviceProfile.deviceToPhone.fragmentBytesOnWire; // 150
DeviceProfile.deviceToPhone.frameIntervalMs;     // 400
```

A ten-fragment reply therefore needs four seconds of clean frames at the
theoretical minimum, and real scanning costs more because the fountain does not
hand out the fragments in order. Size scan timeouts in tens of seconds, not in
the two or three that feel right for a barcode.

## What the scanner refuses, and why

A QR in the camera frame is attacker-controlled input: a sticker, a second
screen, a poster. The scanner is built for that, and turns work away before it
becomes expensive.

- **Type pinning happens before any decoding.** A frame whose `ur:<type>/`
  prefix is not in `expectedTypes` is dropped without touching the fountain
  decoder (`wrong-ur-type`). `request.scanner()` pins this for you.
- **Header bounds are checked before allocation.** A fragment header declares a
  message length, a fragment count and a fragment size, and those numbers size
  arrays and loops. They are validated against `UrLimits` — 64 KiB assembled,
  2048 fragments, 4096 bytes per fragment — first, so sixty characters of QR
  cannot ask your process for gigabytes (`limit-exceeded`).
- **Stream binding needs a second, distinct fragment.** The first fragment of
  a stream binds only *provisionally*; the confirmation is a different fragment
  of the same stream. A single static image cannot confirm itself, so a hostile
  QR cannot hijack an assembly that is already under way. Once a stream is
  confirmed, foreign fragments are refused outright, and a single-part UR
  arriving mid-assembly is refused too (`fragment-mismatch`).
- **Frames are deduplicated**, with a cap on how many are remembered, and junk
  that never reached the decoder cannot fill that budget.
- **Rejection messages never carry frame contents.** Attacker-sized strings
  are truncated, and a wallet export's own bytes never reach a log line.

None of this is fatal to a session. A rejection means "that frame was not for
me" — keep scanning.

## Parse

```dart
final signature = scanner.parse();   // EvmSignatureResult for an EVM request
```

`parse()` does four things in one call: it assembles the UR, checks that the
type is one of the request's `replyTypes`, checks that the reply echoes the
request id **byte for byte**, and decodes the chain's result. Any of those
failing throws `EraSdkError` — this is the throwing path, unlike the feed.

The echo is compared as bytes, not as CBOR values, because the device wraps it
in the UUID tag while some requests send it untagged; a value-level comparison
would reject every genuine reply. A reply that carries no echo at all is
refused rather than tolerated.

Standalone parsing exists on every chain module
(`era.evm.parseSignature(ur, ExpectedReply(requestId: id))`), for when the
reply arrives detached from the request that produced it. Pass the id, or the
echo is returned unvalidated and you have thrown away the binding.

## Error codes to branch on

`EraSdkError.code` is stable API; `message` is for humans and may change. The
closed set, and what each one means for the person holding the phone:

| Code | Where | Meaning |
|---|---|---|
| `not-a-ur` | feed | The frame is not a `ur:` string at all. Some other barcode is in view. Keep scanning |
| `wrong-ur-type` | feed, parse | A UR of a type this scanner is not pinned to. Usually the wrong screen on the device, or the wallet export shown to a signature scanner |
| `malformed-bytewords` | feed | The frame body is not bytewords. A misread; keep scanning |
| `checksum-mismatch` | feed | Bytewords CRC failed — the frame was captured mid-refresh. Keep scanning |
| `malformed-sequence` | feed | The `n-m` sequence segment is unreadable. Keep scanning |
| `fragment-mismatch` | feed | The frame belongs to a different stream than the assembly under way. Two screens in view, or a stale QR left on the device |
| `limit-exceeded` | feed, parse | A header or payload outside `UrLimits`, or a Tron/BCH compressed reply over its ceiling. Not a frame you want to process |
| `incomplete-scan` | parse | `result()` or `parse()` was called before assembly finished. A bug in the calling code |
| `request-id-mismatch` | parse | The reply answers **another** sign request. Show the request again; do not broadcast anything |
| `malformed-cbor` | parse | The assembled payload is not readable CBOR |
| `malformed-reply` | parse | Readable CBOR, wrong shape: a missing field, a signature of the wrong length, an implausible recovery value |
| `empty-signature` | parse | Bitcoin message signing only — see below |
| `gzip-error` | parse | A Tron or Bitcoin Cash reply failed to inflate, or exceeded the inflation ceiling |
| `protobuf-error` | parse | The protobuf inside a Tron or Bitcoin Cash reply is malformed |
| `account-not-found` | linking | The linked export has no account at that path, or no chain code to derive children with |
| `invalid-props` | build | Your inputs. A malformed path, a chain id out of range, a 19-byte address, an empty payload |
| `no-secure-random` | build | The platform has no CSPRNG. Pass `randomBytes` in `EraConnectConfig` |
| `verification-failed` | — | Declared in the closed set, but the verify helpers return a verdict instead of throwing. Branch on `VerifyResult` (page 5), not on this code |

## `empty-signature`, per firmware generation

Bitcoin message signing is the one place where the device's answer depends on
which firmware it runs, and an empty signature is how it says "not this
address kind".

| Firmware | Signs | Answers with an empty signature |
|---|---|---|
| 2.1.0 and newer | BIP-44 (`1…`), BIP-49 (`3…`) and BIP-84 (`bc1q…`) addresses, each with the matching BIP-137 header | Taproot only — BIP-137 defines no header range for it |
| Older | Legacy P2PKH (`1…`) only | Every segwit address, nested or native |

So `empty-signature` on a Taproot address is expected on every firmware; on a
`bc1q…` or `3…` address it tells you the wallet is on an older build. Surface
it as "this address kind cannot be message-signed by this device", and offer
the legacy account if your UI has one.

The two generations also encode the answer differently — newer firmware sends
the raw 65-byte signature, older firmware sends the ASCII of a base64 string.
The SDK accepts both, so `BtcMessageSignatureResult.signature` is always the
raw 65 bytes and `signatureBase64` is always the base64 form. You do not branch
on this.

---

Next: **[5. Verify and broadcast](05-broadcast.md)** — the check that stands
between a signature and the network.
