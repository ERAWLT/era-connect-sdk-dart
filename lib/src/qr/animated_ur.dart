import '../ur/encoder.dart';
import '../ur/ur.dart';

/// Options for [AnimatedUr].
class AnimatedUrOptions {
  const AnimatedUrOptions({this.maxFragmentLength});

  /// Payload bytes per fountain fragment. The on-wire frame adds a ~16-byte
  /// CBOR header, so the default 180 keeps frames within the ~200-byte
  /// per-fragment ceiling hardware-wallet cameras scan reliably. Larger
  /// fragments mean fewer frames but denser QR codes.
  final int? maxFragmentLength;
}

/// Default payload bytes per animated-QR fragment.
const int defaultFragmentLength = 180;

/// Frame source for rendering a UR as an animated QR.
///
/// Drive [nextFrame] from your own ticker (~8 fps is the battle-tested
/// default) and hand each string to your QR component. Frames are UPPERCASE so
/// the QR encoder can use alphanumeric mode (~45% denser than byte mode).
class AnimatedUr {
  AnimatedUr(Ur ur, [AnimatedUrOptions? options])
      : _encoder = UrFountainEncoder(
          ur,
          options?.maxFragmentLength ?? defaultFragmentLength,
        );

  final UrFountainEncoder _encoder;

  /// Whether the payload fits one QR (no animation needed).
  bool get isSingleFrame => _encoder.isSinglePart;

  /// The UR registry type being sent, e.g. `eth-sign-request`.
  String get urType => _encoder.ur.type;

  /// How many source fragments the payload was split into.
  int get fragmentCount => _encoder.fragmentCount;

  /// Next wire frame (uppercase). Single-frame payloads return the same
  /// string every call.
  String nextFrame() => _encoder.nextPart();

  /// The whole request as ONE lowercase `ur:` string — the loggable form, not
  /// what is on screen.
  @override
  String toString() => _encoder.ur.toString();
}
