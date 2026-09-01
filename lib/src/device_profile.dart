/// Timing/size constants of the device's own QR pipeline, for progress UI
/// and timeouts.
abstract final class DeviceProfile {
  /// What the phone displays to the device: ~200 wire bytes per frame at
  /// 8 fps.
  static const QrLegProfile phoneToDevice = QrLegProfile(
    fragmentBytesOnWire: 200,
    payloadBytes: 180,
    frameIntervalMs: 125,
  );

  /// What the device displays back: 150-byte fragments at 2.5 fps. Receiving
  /// is SLOWER than sending — budget scan timeouts accordingly.
  static const QrLegProfile deviceToPhone = QrLegProfile(
    fragmentBytesOnWire: 150,
    frameIntervalMs: 400,
  );
}

/// One direction of the QR pipeline.
class QrLegProfile {
  const QrLegProfile({
    required this.fragmentBytesOnWire,
    this.payloadBytes,
    required this.frameIntervalMs,
  });

  /// Bytewords-encoded bytes per displayed frame.
  final int fragmentBytesOnWire;

  /// CBOR payload bytes per fragment, where the leg defines it.
  final int? payloadBytes;

  /// Milliseconds between frames.
  final int frameIntervalMs;
}
