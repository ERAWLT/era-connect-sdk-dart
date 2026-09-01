/// Outcome of a verification helper. Helpers return, never throw, on
/// mismatches.
///
/// Mirrors the TypeScript SDK's discriminated union as a sealed class:
/// [Verified], [Unverifiable] (ok but nothing was checkable client-side) and
/// [Failed].
sealed class VerifyResult {
  const VerifyResult();

  /// Whether the reply is acceptable.
  bool get ok;

  /// Whether anything was actually verified ([Verified] only).
  bool get checked;

  /// Human-readable explanation for a failure or an unverifiable input;
  /// `null` when verified.
  String? get reason;
}

/// Verified cryptographically / byte-for-byte.
final class Verified extends VerifyResult {
  const Verified();

  @override
  bool get ok => true;

  @override
  bool get checked => true;

  @override
  String? get reason => null;
}

/// Nothing client-side is verifiable for this input (EIP-712 typed data: the
/// digest is the hash of the structure, which only the device computes).
/// The UR-type pin and the request-id echo are the whole binding.
final class Unverifiable extends VerifyResult {
  const Unverifiable(this.reason);

  @override
  bool get ok => true;

  @override
  bool get checked => false;

  @override
  final String reason;
}

/// The check ran and failed.
final class Failed extends VerifyResult {
  const Failed(this.reason);

  @override
  bool get ok => false;

  @override
  bool get checked => false;

  @override
  final String reason;
}

/// Verified cryptographically / byte-for-byte.
const VerifyResult verified = Verified();

/// The check ran and failed.
VerifyResult failed(String reason) => Failed(reason);

/// Nothing client-side is verifiable for this input.
VerifyResult unverifiable(String reason) => Unverifiable(reason);
