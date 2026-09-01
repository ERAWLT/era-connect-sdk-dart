/// Every error thrown by this SDK.
///
/// [code] is stable API and mirrors the TypeScript SDK's `EraErrorCode`
/// union verbatim — integrators branch on it, never on [message] (messages
/// are for humans and may change). The closed set of codes:
///
/// `no-secure-random`, `not-a-ur`, `wrong-ur-type`, `malformed-bytewords`,
/// `checksum-mismatch`, `malformed-cbor`, `malformed-sequence`,
/// `fragment-mismatch`, `limit-exceeded`, `incomplete-scan`,
/// `request-id-mismatch`, `account-not-found`, `invalid-props`,
/// `empty-signature`, `malformed-reply`, `gzip-error`, `protobuf-error`,
/// `verification-failed`.
class EraSdkError implements Exception {
  EraSdkError(this.code, this.message);

  /// Stable machine-readable code from the closed set above.
  final String code;

  /// Human-readable explanation. Not stable API.
  final String message;

  @override
  String toString() => 'EraSdkError($code): $message';
}
