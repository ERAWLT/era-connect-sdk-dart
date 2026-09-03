import 'dart:typed_data';

import '../cbor/decode.dart';
import '../cbor/model.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../qr/animated_ur.dart';
import '../scan/ur_scanner.dart';
import '../ur/ur.dart';

/// SDK configuration. Everything is optional; the SDK performs NO network
/// I/O ever.
class EraConnectConfig {
  const EraConnectConfig({
    this.origin,
    this.randomBytes,
    this.maxFragmentLength,
  });

  /// Wallet name the device shows the user on every request ("Sign for
  /// `<origin>`?"). Set it once here; individual requests can override.
  final String? origin;

  /// CSPRNG override. By default `Random.secure()` is used; on platforms
  /// without one, inject a secure source here. Request-id minting throws
  /// `no-secure-random` when neither is available.
  final RandomBytesFn? randomBytes;

  /// Default payload bytes per animated-QR fragment (180 unless overridden).
  final int? maxFragmentLength;
}

/// Resolved SDK configuration handed to every chain module.
///
/// Implements [EraConnectConfig] so [resolveContext] accepts either (the
/// the wire accepts either form).
class ChainContext implements EraConnectConfig {
  const ChainContext({
    required this.origin,
    this.randomBytes,
    required this.maxFragmentLength,
  });

  @override
  final String origin;

  @override
  final RandomBytesFn? randomBytes;

  @override
  final int maxFragmentLength;
}

/// The origin shown on the device when the config does not name one.
const String defaultOrigin = 'ERA Connect';

/// Resolve a (possibly absent) config into the context chain modules consume.
ChainContext resolveContext([EraConnectConfig? config]) {
  return ChainContext(
    origin: config?.origin ?? defaultOrigin,
    randomBytes: config?.randomBytes,
    maxFragmentLength: config?.maxFragmentLength ?? defaultFragmentLength,
  );
}

/// Optional expectations when parsing a reply standalone (outside
/// [SignRequest.scanner]).
class ExpectedReply {
  const ExpectedReply({this.requestId});

  /// The request id the reply must echo: 16 raw bytes ([Uint8List]) or a
  /// UUID [String].
  final Object? requestId;
}

/// A built sign request: the UR to display plus everything needed to consume
/// the reply. The request id is minted at CONSTRUCTION so the same object
/// that renders the QR also validates the echo — a reply carrying a different
/// id (from an earlier, cancelled flow re-presented to the camera) is refused
/// instead of accepted.
class SignRequest<TResult> {
  SignRequest({
    required this.ur,
    this.requestId,
    required this.replyTypes,
    this.warnings = const [],
    required ChainContext context,
    required TResult Function(Ur ur) parse,
  })  : _context = context,
        _parse = parse;

  /// The UR to display.
  final Ur ur;

  /// Absent only where the protocol has no request id (Bitcoin PSBT).
  final Uint8List? requestId;

  /// UR types that can answer THIS request.
  final List<String> replyTypes;

  /// Non-fatal advisories (e.g. `blind-sign-threshold`).
  final List<String> warnings;

  final ChainContext _context;
  final TResult Function(Ur ur) _parse;

  /// Fragment + animate for display.
  AnimatedUr toAnimated([AnimatedUrOptions? options]) {
    return AnimatedUr(
      ur,
      AnimatedUrOptions(
        maxFragmentLength:
            options?.maxFragmentLength ?? _context.maxFragmentLength,
      ),
    );
  }

  /// A scanner pre-pinned to [replyTypes]; its `parse()` validates the
  /// request-id echo.
  TypedUrScanner<TResult> scanner() {
    return TypedUrScanner<TResult>(
      UrScannerOptions(expectedTypes: replyTypes),
      _parse,
    );
  }
}

/// Build a [SignRequest]: the UR to display, plus the reply plumbing.
SignRequest<TResult> makeSignRequest<TResult>({
  required Ur ur,
  Uint8List? requestId,
  required List<String> replyTypes,
  List<String>? warnings,
  required ChainContext context,
  required TResult Function(Ur ur) parse,
}) {
  return SignRequest<TResult>(
    ur: ur,
    requestId: requestId,
    replyTypes: replyTypes,
    warnings: warnings ?? const [],
    context: context,
    parse: parse,
  );
}

/// Mint or normalize a request id ([Uint8List], UUID [String], or null to
/// mint).
Uint8List resolveRequestId(ChainContext context, Object? requestId) {
  return requestId == null
      ? randomRequestId(context.randomBytes)
      : normalizeRequestId(requestId);
}

/// Accept a reply as a [Ur] object or a single-part `ur:` string.
Ur toUr(Object input) {
  if (input is Ur) return input;
  if (input is String) {
    final parsed = parseUrString(input);
    if (parsed.seq != null) {
      throw EraSdkError(
        'invalid-props',
        'multi-part UR string: assemble it with the request scanner first',
      );
    }
    return Ur(parsed.type, parsed.payload);
  }
  throw EraSdkError('invalid-props', 'reply must be a Ur or a ur: string');
}

// ---------------------------------------------------------------------------
// Reply checks: what every `*-signature` must pass before it is a signature.
// ---------------------------------------------------------------------------

/// The reply UR must be one of the [expected] types.
void requireUrType(Ur ur, List<String> expected, String what) {
  if (!expected.contains(ur.type)) {
    // Attacker-sized string — truncate before it reaches a message.
    final shown =
        ur.type.length > 32 ? '${ur.type.substring(0, 32)}…' : ur.type;
    throw EraSdkError(
      'wrong-ur-type',
      'unexpected $what UR type "$shown", expected ${expected.join(' or ')}',
    );
  }
}

/// The reply payload must decode to a CBOR map.
CborValue requireReplyMap(Ur ur, String what) {
  CborValue decoded;
  try {
    decoded = cborDecode(ur.cbor);
  } on EraSdkError catch (e) {
    throw EraSdkError(
        'malformed-cbor', '$what is not readable CBOR: ${e.message}');
  } catch (e) {
    throw EraSdkError('malformed-cbor', '$what is not readable CBOR: $e');
  }
  final map = asMap(decoded);
  if (map == null) {
    throw EraSdkError('malformed-reply', '$what is not a CBOR map');
  }
  return map;
}

/// The reply must echo the request id byte for byte.
///
/// BYTES, not CBOR values: the device wraps the echo in the UUID tag (37)
/// while requests may send it untagged, so a value-level comparison would
/// reject every genuine reply. An absent echo is a reply that did not come
/// from the request in hand (the device echoes unconditionally when the
/// request carried an id) and is refused rather than tolerated.
Uint8List requireRequestIdEcho(
  CborValue map,
  int key,
  Uint8List? expected,
  String what,
) {
  final echoed = mapGet(map, key);
  final value = echoed == null ? null : stripTags(echoed);
  if (value is! CborBytes) {
    throw EraSdkError(
        'malformed-reply', '$what does not echo the request id (key $key)');
  }
  if (expected != null && !equalBytes(value.value, expected)) {
    throw EraSdkError(
      'request-id-mismatch',
      '$what echoes a different request id — it answers another sign request, not this one',
    );
  }
  return value.value;
}

/// A signature whose length is inside `[min, max]`, or a typed refusal.
Uint8List requireSignatureBytes(
  CborValue? value,
  String what,
  int min,
  int max,
) {
  final v = value == null ? null : stripTags(value);
  if (v is! CborBytes) {
    throw EraSdkError(
        'malformed-reply', '$what is missing the signature (key 2)');
  }
  final length = v.value.length;
  if (length < min || length > max) {
    throw EraSdkError(
      'malformed-reply',
      '$what signature is $length bytes, expected ${min == max ? '$min' : '$min-$max'}',
    );
  }
  return v.value;
}
