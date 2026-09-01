import 'dart:math';
import 'dart:typed_data';

import 'bytes.dart';
import 'errors.dart';

/// A caller-supplied CSPRNG. Must return exactly [length] bytes.
typedef RandomBytesFn = Uint8List Function(int length);

/// 16 unpredictable bytes for a sign request id.
///
/// A CSPRNG output, deliberately NOT a v4/v8 UUID: a UUID spends bits on the
/// wall clock and version fields, leaking the time of signing into the QR and
/// shrinking the unguessable part. The id is what a reply must echo to prove
/// it answers THIS request; it is formatted as a UUID string only where the
/// wire demands one (Tron's `signId`).
Uint8List randomRequestId([RandomBytesFn? randomBytes]) {
  if (randomBytes != null) {
    final out = randomBytes(16);
    if (out.length != 16) {
      throw EraSdkError(
          'no-secure-random', 'randomBytes(16) did not return 16 bytes');
    }
    return out;
  }
  final Random rng;
  try {
    rng = Random.secure();
  } on UnsupportedError {
    throw EraSdkError(
      'no-secure-random',
      'no secure random source on this platform: pass randomBytes in the EraConnect config',
    );
  }
  final out = Uint8List(16);
  for (var i = 0; i < out.length; i++) {
    out[i] = rng.nextInt(256);
  }
  return out;
}

/// Render 16 bytes as a lowercase hyphenated UUID string (8-4-4-4-12).
String uuidStringify(Uint8List bytes) {
  if (bytes.length != 16) {
    throw EraSdkError('invalid-props', 'request id must be 16 bytes');
  }
  final hex = bytesToHex(bytes);
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

final RegExp _hex32 = RegExp(r'^[0-9a-fA-F]{32}$');

/// Accept a request id as 16 raw bytes or a hyphenated/plain 32-hex string.
Uint8List normalizeRequestId(Object id) {
  if (id is Uint8List) {
    if (id.length != 16) {
      throw EraSdkError('invalid-props', 'request id must be 16 bytes');
    }
    return Uint8List.fromList(id);
  }
  if (id is String) {
    final hex = id.replaceAll('-', '');
    if (!_hex32.hasMatch(hex)) {
      throw EraSdkError(
          'invalid-props', 'request id string must be a 32-hex UUID');
    }
    return hexToBytes(hex.toLowerCase());
  }
  throw EraSdkError(
      'invalid-props', 'request id must be 16 bytes or a UUID string');
}
