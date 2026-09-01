import 'dart:typed_data';

import '../core/bytes.dart';
import '../crypto/digests.dart';
import '../crypto/secp256k1.dart';
import 'result.dart';

/// Inputs for [verifyXrpSignature].
class VerifyXrpSignatureArgs {
  const VerifyXrpSignatureArgs({
    required this.signedTx,
    required this.expectedSigningPubKey,
  });

  /// The signed binary transaction from the reply.
  final Uint8List signedTx;

  /// The `SigningPubKey` hex your request JSON carried (33-byte compressed
  /// secp256k1).
  final String expectedSigningPubKey;
}

/// XRP has no request id — this check IS the binding. The signed binary is
/// split into its canonical fields; `TxnSignature` is removed; the remainder
/// (prefixed with the XRPL signing tag `STX\0`) is hashed with SHA-512-half
/// and the DER signature is verified against `SigningPubKey`, which must also
/// equal the key your request carried.
///
/// The field walker covers the types Payment-class transactions use; a
/// transaction carrying an exotic field type comes back `checked: false`
/// rather than a false verdict.
VerifyResult verifyXrpSignature(VerifyXrpSignatureArgs args) {
  List<_XrpField> fields;
  try {
    fields = _splitFields(args.signedTx);
  } on _WalkError catch (e) {
    if (e.message == 'unsupported-field') {
      return unverifiable(
          'the transaction carries a field type this checker does not walk');
    }
    return failed('the signed transaction is not readable: ${e.message}');
  }

  _XrpField? signingPubKey;
  _XrpField? txnSignature;
  for (final f in fields) {
    if (f.header == 0x73) signingPubKey ??= f;
    if (f.header == 0x74) txnSignature ??= f;
  }
  if (signingPubKey == null || txnSignature == null) {
    return failed(
        'the signed transaction is missing SigningPubKey or TxnSignature');
  }
  final expected = hexToBytes(args.expectedSigningPubKey);
  if (!equalBytes(signingPubKey.value, expected)) {
    return failed(
      'the transaction was signed with a different key (${bytesToHex(signingPubKey.value)})',
    );
  }

  // Signing payload: every field except TxnSignature, in the original
  // (canonical) order, behind the 'STX\0' prefix; SHA-512 halved.
  final payload = concatBytes([
    Uint8List.fromList([0x53, 0x54, 0x58, 0x00]),
    for (final f in fields)
      if (f.header != 0x74) f.raw,
  ]);
  final digest = Uint8List.sublistView(sha512(payload), 0, 32);

  bool ok;
  try {
    ok = Secp256k1.verify(_derToCompact(txnSignature.value), digest, expected);
  } on Object catch (e) {
    return failed('XRP signature could not be checked: $e');
  }
  return ok
      ? verified
      : failed('the signature does not verify against SigningPubKey');
}

/// One top-level field of the canonical STObject.
class _XrpField {
  const _XrpField({
    required this.header,
    required this.value,
    required this.raw,
  });

  /// One-byte header for the common fields (0x73 SigningPubKey, 0x74
  /// TxnSignature).
  final int header;

  /// The field's VALUE bytes (VL prefix stripped for blob-like types).
  final Uint8List value;

  /// The complete encoded field, header + length + value.
  final Uint8List raw;
}

/// A structural refusal from the walker (mirrors the reference SDK's plain
/// `Error` messages, `unsupported-field` included).
class _WalkError implements Exception {
  const _WalkError(this.message);

  final String message;

  @override
  String toString() => message;
}

/// Split a canonical STObject into its top-level fields.
List<_XrpField> _splitFields(Uint8List bytes) {
  final fields = <_XrpField>[];
  var pos = 0;
  while (pos < bytes.length) {
    final field = _parseField(bytes, pos);
    fields.add(field.field);
    pos = field.end;
  }
  return fields;
}

class _ParsedField {
  const _ParsedField(this.field, this.end);

  final _XrpField field;
  final int end;
}

/// Nesting ceiling for inner objects/arrays. Real XRPL transactions nest a
/// handful of levels; a hostile reply nesting thousands would otherwise
/// overflow the call stack, and a StackOverflowError is not catchable the
/// way the reference SDK's engine RangeError is — refuse instead.
const int _maxFieldDepth = 32;

/// Parse ONE field at `pos`; returns the field and the offset past it.
_ParsedField _parseField(Uint8List bytes, int pos, [int depth = 0]) {
  if (depth > _maxFieldDepth) throw const _WalkError('nesting too deep');
  final start = pos;
  if (pos >= bytes.length) throw const _WalkError('truncated');
  final first = bytes[pos++];
  var type = first >> 4;
  var fieldCode = first & 0x0f;
  if (type == 0) {
    if (pos >= bytes.length) throw const _WalkError('truncated type');
    type = bytes[pos++];
  }
  if (fieldCode == 0) {
    if (pos >= bytes.length) throw const _WalkError('truncated field code');
    fieldCode = bytes[pos++];
  }

  var valueStart = pos;
  switch (type) {
    case 1: // UInt16
      pos += 2;
    case 2: // UInt32
      pos += 4;
    case 5: // Hash256
      pos += 32;
    case 6:
      // Amount: native XRP = 8 bytes; issued currency = 48 bytes.
      if (pos >= bytes.length) throw const _WalkError('truncated amount');
      final head = bytes[pos];
      pos += (head & 0x80) != 0 ? 48 : 8;
    case 7: // Blob (VL)
    case 8:
      // AccountID (VL)
      final vl = _readVl(bytes, pos);
      valueStart = vl.next;
      pos = vl.next + vl.length;
    case 14:
      // STObject: nested fields until the end marker 0xE1.
      while (pos >= bytes.length || bytes[pos] != 0xe1) {
        if (pos >= bytes.length) {
          throw const _WalkError('unterminated inner object');
        }
        pos = _parseField(bytes, pos, depth + 1).end;
      }
      pos += 1;
    case 15:
      // STArray: a sequence of inner-object fields until 0xF1.
      while (pos >= bytes.length || bytes[pos] != 0xf1) {
        if (pos >= bytes.length) throw const _WalkError('unterminated array');
        pos = _parseField(bytes, pos, depth + 1).end;
      }
      pos += 1;
    default:
      throw const _WalkError('unsupported-field');
  }
  if (pos > bytes.length) throw const _WalkError('truncated field');
  return _ParsedField(
    _XrpField(
      header: (type << 4) | (fieldCode <= 15 ? fieldCode : 0),
      value: bytes.sublist(valueStart, pos),
      raw: bytes.sublist(start, pos),
    ),
    pos,
  );
}

class _VlPrefix {
  const _VlPrefix(this.length, this.next);

  final int length;
  final int next;
}

/// XRPL variable-length prefix.
_VlPrefix _readVl(Uint8List bytes, int pos) {
  if (pos >= bytes.length) throw const _WalkError('truncated length');
  final b1 = bytes[pos];
  if (b1 <= 192) return _VlPrefix(b1, pos + 1);
  if (b1 <= 240) {
    if (pos + 1 >= bytes.length) throw const _WalkError('truncated length');
    final b2 = bytes[pos + 1];
    return _VlPrefix(193 + (b1 - 193) * 256 + b2, pos + 2);
  }
  if (pos + 2 >= bytes.length) throw const _WalkError('truncated length');
  final b2 = bytes[pos + 1];
  final b3 = bytes[pos + 2];
  return _VlPrefix(12481 + (b1 - 241) * 65536 + b2 * 256 + b3, pos + 3);
}

/// Strict DER `SEQUENCE(INTEGER r, INTEGER s)` → 64-byte compact `r || s` —
/// the same acceptance rules as the reference SDK's `Signature.fromDER`:
/// exact length accounting, positive integers, minimal encoding (a leading
/// zero byte only where the next byte would read as a sign bit).
Uint8List _derToCompact(Uint8List der) {
  if (der.length < 8 || der[0] != 0x30) {
    throw ArgumentError('signature is not a DER sequence');
  }
  if (der[1] >= 0x80 || der[1] != der.length - 2) {
    throw ArgumentError('DER sequence has a wrong length');
  }
  var pos = 2;

  Uint8List readInteger() {
    if (pos + 2 > der.length || der[pos] != 0x02) {
      throw ArgumentError('DER integer expected');
    }
    final length = der[pos + 1];
    pos += 2;
    if (length == 0 || length >= 0x80 || pos + length > der.length) {
      throw ArgumentError('DER integer has a wrong length');
    }
    var value = Uint8List.sublistView(der, pos, pos + length);
    pos += length;
    if ((value[0] & 0x80) != 0) {
      throw ArgumentError('DER integer is negative');
    }
    if (value.length > 1 && value[0] == 0x00) {
      if ((value[1] & 0x80) == 0) {
        throw ArgumentError('DER integer is not minimal');
      }
      value = Uint8List.sublistView(value, 1);
    }
    if (value.length > 32) {
      throw ArgumentError('DER integer is wider than 32 bytes');
    }
    return value;
  }

  final r = readInteger();
  final s = readInteger();
  if (pos != der.length) {
    throw ArgumentError('DER sequence has trailing bytes');
  }
  final compact = Uint8List(64);
  compact.setAll(32 - r.length, r);
  compact.setAll(64 - s.length, s);
  return compact;
}
