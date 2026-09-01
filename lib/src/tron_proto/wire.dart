import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';

/// Minimal protobuf wire codec for the Tron signing envelope. Varint and
/// length-delimited wire types only — the schema uses nothing else.
///
/// Writer semantics mirror the reference implementation: EXPLICITLY SET fields
/// are written even when they hold default values (a `timestamp` of 0 is
/// `tag, 0x00` on the wire), and fields are emitted in ascending field-number
/// order. Byte-exactness against the golden fixtures depends on both.
class ProtoWriter {
  final List<Uint8List> _parts = [];

  /// Append a varint (wire type 0) field.
  ProtoWriter varintField(int field, BigInt value) {
    _parts
      ..add(_tag(field, 0))
      ..add(varint(value));
    return this;
  }

  /// Append a UTF-8 string (wire type 2) field.
  ProtoWriter stringField(int field, String value) {
    final bytes = utf8Encode(value);
    _parts
      ..add(_tag(field, 2))
      ..add(varint(BigInt.from(bytes.length)))
      ..add(bytes);
    return this;
  }

  /// Append a raw bytes (wire type 2) field.
  ProtoWriter bytesField(int field, Uint8List value) {
    _parts
      ..add(_tag(field, 2))
      ..add(varint(BigInt.from(value.length)))
      ..add(value);
    return this;
  }

  /// Append an already-encoded sub-message (wire type 2) field.
  ProtoWriter messageField(int field, Uint8List encoded) {
    _parts
      ..add(_tag(field, 2))
      ..add(varint(BigInt.from(encoded.length)))
      ..add(encoded);
    return this;
  }

  /// The concatenated wire bytes of every appended field, in append order.
  Uint8List finish() {
    return concatBytes(_parts);
  }
}

Uint8List _tag(int field, int wireType) {
  return varint(BigInt.from((field << 3) | wireType));
}

/// Encode a non-negative integer as a protobuf base-128 varint.
Uint8List varint(BigInt value) {
  var v = value;
  if (v < BigInt.zero) {
    throw EraSdkError('protobuf-error', 'negative varint');
  }
  final out = <int>[];
  do {
    var byte = (v & BigInt.from(0x7f)).toInt();
    v >>= 7;
    if (v > BigInt.zero) byte |= 0x80;
    out.add(byte);
  } while (v > BigInt.zero);
  return Uint8List.fromList(out);
}

/// One decoded protobuf field, as [readFields] returns them.
class ProtoField {
  const ProtoField({
    required this.field,
    required this.wireType,
    required this.value,
    required this.bytes,
  });

  /// The field number (never 0).
  final int field;

  /// The wire type (0, 1, 2 or 5).
  final int wireType;

  /// Set for wire type 0.
  final BigInt value;

  /// Set for wire type 2 (verbatim slice of the input).
  final Uint8List bytes;
}

/// Hardened field reader: varint shift capped, lengths bounds-checked before
/// slicing, unknown fields skippable by wire type, group wire types refused.
List<ProtoField> readFields(Uint8List bytes) {
  final fields = <ProtoField>[];
  var offset = 0;

  BigInt readVarint() {
    var result = BigInt.zero;
    var shift = 0;
    for (;;) {
      if (offset >= bytes.length) {
        throw EraSdkError('protobuf-error', 'truncated varint');
      }
      final byte = bytes[offset];
      offset += 1;
      result |= BigInt.from(byte & 0x7f) << shift;
      if ((byte & 0x80) == 0) return result;
      shift += 7;
      if (shift > 63) {
        throw EraSdkError('protobuf-error', 'varint exceeds 64 bits');
      }
    }
  }

  while (offset < bytes.length) {
    final key = readVarint();
    final field = (key >> 3).toInt();
    final wireType = (key & BigInt.from(7)).toInt();
    if (field == 0) {
      throw EraSdkError('protobuf-error', 'field number 0');
    }
    switch (wireType) {
      case 0:
        fields.add(ProtoField(
          field: field,
          wireType: wireType,
          value: readVarint(),
          bytes: _empty,
        ));
      case 1:
        if (offset + 8 > bytes.length) {
          throw EraSdkError('protobuf-error', 'truncated fixed64');
        }
        fields.add(ProtoField(
          field: field,
          wireType: wireType,
          value: BigInt.zero,
          bytes: bytes.sublist(offset, offset + 8),
        ));
        offset += 8;
      case 2:
        final length = readVarint();
        if (length > BigInt.from(bytes.length - offset)) {
          throw EraSdkError(
            'protobuf-error',
            'length-delimited field exceeds input',
          );
        }
        final len = length.toInt();
        fields.add(ProtoField(
          field: field,
          wireType: wireType,
          value: BigInt.zero,
          bytes: bytes.sublist(offset, offset + len),
        ));
        offset += len;
      case 5:
        if (offset + 4 > bytes.length) {
          throw EraSdkError('protobuf-error', 'truncated fixed32');
        }
        fields.add(ProtoField(
          field: field,
          wireType: wireType,
          value: BigInt.zero,
          bytes: bytes.sublist(offset, offset + 4),
        ));
        offset += 4;
      default:
        throw EraSdkError('protobuf-error', 'unsupported wire type $wireType');
    }
  }
  return fields;
}

final Uint8List _empty = Uint8List(0);

/// First occurrence of a length-delimited field, or null.
Uint8List? firstBytes(List<ProtoField> fields, int field) {
  for (final f in fields) {
    if (f.field == field && f.wireType == 2) return f.bytes;
  }
  return null;
}

/// First occurrence of a varint field, or null.
BigInt? firstVarint(List<ProtoField> fields, int field) {
  for (final f in fields) {
    if (f.field == field && f.wireType == 0) return f.value;
  }
  return null;
}
