import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';
import 'model.dart';

/// Deterministic CBOR encoder: definite lengths only, minimal-width integer
/// heads, map entries in insertion order. This matches, byte for byte, what the
/// reference implementation produces and what the device firmware parses — the
/// exact bytes are pinned by golden-vector tests, which is why this encoder is
/// hand-rolled rather than delegated to a dependency's release cadence.
///
/// It deliberately cannot emit floats, indefinite lengths or exotic simple
/// values: the protocol never uses them.
Uint8List cborEncode(CborValue value) {
  final parts = <Uint8List>[];
  _writeValue(value, parts, 0);
  return concatBytes(parts);
}

// Deep enough for the deepest registry structure the SDK speaks (the
// qr-hardware-call tree nests 9 levels once tags and map entries are
// counted), with headroom; still a hard bound against recursion abuse.
const int _maxDepth = 16;

void _writeValue(CborValue value, List<Uint8List> parts, int depth) {
  if (depth > _maxDepth) {
    throw EraSdkError('malformed-cbor', 'cbor encode: nesting too deep');
  }
  switch (value) {
    case final CborUint v:
      parts.add(_head(0, v.value));
    case final CborNegint v:
      if (v.value < BigInt.zero) {
        throw EraSdkError('malformed-cbor', 'nint holds the magnitude');
      }
      parts.add(_head(1, v.value));
    case final CborBytes v:
      parts
        ..add(_head(2, BigInt.from(v.value.length)))
        ..add(v.value);
    case final CborText v:
      final utf8 = utf8Encode(v.value);
      parts
        ..add(_head(3, BigInt.from(utf8.length)))
        ..add(utf8);
    case final CborArray v:
      parts.add(_head(4, BigInt.from(v.items.length)));
      for (final item in v.items) {
        _writeValue(item, parts, depth + 1);
      }
    case final CborMap v:
      parts.add(_head(5, BigInt.from(v.entries.length)));
      for (final (k, e) in v.entries) {
        _writeValue(k, parts, depth + 1);
        _writeValue(e, parts, depth + 1);
      }
    case final CborTag v:
      parts.add(_head(6, BigInt.from(v.tag)));
      _writeValue(v.value, parts, depth + 1);
    case final CborBool v:
      parts.add(Uint8List.fromList([v.value ? 0xf5 : 0xf4]));
    case CborNull():
      parts.add(Uint8List.fromList([0xf6]));
  }
}

final BigInt _b24 = BigInt.from(24);
final BigInt _bU8Max = BigInt.from(0xff);
final BigInt _bU16Max = BigInt.from(0xffff);
final BigInt _bU32Max = BigInt.from(0xffffffff);
final BigInt _bU64Max = (BigInt.one << 64) - BigInt.one;

/// Major-type head with a minimal-width argument.
Uint8List _head(int major, BigInt arg) {
  if (arg < BigInt.zero) {
    throw EraSdkError('malformed-cbor', 'cbor head: negative argument');
  }
  final m = major << 5;
  if (arg < _b24) return Uint8List.fromList([m | arg.toInt()]);
  if (arg <= _bU8Max) return Uint8List.fromList([m | 24, arg.toInt()]);
  if (arg <= _bU16Max) {
    final n = arg.toInt();
    return Uint8List.fromList([m | 25, n >>> 8, n & 0xff]);
  }
  if (arg <= _bU32Max) {
    final n = arg.toInt();
    return Uint8List.fromList([
      m | 26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ]);
  }
  if (arg <= _bU64Max) {
    final out = Uint8List(9);
    out[0] = m | 27;
    var v = arg;
    for (var i = 8; i >= 1; i--) {
      out[i] = (v & _bU8Max).toInt();
      v >>= 8;
    }
    return out;
  }
  throw EraSdkError('malformed-cbor', 'cbor head: argument exceeds 64 bits');
}
