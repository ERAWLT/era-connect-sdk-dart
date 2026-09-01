import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';
import 'encode.dart';
import 'model.dart';

/// Hardened CBOR decoder for scanned (attacker-controlled) payloads.
///
/// Policy, enforced as defaults rather than options:
///  - definite lengths only (indefinite refused);
///  - no floats, no simple values beyond bool/null;
///  - duplicate map keys refused;
///  - nesting depth capped;
///  - lengths bounds-checked before any allocation;
///  - trailing bytes after the top-level item refused.
///
/// Unknown tags are surfaced as [CborTag] wrappers, never dropped — the tag-37
/// request-id echo is compared tag-agnostically by the callers.
CborValue cborDecode(Uint8List bytes) {
  final reader = _Reader(bytes);
  final value = reader.readValue(0);
  if (reader.offset != bytes.length) {
    throw _err('trailing bytes after the top-level item');
  }
  return value;
}

const int _maxDepth = 16; // matches the encoder; see encode.dart

final BigInt _tagMax = BigInt.from(0xffffffff);

EraSdkError _err(String message) =>
    EraSdkError('malformed-cbor', 'cbor: $message');

class _Reader {
  _Reader(this.bytes);

  final Uint8List bytes;
  int offset = 0;

  CborValue readValue(int depth) {
    if (depth > _maxDepth) throw _err('nesting too deep');
    final initial = _readByte();
    final major = initial >>> 5;
    final info = initial & 0x1f;

    switch (major) {
      case 0:
        return CborUint(_readArg(info));
      case 1:
        return CborNegint(_readArg(info));
      case 2:
        final len = _readLength(info);
        return CborBytes(_readBytes(len));
      case 3:
        final len = _readLength(info);
        final raw = _readBytes(len);
        final String text;
        try {
          text = utf8Decode(raw);
        } on FormatException {
          throw _err('text string is not valid UTF-8');
        }
        return CborText(text);
      case 4:
        final len = _readLength(info);
        if (len > bytes.length - offset) {
          throw _err('array length exceeds input');
        }
        final items = <CborValue>[];
        for (var i = 0; i < len; i++) {
          items.add(readValue(depth + 1));
        }
        return CborArray(items);
      case 5:
        final len = _readLength(info);
        if (len * 2 > bytes.length - offset) {
          throw _err('map length exceeds input');
        }
        final entries = <(CborValue, CborValue)>[];
        final seenKeys = <String>{};
        for (var i = 0; i < len; i++) {
          final key = readValue(depth + 1);
          final keyId = bytesToHex(cborEncode(key));
          if (!seenKeys.add(keyId)) throw _err('duplicate map key');
          entries.add((key, readValue(depth + 1)));
        }
        return CborMap(entries);
      case 6:
        final tag = _readArg(info);
        if (tag > _tagMax) throw _err('tag exceeds 32 bits');
        return CborTag(tag.toInt(), readValue(depth + 1));
      case 7:
        if (info == 20) return const CborBool(false);
        if (info == 21) return const CborBool(true);
        if (info == 22) return const CborNull();
        throw _err('unsupported simple/float value (info $info)');
      default:
        throw _err('unreachable major type');
    }
  }

  int _readByte() {
    if (offset >= bytes.length) throw _err('truncated input');
    return bytes[offset++];
  }

  /// Argument of a head. Refuses indefinite (31) and reserved (28-30).
  BigInt _readArg(int info) {
    if (info < 24) return BigInt.from(info);
    if (info == 24) return BigInt.from(_readByte());
    if (info == 25) {
      final hi = _readByte();
      return BigInt.from((hi << 8) | _readByte());
    }
    if (info == 26) {
      var v = BigInt.zero;
      for (var i = 0; i < 4; i++) {
        v = (v << 8) | BigInt.from(_readByte());
      }
      return v;
    }
    if (info == 27) {
      var v = BigInt.zero;
      for (var i = 0; i < 8; i++) {
        v = (v << 8) | BigInt.from(_readByte());
      }
      return v;
    }
    if (info == 31) throw _err('indefinite lengths are refused');
    throw _err('reserved additional info $info');
  }

  int _readLength(int info) {
    final len = _readArg(info);
    if (len > BigInt.from(bytes.length - offset)) {
      throw _err('length exceeds input');
    }
    return len.toInt();
  }

  Uint8List _readBytes(int length) {
    final end = offset + length;
    final out = bytes.sublist(offset, end);
    offset = end;
    return out;
  }
}
