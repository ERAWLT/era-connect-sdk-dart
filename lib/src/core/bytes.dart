import 'dart:typed_data';

/// Byte helpers. `Uint8List` end-to-end; no `dart:io`, no platform channels.

Uint8List concatBytes(List<Uint8List> arrays) {
  var total = 0;
  for (final a in arrays) {
    total += a.length;
  }
  final out = Uint8List(total);
  var offset = 0;
  for (final a in arrays) {
    out.setAll(offset, a);
    offset += a.length;
  }
  return out;
}

/// Constant-shape byte equality (length check + full loop).
bool equalBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Big-endian unsigned 32-bit.
Uint8List u32be(int value) {
  final out = Uint8List(4);
  out[0] = (value >> 24) & 0xff;
  out[1] = (value >> 16) & 0xff;
  out[2] = (value >> 8) & 0xff;
  out[3] = value & 0xff;
  return out;
}

const String _hexChars = '0123456789abcdef';

String bytesToHex(Uint8List bytes) {
  final out = StringBuffer();
  for (final b in bytes) {
    out
      ..write(_hexChars[b >> 4])
      ..write(_hexChars[b & 0x0f]);
  }
  return out.toString();
}

Uint8List hexToBytes(String hex) {
  var h = hex;
  if (h.startsWith('0x') || h.startsWith('0X')) h = h.substring(2);
  if (h.length.isOdd) {
    throw const FormatException('hex string has odd length');
  }
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final byte = int.tryParse(h.substring(i * 2, i * 2 + 2), radix: 16);
    if (byte == null) {
      throw const FormatException('hex string has non-hex characters');
    }
    out[i] = byte;
  }
  return out;
}

/// Minimal-width big-endian bytes of a non-negative BigInt (`0` -> `[0]`).
Uint8List bigintToBytes(BigInt value) {
  if (value.isNegative) {
    throw const FormatException('negative bigint');
  }
  if (value == BigInt.zero) return Uint8List.fromList([0]);
  var hex = value.toRadixString(16);
  if (hex.length.isOdd) hex = '0$hex';
  return hexToBytes(hex);
}

BigInt bytesToBigint(Uint8List bytes) {
  var out = BigInt.zero;
  for (final b in bytes) {
    out = (out << 8) | BigInt.from(b);
  }
  return out;
}

/// UTF-8 encode. Hand-rolled so the byte output is identical on every
/// platform this package targets; throws on an unpaired surrogate instead of
/// silently emitting U+FFFD, because a request is content-addressed and a
/// substituted character changes what gets signed.
Uint8List utf8Encode(String text) {
  final out = <int>[];
  for (var i = 0; i < text.length; i++) {
    var code = text.codeUnitAt(i);
    if (code < 0x80) {
      out.add(code);
    } else if (code < 0x800) {
      out
        ..add(0xc0 | (code >> 6))
        ..add(0x80 | (code & 0x3f));
    } else if (code < 0xd800 || code >= 0xe000) {
      out
        ..add(0xe0 | (code >> 12))
        ..add(0x80 | ((code >> 6) & 0x3f))
        ..add(0x80 | (code & 0x3f));
    } else {
      i++;
      if (i >= text.length) {
        throw const FormatException('unpaired surrogate in string');
      }
      final next = text.codeUnitAt(i);
      code = 0x10000 + (((code & 0x3ff) << 10) | (next & 0x3ff));
      out
        ..add(0xf0 | (code >> 18))
        ..add(0x80 | ((code >> 12) & 0x3f))
        ..add(0x80 | ((code >> 6) & 0x3f))
        ..add(0x80 | (code & 0x3f));
    }
  }
  return Uint8List.fromList(out);
}

/// STRICT UTF-8 decode. Throws on malformed input, including overlong
/// encodings, surrogate code points and values past U+10FFFF — a lenient
/// decoder would let a hostile reply smuggle bytes that render as different
/// text than they compare as.
String utf8Decode(Uint8List bytes) {
  final out = StringBuffer();
  var i = 0;
  while (i < bytes.length) {
    final b0 = bytes[i];
    if (b0 < 0x80) {
      out.writeCharCode(b0);
      i += 1;
      continue;
    }
    int extra;
    int code;
    int minCode;
    if ((b0 & 0xe0) == 0xc0) {
      extra = 1;
      code = b0 & 0x1f;
      minCode = 0x80;
    } else if ((b0 & 0xf0) == 0xe0) {
      extra = 2;
      code = b0 & 0x0f;
      minCode = 0x800;
    } else if ((b0 & 0xf8) == 0xf0) {
      extra = 3;
      code = b0 & 0x07;
      minCode = 0x10000;
    } else {
      throw const FormatException('malformed UTF-8');
    }
    if (i + extra >= bytes.length) {
      throw const FormatException('truncated UTF-8');
    }
    for (var k = 1; k <= extra; k++) {
      final bk = bytes[i + k];
      if ((bk & 0xc0) != 0x80) {
        throw const FormatException('malformed UTF-8 continuation');
      }
      code = (code << 6) | (bk & 0x3f);
    }
    if (code < minCode) {
      throw const FormatException('overlong UTF-8 encoding');
    }
    if (code >= 0xd800 && code <= 0xdfff) {
      throw const FormatException('UTF-8 encodes a surrogate');
    }
    if (code > 0x10ffff) {
      throw const FormatException('UTF-8 code point out of range');
    }
    if (code > 0xffff) {
      code -= 0x10000;
      out
        ..writeCharCode(0xd800 + (code >> 10))
        ..writeCharCode(0xdc00 + (code & 0x3ff));
    } else {
      out.writeCharCode(code);
    }
    i += 1 + extra;
  }
  return out.toString();
}

/// ASCII decode (used for replies that carry text as raw bytes). Throws on
/// non-ASCII.
String asciiDecode(Uint8List bytes) {
  final out = StringBuffer();
  for (final b in bytes) {
    if (b > 0x7f) {
      throw const FormatException('non-ASCII byte');
    }
    out.writeCharCode(b);
  }
  return out.toString();
}
