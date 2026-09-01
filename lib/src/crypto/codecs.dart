import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';
import 'digests.dart';

/// Address text codecs (base58, base58check, bech32). Hand-rolled: the SDK's
/// byte-exact address contract must not float with third-party releases.

const String _base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

String base58Encode(Uint8List bytes) {
  var value = bytesToBigint(bytes);
  final out = StringBuffer();
  final fiftyEight = BigInt.from(58);
  while (value > BigInt.zero) {
    final rem = (value % fiftyEight).toInt();
    out.write(_base58Alphabet[rem]);
    value = value ~/ fiftyEight;
  }
  for (final b in bytes) {
    if (b != 0) break;
    out.write('1');
  }
  return String.fromCharCodes(out.toString().codeUnits.reversed);
}

Uint8List base58Decode(String text) {
  var value = BigInt.zero;
  final fiftyEight = BigInt.from(58);
  for (final ch in text.split('')) {
    final idx = _base58Alphabet.indexOf(ch);
    if (idx < 0) {
      throw EraSdkError('invalid-props', 'base58: invalid character "$ch"');
    }
    value = value * fiftyEight + BigInt.from(idx);
  }
  var leading = 0;
  for (final ch in text.split('')) {
    if (ch != '1') break;
    leading++;
  }
  final body = value == BigInt.zero ? Uint8List(0) : bigintToBytes(value);
  final out = Uint8List(leading + body.length);
  out.setAll(leading, body);
  return out;
}

String base58CheckEncode(Uint8List payload) {
  final check = sha256d(payload);
  return base58Encode(concatBytes([payload, Uint8List.sublistView(check, 0, 4)]));
}

Uint8List base58CheckDecode(String text) {
  final raw = base58Decode(text);
  if (raw.length < 5) {
    throw EraSdkError('invalid-props', 'base58check: too short');
  }
  final payload = Uint8List.sublistView(raw, 0, raw.length - 4);
  final check = sha256d(payload);
  for (var i = 0; i < 4; i++) {
    if (raw[raw.length - 4 + i] != check[i]) {
      throw EraSdkError('invalid-props', 'base58check: checksum mismatch');
    }
  }
  return payload;
}

// --- bech32 (BIP-173) ------------------------------------------------------

const String _bech32Charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

int _bech32Polymod(List<int> values) {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  var chk = 1;
  for (final v in values) {
    final b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (var i = 0; i < 5; i++) {
      if ((b >> i) & 1 == 1) chk ^= gen[i];
    }
  }
  return chk;
}

List<int> _bech32HrpExpand(String hrp) => [
      for (final c in hrp.codeUnits) c >> 5,
      0,
      for (final c in hrp.codeUnits) c & 31,
    ];

/// Convert between bit group sizes (BIP-173 `convertbits`).
List<int> convertBits(List<int> data, int from, int to, {required bool pad}) {
  var acc = 0;
  var bits = 0;
  final out = <int>[];
  final maxv = (1 << to) - 1;
  for (final value in data) {
    if (value < 0 || value >> from != 0) {
      throw EraSdkError('invalid-props', 'convertBits: value out of range');
    }
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.add((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.add((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
    throw EraSdkError('invalid-props', 'convertBits: invalid padding');
  }
  return out;
}

/// Encode 5-bit words as bech32 (constant 1 — segwit v0 addresses).
String bech32Encode(String hrp, List<int> words) {
  final values = [..._bech32HrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0];
  final polymod = _bech32Polymod(values) ^ 1;
  final checksum = [for (var i = 0; i < 6; i++) (polymod >> (5 * (5 - i))) & 31];
  final body = [...words, ...checksum].map((v) => _bech32Charset[v]).join();
  return '$hrp' '1$body';
}
