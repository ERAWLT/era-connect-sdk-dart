/// CashAddr codec (the Bitcoin Cash address format).
///
/// Not bech32: the checksum is a 40-bit BCH code over its own generator set,
/// and there is no separator-position rule — the payload is everything after
/// the optional `prefix:`. The decoder takes every spec-legal spelling
/// (bare, prefixed, all-uppercase; mixed case refused), but the DEVICE's own
/// parser reads only the lowercase form — its prefix rebuild turns an
/// uppercase body into a mixed-case string it then rejects, and the refusal
/// fails open into a zero hash. Anything that goes on the wire must therefore
/// be re-encoded through [encodeCashAddr], never passed through verbatim;
/// `BchChain.generateSignRequest` does exactly that.
library;

import 'dart:typed_data';

import '../core/errors.dart';

const String _charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

final Map<int, int> _charsetRev = {
  for (var i = 0; i < _charset.length; i++) _charset.codeUnitAt(i): i,
};

/// The default (mainnet) human-readable prefix.
const String cashaddrPrefix = 'bitcoincash';

final List<BigInt> _generator = [
  BigInt.from(0x98f2bc8e61),
  BigInt.from(0x79b76d99e2),
  BigInt.from(0xf33e5fb3c4),
  BigInt.from(0xae2eabe2a8),
  BigInt.from(0x1e4f43e470),
];

BigInt _polymod(List<int> values) {
  final mask35 = BigInt.from(0x07ffffffff);
  var c = BigInt.one;
  for (final d in values) {
    final c0 = c >> 35;
    c = ((c & mask35) << 5) ^ BigInt.from(d);
    for (var i = 0; i < 5; i++) {
      if (((c0 >> i) & BigInt.one) != BigInt.zero) c ^= _generator[i];
    }
  }
  return c ^ BigInt.one;
}

/// Prefix expansion: the low five bits of each character, then a zero.
List<int> _expandPrefix(String prefix) {
  final out = <int>[];
  for (var i = 0; i < prefix.length; i++) {
    out.add(prefix.codeUnitAt(i) & 0x1f);
  }
  out.add(0);
  return out;
}

List<int> _convertBits(List<int> data, int from, int to, bool pad) {
  var acc = 0;
  var bits = 0;
  final out = <int>[];
  final maxv = (1 << to) - 1;
  for (final value in data) {
    if (value < 0 || (value >> from) != 0) {
      throw EraSdkError('invalid-props', 'cashaddr: value out of range');
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
    throw EraSdkError('invalid-props', 'cashaddr: invalid padding');
  }
  return out;
}

/// The two script kinds the device builds outputs for.
enum CashAddrType { p2pkh, p2sh }

/// A decoded CashAddr: script kind, hash160 and the prefix it carried.
class CashAddrPayload {
  const CashAddrPayload({
    required this.type,
    required this.hash,
    required this.prefix,
  });

  /// The script kind the version byte named.
  final CashAddrType type;

  /// The 20-byte hash160.
  final Uint8List hash;

  /// The (lowercased) human-readable prefix the address resolved to.
  final String prefix;
}

final RegExp _asciiGuard = RegExp(r'^[0-9A-Za-z:]*$');
final RegExp _anyUpper = RegExp('[A-Z]');
final RegExp _anyLower = RegExp('[a-z]');

const List<int> _hashSizes = [160, 192, 224, 256, 320, 384, 448, 512];

/// Decode a CashAddr, with or without its `prefix:`. Only 20-byte P2PKH and
/// P2SH payloads are accepted — those are the two script kinds the device
/// builds outputs for.
CashAddrPayload decodeCashAddr(
  String address, [
  String expectedPrefix = cashaddrPrefix,
]) {
  // ASCII only, before any case folding: the case guard below is ASCII-scoped,
  // while String.toLowerCase folds full Unicode — U+212A KELVIN SIGN would
  // otherwise slip past the guard and fold into a charset 'k'.
  if (!_asciiGuard.hasMatch(address)) {
    throw EraSdkError('invalid-props', 'cashaddr: invalid character');
  }
  final hasUpper = _anyUpper.hasMatch(address);
  final hasLower = _anyLower.hasMatch(address);
  if (hasUpper && hasLower) {
    throw EraSdkError('invalid-props', 'cashaddr: mixed-case address refused');
  }
  final lower = address.toLowerCase();
  final colon = lower.lastIndexOf(':');
  final prefix = colon == -1 ? expectedPrefix : lower.substring(0, colon);
  final payload = colon == -1 ? lower : lower.substring(colon + 1);
  if (prefix != expectedPrefix) {
    throw EraSdkError(
      'invalid-props',
      'cashaddr: prefix "$prefix" does not match expected "$expectedPrefix"',
    );
  }
  if (payload.length < 8 + 1) {
    throw EraSdkError('invalid-props', 'cashaddr: payload too short');
  }
  final values = <int>[];
  for (var i = 0; i < payload.length; i++) {
    final v = _charsetRev[payload.codeUnitAt(i)];
    if (v == null) {
      throw EraSdkError(
        'invalid-props',
        'cashaddr: invalid character "${payload[i]}"',
      );
    }
    values.add(v);
  }
  if (_polymod([..._expandPrefix(prefix), ...values]) != BigInt.zero) {
    throw EraSdkError('invalid-props', 'cashaddr: checksum mismatch');
  }
  final data = _convertBits(values.sublist(0, values.length - 8), 5, 8, false);
  if (data.isEmpty) {
    throw EraSdkError('invalid-props', 'cashaddr: empty payload');
  }
  final version = data[0];
  if (version & 0x80 != 0) {
    throw EraSdkError('invalid-props', 'cashaddr: reserved version bit set');
  }
  final typeBits = (version >> 3) & 0x0f;
  final sizeBits = version & 0x07;
  final hashBits = _hashSizes[sizeBits];
  if (data.length - 1 != hashBits ~/ 8) {
    throw EraSdkError(
      'invalid-props',
      'cashaddr: hash length does not match version byte',
    );
  }
  if (typeBits != 0 && typeBits != 1) {
    throw EraSdkError(
      'invalid-props',
      'cashaddr: unsupported address type $typeBits',
    );
  }
  if (hashBits != 160) {
    throw EraSdkError(
      'invalid-props',
      'cashaddr: only 20-byte hashes are supported',
    );
  }
  return CashAddrPayload(
    type: typeBits == 0 ? CashAddrType.p2pkh : CashAddrType.p2sh,
    hash: Uint8List.fromList(data.sublist(1)),
    prefix: prefix,
  );
}

/// Encode a 20-byte hash160 as a CashAddr. Returns the bare form by default.
String encodeCashAddr(
  CashAddrType type,
  Uint8List hash, {
  String? prefix,
  bool? withPrefix,
}) {
  if (hash.length != 20) {
    throw EraSdkError('invalid-props', 'cashaddr: hash must be 20 bytes');
  }
  final hrp = prefix ?? cashaddrPrefix;
  // typeBits<<3 | sizeBits(160 -> 0)
  final version = type == CashAddrType.p2pkh ? 0 : 8;
  final payload = _convertBits([version, ...hash], 8, 5, true);
  final checksumInput = [
    ..._expandPrefix(hrp),
    ...payload,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  ];
  final checksum = _polymod(checksumInput);
  final mask5 = BigInt.from(0x1f);
  final suffix = <int>[];
  for (var i = 7; i >= 0; i--) {
    suffix.add(((checksum >> (5 * i)) & mask5).toInt());
  }
  final body = [...payload, ...suffix].map((v) => _charset[v]).join();
  return (withPrefix ?? false) ? '$hrp:$body' : body;
}
