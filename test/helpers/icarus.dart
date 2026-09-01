/// TEST-ONLY Cardano Icarus (CIP-3 / BIP32-Ed25519 "V2") PRIVATE-side
/// implementation: master key from entropy, hardened/soft private derivation,
/// extended signing. It exists to cross-validate the SDK's PUBLIC soft
/// derivation and digest against an independent private-side computation
/// (and against the firmware corpus, which signs from the same scheme).
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as c;
import 'package:era_connect/src/accounts/derive.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/crypto/digests.dart';

/// An Icarus extended private key.
class XPrv {
  XPrv({required this.kL, required this.kR, required this.chainCode});

  /// 32-byte scalar (little-endian).
  final Uint8List kL;

  /// 32-byte nonce seed.
  final Uint8List kR;

  final Uint8List chainCode;
}

/// One derivation level: index plus the hardened flag.
class IcarusLevel {
  const IcarusLevel({required this.index, required this.hardened});

  final int index;
  final bool hardened;
}

final BigInt _n = ed25519GroupOrder;

BigInt _leToBigint(Uint8List bytes) {
  var out = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    out = (out << 8) | BigInt.from(bytes[i]);
  }
  return out;
}

Uint8List _bigintToLe(BigInt value, int length) {
  final out = Uint8List(length);
  var v = value;
  for (var i = 0; i < length; i++) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  return out;
}

Uint8List _u32le(int value) {
  return Uint8List.fromList([
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
  ]);
}

/// 32-byte LE addition a + b, final carry dropped (cardano-crypto semantics).
Uint8List _addLe(Uint8List a, Uint8List b) {
  final out = Uint8List(32);
  var carry = 0;
  for (var i = 0; i < 32; i++) {
    final sum = (i < a.length ? a[i] : 0) + (i < b.length ? b[i] : 0) + carry;
    out[i] = sum & 0xff;
    carry = sum >> 8;
  }
  return out;
}

/// kL + 8 * ZL[0..28], 32-byte LE, carry dropped.
Uint8List _add28Mul8(Uint8List kL, Uint8List zL) {
  final mul = _bigintToLe(BigInt.from(8) * _leToBigint(zL.sublist(0, 28)), 32);
  return _addLe(kL, mul);
}

/// The compressed public key of a private scalar.
Uint8List publicKeyOf(Uint8List kL) {
  final scalar = _leToBigint(kL) % _n;
  return ed25519ScalarMultBase(scalar);
}

/// PBKDF2-HMAC-SHA512 (RFC 8018). Test-only: the TypeScript helper uses the
/// noble implementation; this one is hand-rolled on `package:crypto`'s Hmac.
Uint8List pbkdf2HmacSha512(
  Uint8List password,
  Uint8List salt,
  int iterations,
  int dkLen,
) {
  final prf = c.Hmac(c.sha512, password);
  final blocks = (dkLen + 63) ~/ 64;
  final out = Uint8List(blocks * 64);
  for (var block = 1; block <= blocks; block++) {
    var u = Uint8List.fromList(
      prf.convert(concatBytes([salt, u32be(block)])).bytes,
    );
    final t = Uint8List.fromList(u);
    for (var iter = 1; iter < iterations; iter++) {
      u = Uint8List.fromList(prf.convert(u).bytes);
      for (var j = 0; j < 64; j++) {
        t[j] ^= u[j];
      }
    }
    out.setAll((block - 1) * 64, t);
  }
  return out.sublist(0, dkLen);
}

/// Icarus master key: PBKDF2-HMAC-SHA512(pass="", salt=entropy, 4096, 96) +
/// V2 clamp.
XPrv icarusMasterFromEntropy(Uint8List entropy) {
  final out = pbkdf2HmacSha512(Uint8List(0), entropy, 4096, 96);
  final kL = out.sublist(0, 32);
  kL[0] &= 0xf8;
  kL[31] &= 0x1f;
  kL[31] |= 0x40;
  return XPrv(kL: kL, kR: out.sublist(32, 64), chainCode: out.sublist(64, 96));
}

/// One hardened or soft private child.
XPrv deriveChild(XPrv parent, int index, bool hardened) {
  final i = hardened ? index + 0x80000000 : index;
  Uint8List z;
  Uint8List cc;
  if (hardened) {
    z = hmacSha512(
      parent.chainCode,
      concatBytes([
        Uint8List.fromList([0x00]),
        parent.kL,
        parent.kR,
        _u32le(i),
      ]),
    );
    cc = Uint8List.fromList(
      hmacSha512(
        parent.chainCode,
        concatBytes([
          Uint8List.fromList([0x01]),
          parent.kL,
          parent.kR,
          _u32le(i),
        ]),
      ).sublist(32),
    );
  } else {
    final a = publicKeyOf(parent.kL);
    z = hmacSha512(
      parent.chainCode,
      concatBytes([
        Uint8List.fromList([0x02]),
        a,
        _u32le(i),
      ]),
    );
    cc = Uint8List.fromList(
      hmacSha512(
        parent.chainCode,
        concatBytes([
          Uint8List.fromList([0x03]),
          a,
          _u32le(i),
        ]),
      ).sublist(32),
    );
  }
  return XPrv(
    kL: _add28Mul8(parent.kL, z.sublist(0, 32)),
    kR: _addLe(parent.kR, z.sublist(32, 64)),
    chainCode: cc,
  );
}

/// Derive along a whole path.
XPrv derivePath(XPrv root, List<IcarusLevel> levels) {
  var node = root;
  for (final level in levels) {
    node = deriveChild(node, level.index, level.hardened);
  }
  return node;
}

/// Cardano ed25519-extended signing of a message (here: the 32-byte tx hash).
Uint8List extendedSign(XPrv key, Uint8List message) {
  final a = publicKeyOf(key.kL);
  final nonce = _leToBigint(sha512(concatBytes([key.kR, message]))) % _n;
  final rBytes =
      ed25519ScalarMultBase(nonce == BigInt.zero ? BigInt.one : nonce);
  final hram = _leToBigint(sha512(concatBytes([rBytes, a, message]))) % _n;
  final s = (nonce + hram * (_leToBigint(key.kL) % _n)) % _n;
  return concatBytes([rBytes, _bigintToLe(s, 32)]);
}
