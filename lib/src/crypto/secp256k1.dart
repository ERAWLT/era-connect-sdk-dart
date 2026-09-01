import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';

import '../core/bytes.dart';

/// secp256k1 verification and public-key recovery, hand-rolled on the curve
/// primitives so the semantics match the TypeScript SDK's `@noble/curves`
/// usage exactly — including the LOW-S rule: a signature with `s > n/2` is
/// refused as malleated, the same default every verifier in this SDK relies
/// on. Signing deliberately does not exist here; this SDK never holds keys.
class Secp256k1 {
  Secp256k1._();

  static final ECDomainParameters _domain = ECCurve_secp256k1();

  static BigInt get order => _domain.n;

  /// Parse a compressed (33-byte) or uncompressed (65-byte) public key.
  /// Throws [ArgumentError] on anything that is not a curve point.
  static ECPoint parsePublicKey(Uint8List bytes) {
    if (bytes.length != 33 && bytes.length != 65) {
      throw ArgumentError('public key must be 33 or 65 bytes');
    }
    final point = _domain.curve.decodePoint(bytes);
    if (point == null || point.isInfinity) {
      throw ArgumentError('invalid public key encoding');
    }
    return point;
  }

  /// Verify a compact `r || s` signature over a 32-byte digest.
  ///
  /// Enforces canonical low-S: `s > n/2` returns false.
  static bool verify(
      Uint8List signature64, Uint8List digest32, Uint8List publicKey) {
    if (signature64.length != 64 || digest32.length != 32) return false;
    final r = bytesToBigint(Uint8List.sublistView(signature64, 0, 32));
    final s = bytesToBigint(Uint8List.sublistView(signature64, 32, 64));
    final n = _domain.n;
    if (r <= BigInt.zero || r >= n || s <= BigInt.zero || s >= n) return false;
    if (s > (n >> 1)) return false; // malleated high-S

    final ECPoint q;
    try {
      q = parsePublicKey(publicKey);
    } on ArgumentError {
      return false;
    }
    final z = bytesToBigint(digest32) % n;
    final w = s.modInverse(n);
    final u1 = (z * w) % n;
    final u2 = (r * w) % n;
    final point = (_domain.G * u1)! + (q * u2)!;
    if (point == null || point.isInfinity) return false;
    final x = point.x!.toBigInteger()! % n;
    return x == r;
  }

  /// Recover the compressed public key from a compact signature, its 32-byte
  /// digest and a recovery id (0..3). Throws [ArgumentError] when the inputs
  /// do not name a valid point.
  static Uint8List recover(
      Uint8List signature64, Uint8List digest32, int recoveryId) {
    if (signature64.length != 64) {
      throw ArgumentError('signature must be 64 bytes');
    }
    if (digest32.length != 32) {
      throw ArgumentError('digest must be 32 bytes');
    }
    if (recoveryId < 0 || recoveryId > 3) {
      throw ArgumentError('recovery id must be 0..3');
    }
    final n = _domain.n;
    final r = bytesToBigint(Uint8List.sublistView(signature64, 0, 32));
    final s = bytesToBigint(Uint8List.sublistView(signature64, 32, 64));
    if (r <= BigInt.zero || r >= n || s <= BigInt.zero || s >= n) {
      throw ArgumentError('signature scalar out of range');
    }

    // x = r (+ n for the rare recId>=2 case where r wrapped past the order).
    final x = recoveryId >= 2 ? r + n : r;
    final prime = BigInt.parse(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
      radix: 16,
    );
    if (x >= prime) {
      throw ArgumentError('recovery x out of field');
    }
    final rPoint = _decompress(x, recoveryId & 1);

    final z = bytesToBigint(digest32) % n;
    final rInv = r.modInverse(n);
    // Q = r^-1 * (s*R - z*G)
    final sr = (rPoint * s)!;
    final zg = (_domain.G * ((n - z) % n))!;
    final q = ((sr + zg)! * rInv)!;
    if (q.isInfinity) {
      throw ArgumentError('recovered point at infinity');
    }
    return Uint8List.fromList(q.getEncoded(true));
  }

  static ECPoint _decompress(BigInt x, int yParity) {
    final encoded = Uint8List(33);
    encoded[0] = 0x02 + yParity;
    final xBytes = bigintToBytes(x);
    encoded.setAll(33 - xBytes.length, xBytes);
    final point = _domain.curve.decodePoint(encoded);
    if (point == null) {
      throw ArgumentError('x is not on the curve');
    }
    return point;
  }
}
