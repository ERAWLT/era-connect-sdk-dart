import 'dart:typed_data';

final BigInt _mask64 = (BigInt.one << 64) - BigInt.one;
final BigInt _five = BigInt.from(5);
final BigInt _nine = BigInt.from(9);

/// Exact — `1 / 2^53` is a power of two, representable without rounding.
const double _pow2neg53 = 1.0 / 9007199254740992.0;

BigInt _rotl(BigInt x, int k) => ((x << k) | (x >> (64 - k))) & _mask64;

/// Xoshiro256** seeded from a 32-byte digest, with the exact
/// `(x >>> 11) * 2^-53` double conversion the BC-UR fountain code uses.
///
/// The draw sequence IS the wire protocol: the device runs the same PRNG over
/// the same seed to derive which source fragments a fountain frame covers.
class Xoshiro256ss {
  /// Seed from a 32-byte digest split into four big-endian u64 words.
  factory Xoshiro256ss(Uint8List digest) {
    if (digest.length != 32) {
      throw const FormatException('xoshiro seed must be 32 bytes');
    }
    BigInt word(int offset) {
      var v = BigInt.zero;
      for (var i = 0; i < 8; i++) {
        v = (v << 8) | BigInt.from(digest[offset + i]);
      }
      return v;
    }

    final s0 = word(0);
    final s1 = word(8);
    final s2 = word(16);
    final s3 = word(24);
    if ((s0 | s1 | s2 | s3) == BigInt.zero) {
      throw const FormatException('xoshiro seed must not be all zeros');
    }
    return Xoshiro256ss._(s0, s1, s2, s3);
  }

  Xoshiro256ss._(this._s0, this._s1, this._s2, this._s3);

  BigInt _s0;
  BigInt _s1;
  BigInt _s2;
  BigInt _s3;

  BigInt nextRaw64() {
    final result = (_rotl((_s1 * _five) & _mask64, 7) * _nine) & _mask64;
    final t = (_s1 << 17) & _mask64;
    _s2 ^= _s0;
    _s3 ^= _s1;
    _s1 ^= _s2;
    _s0 ^= _s3;
    _s2 ^= t;
    _s3 = _rotl(_s3, 45);
    return result;
  }

  /// Uniform double in [0, 1): top 53 bits of the raw draw. Exact — no precision loss.
  double nextDouble() => (nextRaw64() >> 11).toDouble() * _pow2neg53;
}
