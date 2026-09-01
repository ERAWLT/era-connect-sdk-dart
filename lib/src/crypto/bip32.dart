import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import 'digests.dart';
import 'secp256k1.dart';

/// Non-hardened BIP-32 public child derivation — the only derivation a
/// watch-only SDK needs. Hardened steps require the private key and are
/// refused; the linked account already sits below every hardened level.
Uint8List deriveChildPublicKey(
    Uint8List parentPublicKey33, Uint8List chainCode, int index) {
  if (parentPublicKey33.length != 33) {
    throw EraSdkError('invalid-props', 'parent public key must be 33 bytes');
  }
  if (chainCode.length != 32) {
    throw EraSdkError('invalid-props', 'chain code must be 32 bytes');
  }
  if (index < 0 || index >= 0x80000000) {
    throw EraSdkError(
        'invalid-props', 'public derivation index must be non-hardened');
  }
  final data = concatBytes([parentPublicKey33, u32be(index)]);
  final i = hmacSha512(chainCode, data);
  final il = bytesToBigint(Uint8List.sublistView(i, 0, 32));

  final ECDomainParameters domain = ECCurve_secp256k1();
  if (il >= domain.n) {
    throw EraSdkError(
        'invalid-props', 'derived scalar out of range (try the next index)');
  }
  final parent = Secp256k1.parsePublicKey(parentPublicKey33);
  final child = (domain.G * il)! + parent;
  if (child == null || child.isInfinity) {
    throw EraSdkError(
        'invalid-props', 'derived point at infinity (try the next index)');
  }
  return Uint8List.fromList(child.getEncoded(true));
}

/// The BIP-32 fingerprint of a public key: the first four bytes of its
/// hash160, as a big-endian unsigned 32-bit value.
int publicKeyFingerprint(Uint8List publicKey33) {
  final h = hash160(publicKey33);
  return (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
}

/// Derive along a run of non-hardened steps (e.g. `[change, index]`),
/// propagating the chain code between levels.
Uint8List derivePublicKeyPath(
    Uint8List publicKey33, Uint8List chainCode, List<int> steps) {
  var pub = publicKey33;
  var cc = chainCode;
  for (final step in steps) {
    if (step < 0 || step >= 0x80000000) {
      throw EraSdkError(
          'invalid-props', 'public derivation index must be non-hardened');
    }
    final i = hmacSha512(cc, concatBytes([pub, u32be(step)]));
    pub = deriveChildPublicKey(pub, cc, step);
    cc = Uint8List.sublistView(i, 32, 64);
  }
  return pub;
}
