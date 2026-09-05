import 'dart:typed_data';

import '../chains/cashaddr.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../crypto/bip32.dart';
import '../crypto/codecs.dart';
import '../crypto/digests.dart';
import '../crypto/secp256k1.dart';

/// Non-hardened BIP-32 child public key from an account-level (publicKey, chainCode).
Uint8List derivePublicKey(
  Uint8List publicKey,
  Uint8List chainCode,
  int change,
  int index,
) {
  return derivePublicKeyPath(publicKey, chainCode, [change, index]);
}

Uint8List _uncompressed(Uint8List publicKey33) {
  return Uint8List.fromList(
    Secp256k1.parsePublicKey(publicKey33).getEncoded(false),
  );
}

/// EIP-55 checksummed address from a compressed secp256k1 public key.
String evmAddressFromPublicKey(Uint8List publicKey33) {
  final hash = keccak256(Uint8List.sublistView(_uncompressed(publicKey33), 1));
  final addr = bytesToHex(Uint8List.sublistView(hash, 12));
  final check = keccak256(
    Uint8List.fromList([for (final c in addr.codeUnits) c]),
  );
  final out = StringBuffer();
  for (var i = 0; i < addr.length; i++) {
    final nibble = i % 2 == 0 ? check[i >> 1] >> 4 : check[i >> 1] & 0x0f;
    out.write(nibble >= 8 ? addr[i].toUpperCase() : addr[i]);
  }
  return '0x$out';
}

/// CashAddr P2PKH address (Bitcoin Cash) from a compressed public key.
String bchAddressFromPublicKey(Uint8List publicKey33, {bool? withPrefix}) {
  return encodeCashAddr(
    CashAddrType.p2pkh,
    hash160(publicKey33),
    withPrefix: withPrefix,
  );
}

/// P2WPKH (witness v0) bech32 address.
String btcP2wpkhAddressFromPublicKey(
  Uint8List publicKey33, [
  String hrp = 'bc',
]) {
  return bech32Encode(
    hrp,
    [0, ...convertBits(hash160(publicKey33), 8, 5, pad: true)],
  );
}

/// Legacy P2PKH base58check address (`1...`).
String btcP2pkhAddressFromPublicKey(
  Uint8List publicKey33, [
  bool testnet = false,
]) {
  return base58CheckEncode(concatBytes([
    Uint8List.fromList([testnet ? 0x6f : 0x00]),
    hash160(publicKey33),
  ]));
}

/// Nested segwit (P2SH-P2WPKH) base58check address (`3...`).
String btcNestedSegwitAddressFromPublicKey(
  Uint8List publicKey33, [
  bool testnet = false,
]) {
  final redeemScript = concatBytes([
    Uint8List.fromList([0x00, 0x14]),
    hash160(publicKey33),
  ]);
  return base58CheckEncode(concatBytes([
    Uint8List.fromList([testnet ? 0xc4 : 0x05]),
    hash160(redeemScript),
  ]));
}

/// Cosmos bech32 address: plain bech32 of the 20-byte hash160, with NO
/// witness-version prefix (that is a segwit thing, not a Cosmos one). Every
/// zone carries its own HRP over the same key, so [prefix] is the caller's.
String cosmosAddressFromPublicKey(Uint8List publicKey33, String prefix) {
  return bech32Encode(
    prefix,
    convertBits(hash160(publicKey33), 8, 5, pad: true),
  );
}

/// The XRPL base58 dictionary: the same 58 symbols as Bitcoin's, in a
/// different order. The alphabet is part of the address format, not a
/// presentation detail — encoding an account under the wrong one yields a
/// well-formed address for somebody else.
const String _xrpBase58Alphabet =
    'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

/// base58 over an explicit dictionary; each leading zero byte keeps its
/// one-symbol encoding.
String _base58EncodeWith(Uint8List bytes, String alphabet) {
  var value = bytesToBigint(bytes);
  final fiftyEight = BigInt.from(58);
  final out = StringBuffer();
  while (value > BigInt.zero) {
    out.write(alphabet[(value % fiftyEight).toInt()]);
    value = value ~/ fiftyEight;
  }
  for (final b in bytes) {
    if (b != 0) break;
    out.write(alphabet[0]);
  }
  return String.fromCharCodes(out.toString().codeUnits.reversed);
}

/// XRP classic address (`r...`): base58check over `0x00 || hash160(pubkey)`,
/// with Bitcoin's double-SHA-256 checksum but XRPL's own base58 dictionary.
/// [base58CheckEncode] is hard-wired to the Bitcoin alphabet, so the four
/// checksum bytes are appended explicitly here.
String xrpAddressFromPublicKey(Uint8List publicKey33) {
  final payload = concatBytes([
    Uint8List.fromList([0x00]),
    hash160(publicKey33),
  ]);
  return _base58EncodeWith(
    concatBytes([payload, Uint8List.sublistView(sha256d(payload), 0, 4)]),
    _xrpBase58Alphabet,
  );
}

/// Tron base58check address (0x41-prefixed keccak hash).
String tronAddressFromPublicKey(Uint8List publicKey33) {
  final hash = keccak256(Uint8List.sublistView(_uncompressed(publicKey33), 1));
  return base58CheckEncode(concatBytes([
    Uint8List.fromList([0x41]),
    Uint8List.sublistView(hash, 12),
  ]));
}

/// `0x` Sui address: BLAKE2b-256 of the scheme flag (0x00 = Ed25519) plus the public key.
String suiAddressFromPublicKey(Uint8List publicKey32) {
  final digest = blake2b(
    concatBytes([
      Uint8List.fromList([0x00]),
      publicKey32,
    ]),
    32,
  );
  return '0x${bytesToHex(digest)}';
}

/// A Solana address IS the Ed25519 public key, base58.
String solanaAddressFromPublicKey(Uint8List publicKey32) {
  return base58Encode(publicKey32);
}

/// BIP-32 mainnet public version bytes (`xpub`).
const int xpubVersion = 0x0488b21e;

/// BIP-32 testnet public version bytes (`tpub`).
const int tpubVersion = 0x043587cf;

/// SLIP-132, BIP-84 P2WPKH version bytes (`zpub`).
const int zpubVersion = 0x04b24746;

/// SLIP-132, BIP-84 P2WPKH testnet version bytes (`vpub`).
const int vpubVersion = 0x045f1cf6;

/// BIP-32 extended public key serialization.
String serializeExtendedPublicKey({
  int version = xpubVersion,
  required int depth,
  required int parentFingerprint,
  required int childNumber,
  required Uint8List chainCode,
  required Uint8List publicKey,
}) {
  if (chainCode.length != 32 || publicKey.length != 33) {
    throw EraSdkError(
      'invalid-props',
      'extended key needs a 32-byte chain code and 33-byte key',
    );
  }
  return base58CheckEncode(concatBytes([
    u32be(version),
    Uint8List.fromList([depth & 0xff]),
    u32be(parentFingerprint),
    u32be(childNumber),
    chainCode,
    publicKey,
  ]));
}

// ---------------------------------------------------------------------------
// Cardano (BIP32-Ed25519 / CIP-3 "V2") soft public derivation
// ---------------------------------------------------------------------------

/// A soft-derived BIP32-Ed25519 public node: the child key plus its chain
/// code.
class CardanoSoftNode {
  const CardanoSoftNode({required this.publicKey, required this.chainCode});

  /// 32-byte compressed Ed25519 public key.
  final Uint8List publicKey;

  /// 32-byte chain code.
  final Uint8List chainCode;
}

Uint8List _u32le(int value) {
  return Uint8List.fromList([
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
  ]);
}

BigInt _leBytesToBigint(Uint8List bytes) {
  var out = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    out = (out << 8) | BigInt.from(bytes[i]);
  }
  return out;
}

/// Public (soft) child of a BIP32-Ed25519 extended public key — the scheme
/// Cardano wallets share account xpubs under (CIP-3/V2):
///
///     Z       = HMAC-SHA512(chainCode, 0x02 || A || le32(index))
///     childA  = A + [8 * ZL[0..28]] * B
///     childCC = HMAC-SHA512(chainCode, 0x03 || A || le32(index))[32..]
///
/// Only non-hardened indices are derivable publicly, which is exactly what
/// the role/index tail of a CIP-1852 path uses.
CardanoSoftNode cardanoSoftDeriveChild(
  Uint8List publicKey,
  Uint8List chainCode,
  int index,
) {
  if (publicKey.length != 32 || chainCode.length != 32) {
    throw EraSdkError(
      'invalid-props',
      'Cardano derivation needs a 32-byte key and chain code',
    );
  }
  if (index < 0 || index >= 0x80000000) {
    throw EraSdkError(
        'invalid-props', 'Cardano public derivation is soft-index only');
  }
  final z = hmacSha512(
    chainCode,
    concatBytes([
      Uint8List.fromList([0x02]),
      publicKey,
      _u32le(index),
    ]),
  );
  final cc = Uint8List.fromList(
    hmacSha512(
      chainCode,
      concatBytes([
        Uint8List.fromList([0x03]),
        publicKey,
        _u32le(index),
      ]),
    ).sublist(32),
  );
  final scalar = BigInt.from(8) * _leBytesToBigint(z.sublist(0, 28));
  final parent = _decompress(publicKey);
  final child = scalar == BigInt.zero ? parent : _add(parent, _mulBase(scalar));
  return CardanoSoftNode(publicKey: _compress(child), chainCode: cc);
}

/// Soft-derive along several indices (e.g. role, then address index).
Uint8List cardanoSoftDerivePath(
  Uint8List publicKey,
  Uint8List chainCode,
  List<int> indices,
) {
  var node = CardanoSoftNode(publicKey: publicKey, chainCode: chainCode);
  for (final index in indices) {
    node = cardanoSoftDeriveChild(node.publicKey, node.chainCode, index);
  }
  return node.publicKey;
}

// ---------------------------------------------------------------------------
// Minimal Ed25519 group arithmetic (RFC 8032). BigInt affine coordinates:
// derivation runs a handful of times per linked wallet, so clarity wins over
// speed, and the complete twisted-Edwards addition formula has no special
// cases to get wrong.
// ---------------------------------------------------------------------------

/// An affine point `(x, y)`; the identity is `(0, 1)`.
typedef _Point = (BigInt, BigInt);

final BigInt _p = (BigInt.one << 255) - BigInt.from(19);

/// The curve constant `d = -121665 / 121666 mod p`.
final BigInt _d = (_p - BigInt.from(121665)) *
    BigInt.from(121666).modPow(_p - BigInt.two, _p) %
    _p;

/// `sqrt(-1) mod p`, used by point decompression.
final BigInt _sqrtM1 = BigInt.two.modPow((_p - BigInt.one) >> 2, _p);

final BigInt _groupOrder = (BigInt.one << 252) +
    BigInt.parse('27742317777372353535851937790883648493');

final _Point _base = (
  BigInt.parse(
      '15112221349535400772501151409588531511454012693041857206046113283949847762202'),
  BigInt.parse(
      '46316835694926478169428394003475163141307993866256225615783033603165251855960'),
);

/// The Ed25519 group order `n`. Test-support parity with the reference
/// implementation (the private-side Icarus cross-check derives against it).
final BigInt ed25519GroupOrder = _groupOrder;

/// Compressed `scalar * B` for a non-negative [scalar] (`0` yields the
/// identity encoding). Test-support parity with the reference implementation.
Uint8List ed25519ScalarMultBase(BigInt scalar) {
  if (scalar.isNegative) {
    throw EraSdkError('invalid-props', 'Ed25519 scalar must be non-negative');
  }
  return _compress(_mulBase(scalar));
}

_Point _add(_Point a, _Point b) {
  final (x1, y1) = a;
  final (x2, y2) = b;
  final x1x2 = x1 * x2 % _p;
  final y1y2 = y1 * y2 % _p;
  final dxy = _d * x1x2 % _p * y1y2 % _p;
  final x3 =
      (x1 * y2 + y1 * x2) % _p * ((BigInt.one + dxy) % _p).modInverse(_p) % _p;
  final y3 = (y1y2 + x1x2) % _p * ((BigInt.one - dxy) % _p).modInverse(_p) % _p;
  return (x3, y3);
}

_Point _mulBase(BigInt scalar) {
  var result = (BigInt.zero, BigInt.one);
  var addend = _base;
  var k = scalar;
  while (k > BigInt.zero) {
    if (k.isOdd) result = _add(result, addend);
    addend = _add(addend, addend);
    k >>= 1;
  }
  return result;
}

/// RFC 8032 §5.1.3 point decompression, strict: a non-canonical `y`, an
/// off-curve `x²`, or a `-0` encoding is refused (`invalid-props`) rather
/// than coerced — a linked wallet's key bytes are attacker-suppliable.
_Point _decompress(Uint8List bytes) {
  final y0 = _leBytesToBigint(bytes);
  final sign = (bytes[31] >> 7) & 1;
  final y = y0 & ((BigInt.one << 255) - BigInt.one);
  if (y >= _p) {
    throw EraSdkError('invalid-props', 'not a valid Ed25519 point');
  }
  final y2 = y * y % _p;
  final u = (y2 - BigInt.one) % _p;
  final v = (_d * y2 + BigInt.one) % _p;
  // x = u * v^3 * (u * v^7)^((p-5)/8)
  var x = u *
      v.modPow(BigInt.from(3), _p) %
      _p *
      (u * v.modPow(BigInt.from(7), _p) % _p)
          .modPow((_p - BigInt.from(5)) >> 3, _p) %
      _p;
  final vx2 = v * x % _p * x % _p;
  if (vx2 == u) {
    // x is correct.
  } else if (vx2 == (_p - u) % _p) {
    x = x * _sqrtM1 % _p;
  } else {
    throw EraSdkError('invalid-props', 'not a valid Ed25519 point');
  }
  if (x == BigInt.zero && sign == 1) {
    throw EraSdkError('invalid-props', 'not a valid Ed25519 point');
  }
  if ((x.isOdd ? 1 : 0) != sign) x = _p - x;
  return (x, y);
}

Uint8List _compress(_Point point) {
  final (x, y) = point;
  final out = Uint8List(32);
  var v = y;
  for (var i = 0; i < 32; i++) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  if (x.isOdd) out[31] |= 0x80;
  return out;
}
