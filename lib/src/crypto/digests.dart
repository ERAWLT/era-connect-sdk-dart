import 'dart:typed_data';

import 'package:crypto/crypto.dart' as c;
import 'package:pointycastle/digests/blake2b.dart';
import 'package:pointycastle/digests/keccak.dart';
import 'package:pointycastle/digests/ripemd160.dart';

/// Thin digest wrappers. One place decides which implementation backs each
/// hash, so a swap never touches chain or verify code.

Uint8List sha256(Uint8List data) => Uint8List.fromList(c.sha256.convert(data).bytes);

Uint8List sha512(Uint8List data) => Uint8List.fromList(c.sha512.convert(data).bytes);

Uint8List hmacSha512(Uint8List key, Uint8List data) =>
    Uint8List.fromList(c.Hmac(c.sha512, key).convert(data).bytes);

Uint8List keccak256(Uint8List data) => KeccakDigest(256).process(data);

Uint8List blake2b256(Uint8List data) => Blake2bDigest(digestSize: 32).process(data);

Uint8List blake2b(Uint8List data, int digestSize) =>
    Blake2bDigest(digestSize: digestSize).process(data);

Uint8List ripemd160(Uint8List data) => RIPEMD160Digest().process(data);

Uint8List sha256d(Uint8List data) => sha256(sha256(data));

Uint8List hash160(Uint8List data) => ripemd160(sha256(data));
