import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/crypto/bip32.dart';
import 'package:era_connect/src/crypto/codecs.dart';
import 'package:era_connect/src/crypto/digests.dart';
import 'package:era_connect/src/crypto/ed25519.dart';
import 'package:era_connect/src/crypto/secp256k1.dart';
import 'package:test/test.dart';

/// Cross-implementation known-answer tests: the fixture was produced by the
/// reference vectors's crypto stack (an independent curve/hash stack),
/// so agreement here pins this port to the same primitives byte-for-byte.
void main() {
  final kat =
      jsonDecode(File('test/fixtures/crypto-kat.json').readAsStringSync())
          as Map<String, dynamic>;

  group('digests', () {
    final digests = kat['digests'] as Map<String, dynamic>;
    final abc = Uint8List.fromList('abc'.codeUnits);

    test('match the reference stack', () {
      expect(bytesToHex(keccak256(abc)), digests['keccak256_abc']);
      expect(bytesToHex(blake2b256(abc)), digests['blake2b256_abc']);
      expect(bytesToHex(blake2b(abc, 64)), digests['blake2b512_abc']);
      expect(bytesToHex(ripemd160(abc)), digests['ripemd160_abc']);
    });
  });

  group('secp256k1', () {
    test('verifies and recovers every reference signature', () {
      for (final raw in kat['secp256k1'] as List<dynamic>) {
        final v = raw as Map<String, dynamic>;
        final sig = hexToBytes('${v['r'] as String}${v['s'] as String}');
        final digest = hexToBytes(v['digest'] as String);
        final pub = hexToBytes(v['pub33'] as String);
        expect(Secp256k1.verify(sig, digest, pub), isTrue);
        expect(
          bytesToHex(Secp256k1.recover(sig, digest, v['recovery'] as int)),
          v['pub33'],
        );
        // A flipped digest byte must not verify.
        final bad = Uint8List.fromList(digest);
        bad[0] ^= 1;
        expect(Secp256k1.verify(sig, bad, pub), isFalse);
      }
    });

    test('refuses hybrid prefixes and off-curve uncompressed keys', () {
      final v =
          (kat['secp256k1'] as List<dynamic>).first as Map<String, dynamic>;
      final sig = hexToBytes('${v['r'] as String}${v['s'] as String}');
      final digest = hexToBytes(v['digest'] as String);
      // Rebuild the same point as uncompressed, then damage the encoding.
      final point = Secp256k1.parsePublicKey(hexToBytes(v['pub33'] as String));
      final uncompressed = Uint8List.fromList(point.getEncoded(false));
      expect(Secp256k1.verify(sig, digest, uncompressed), isTrue);

      // Hybrid prefixes 0x06/0x07 wrap the same coordinates; the reference
      // curve library refuses them, so verify must return false, not true.
      for (final prefix in [0x06, 0x07]) {
        final hybrid = Uint8List.fromList(uncompressed);
        hybrid[0] = prefix;
        expect(Secp256k1.verify(sig, digest, hybrid), isFalse);
        expect(() => Secp256k1.parsePublicKey(hybrid), throwsArgumentError);
      }

      // Off-curve: y+1 satisfies no curve equation.
      final offCurve = Uint8List.fromList(uncompressed);
      offCurve[64] = (offCurve[64] + 1) & 0xff;
      expect(() => Secp256k1.parsePublicKey(offCurve), throwsArgumentError);
      expect(Secp256k1.verify(sig, digest, offCurve), isFalse);
    });

    test('refuses the malleated high-S form', () {
      final v = kat['secp256k1HighS'] as Map<String, dynamic>;
      final sig = hexToBytes('${v['r'] as String}${v['s'] as String}');
      expect(
        Secp256k1.verify(sig, hexToBytes(v['digest'] as String),
            hexToBytes(v['pub33'] as String)),
        isFalse,
      );
    });
  });

  group('ed25519', () {
    test('verifies the reference signatures', () {
      for (final raw in kat['ed25519'] as List<dynamic>) {
        final v = raw as Map<String, dynamic>;
        expect(
          ed25519Verify(
            hexToBytes(v['pub'] as String),
            hexToBytes(v['msg'] as String),
            hexToBytes(v['sig'] as String),
          ),
          isTrue,
        );
        final badSig = hexToBytes(v['sig'] as String);
        badSig[0] ^= 1;
        expect(
            ed25519Verify(hexToBytes(v['pub'] as String),
                hexToBytes(v['msg'] as String), badSig),
            isFalse);
      }
    });
  });

  group('bip32 public derivation', () {
    test('matches the reference child keys', () {
      final v = (kat['bip32'] as List<dynamic>).first as Map<String, dynamic>;
      final parent = hexToBytes(v['parentPub'] as String);
      final cc = hexToBytes(v['chainCode'] as String);
      expect(
          bytesToHex(derivePublicKeyPath(parent, cc, [0, 0])), v['child_0_0']);
      expect(
          bytesToHex(derivePublicKeyPath(parent, cc, [1, 5])), v['child_1_5']);
    });
  });

  group('codecs', () {
    test('base58check round-trips and validates', () {
      // The canonical first BIP-44 address bytes of the test-seed BTC account
      // are covered by accounts tests; here pin the codec itself.
      final payload = Uint8List.fromList([0x00, ...List.filled(20, 0xab)]);
      final encoded = base58CheckEncode(payload);
      expect(base58CheckDecode(encoded), payload);
      final corrupted = '${encoded.substring(0, encoded.length - 1)}1';
      expect(() => base58CheckDecode(corrupted), throwsA(anything));
    });

    test('bech32 encodes the canonical BIP-173 vector', () {
      // P2WPKH of hash160 751e76e8199196d454941c45d1b3a323f1433bd6 (the
      // BIP-173 spec example for witness v0).
      final hash = hexToBytes('751e76e8199196d454941c45d1b3a323f1433bd6');
      final words = [0, ...convertBits(hash, 8, 5, pad: true)];
      expect(
        bech32Encode('bc', words),
        'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
      );
    });
  });
}
