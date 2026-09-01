import 'dart:typed_data';

import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/chains/xrp.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/crypto/digests.dart';
import 'package:era_connect/src/verify/xrp.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:test/test.dart';

final ECDomainParameters _domain = ECCurve_secp256k1();

/// Compressed secp256k1 public key for a raw private scalar (test-only — the
/// SDK itself never holds keys).
Uint8List compressedPublicKey(Uint8List priv) {
  final d = bytesToBigint(priv);
  return Uint8List.fromList((_domain.G * d)!.getEncoded(true));
}

/// Deterministic (RFC 6979) low-S ECDSA over a raw 32-byte digest, DER
/// encoded — the same signature shape `@noble/curves` produces in the
/// reference SDK's tests.
Uint8List signDerLowS(Uint8List digest32, Uint8List priv) {
  final signer = ECDSASigner(null, HMac(SHA256Digest(), 64));
  signer.init(
    true,
    PrivateKeyParameter<ECPrivateKey>(
      ECPrivateKey(bytesToBigint(priv), _domain),
    ),
  );
  final signature = signer.generateSignature(digest32) as ECSignature;
  final n = _domain.n;
  final s = signature.s > (n >> 1) ? n - signature.s : signature.s;
  Uint8List derInt(BigInt v) {
    final bytes = bigintToBytes(v);
    return (bytes[0] & 0x80) != 0
        ? Uint8List.fromList([0x00, ...bytes])
        : bytes;
  }

  final r = derInt(signature.r);
  final sBytes = derInt(s);
  return Uint8List.fromList([
    0x30,
    4 + r.length + sBytes.length,
    0x02,
    r.length,
    ...r,
    0x02,
    sBytes.length,
    ...sBytes,
  ]);
}

void main() {
  test('deeply nested inner objects are refused, not a stack overflow', () {
    // 200k opening inner-object markers followed by their closers would
    // overflow the call stack without the depth cap; the verifier must
    // return a failed verdict instead of crashing.
    final hostile = Uint8List.fromList([
      ...List.filled(200000, 0xe2),
      ...List.filled(200000, 0xe1),
    ]);
    final verdict = verifyXrpSignature(VerifyXrpSignatureArgs(
      signedTx: hostile,
      expectedSigningPubKey: "02${'00' * 32}",
    ));
    expect(verdict.ok, isFalse);
  });

  final era = XrpChain(const EraConnectConfig(origin: 'Rest Test'));

  group('XRP', () {
    test('validates the request JSON gate', () {
      expect(
        () => era.generateSignRequest(
          const XrpSignRequestProps(
            transaction: {'TransactionType': 'Payment'},
          ),
        ),
        throwsA(
          isA<EraSdkError>()
              .having((e) => e.message, 'message', contains('Account')),
        ),
      );
      final request = era.generateSignRequest(
        XrpSignRequestProps(
          transaction: {
            'TransactionType': 'Payment',
            'Account': 'rMYQaEBLwyvSmDoRnH2tsqGE2LK4S3Rdap',
            'Destination': 'rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf',
            'Amount': '1000',
            'Fee': '12',
            'Sequence': 1,
            'SigningPubKey': bytesToHex(
              compressedPublicKey(Uint8List.fromList(List.filled(32, 8))),
            ),
          },
        ),
      );
      expect(request.ur.type, 'bytes');
      expect(request.requestId, isNull); // honestly no request id on this wire
    });

    test('verifies a hand-built signed binary (walker + signing hash + DER)',
        () {
      final priv = Uint8List.fromList(List.filled(32, 8));
      final pub = compressedPublicKey(priv);
      // Build a minimal canonical tx: TransactionType(0x12 UInt16), Sequence
      // (0x24 UInt32), Amount(0x61), Fee(0x68), SigningPubKey(0x73 VL),
      // Account(0x81 VL), Destination(0x83 VL) — signature inserted as 0x74.
      final fields = <Uint8List>[
        Uint8List.fromList([0x12, 0x00, 0x00]), // Payment
        Uint8List.fromList([0x24, 0, 0, 0, 1]), // Sequence 1
        Uint8List.fromList(
            [0x61, 0x40, 0, 0, 0, 0, 0, 0x03, 0xe8]), // 1000 drops
        Uint8List.fromList([0x68, 0x40, 0, 0, 0, 0, 0, 0, 12]), // fee 12
        Uint8List.fromList([0x73, 33, ...pub]),
        Uint8List.fromList([0x81, 20, ...List.filled(20, 0xaa)]),
        Uint8List.fromList([0x83, 20, ...List.filled(20, 0xbb)]),
      ];

      final signingPayload = concatBytes([
        Uint8List.fromList([0x53, 0x54, 0x58, 0x00]),
        ...fields,
      ]);
      final digest = Uint8List.sublistView(sha512(signingPayload), 0, 32);
      final der = signDerLowS(digest, priv);
      // Canonical order: TxnSignature (0x74) sits after SigningPubKey (0x73).
      final signed = concatBytes([
        ...fields.sublist(0, 5),
        Uint8List.fromList([0x74, der.length, ...der]),
        ...fields.sublist(5),
      ]);

      final good = verifyXrpSignature(
        VerifyXrpSignatureArgs(
          signedTx: signed,
          expectedSigningPubKey: bytesToHex(pub),
        ),
      );
      expect(good.ok, isTrue);
      expect(good.checked, isTrue);

      final tampered = Uint8List.fromList(signed);
      tampered[4] = 2; // Sequence 1 → 2
      final bad = verifyXrpSignature(
        VerifyXrpSignatureArgs(
          signedTx: tampered,
          expectedSigningPubKey: bytesToHex(pub),
        ),
      );
      expect(bad.ok, isFalse);
    });
  });
}
