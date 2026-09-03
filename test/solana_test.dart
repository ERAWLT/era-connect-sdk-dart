import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/chains/solana.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:era_connect/src/verify/solana.dart';
import 'package:test/test.dart';

/// Device replies synthesized with test keys: the exact CBOR/protobuf shapes
/// the firmware emits, signed so the verification helpers have something real
/// to recover. No fixture material from any private source.
void main() {
  final era = SolanaChain(const EraConnectConfig(origin: 'Test Wallet'));
  final requestId = Uint8List.fromList(List.generate(16, (i) => i + 1));
  final signData = Uint8List.fromList(List.generate(48, (i) => i * 3));

  group('Solana reply parsing + verification', () {
    final solPriv = ed.newKeyFromSeed(Uint8List.fromList(List.filled(32, 5)));
    final solPub = Uint8List.fromList(ed.public(solPriv).bytes);
    final request = era.generateSignRequest(SolSignRequestProps(
      requestId: requestId,
      signData: signData,
      path: "m/44'/501'/0'",
      xfp: '33333333',
      publicKey: solPub,
    ));
    final signature = ed.sign(solPriv, signData);

    Ur solReply(CborValue sigValue) {
      return Ur(
        'sol-signature',
        cborEncode(cbMap([
          (1, cbTag(37, cbBytes(requestId))),
          (2, sigValue),
        ])),
      );
    }

    test('round-trips and verifies', () {
      final scanner = request.scanner();
      scanner.receivePart(solReply(cbBytes(signature)).toWireString());
      final parsed = scanner.parse();
      expect(parsed.signature, signature);
      final result = verifySolanaSignature(VerifySolanaSignatureArgs(
        signData: signData,
        signature: parsed.signature,
        publicKey: solPub,
      ));
      expect(result.ok, isTrue);
      expect(result.checked, isTrue);
    });

    test('accepts the legacy hex-text signature shape', () {
      final parsed = era.parseSignature(
        solReply(cbText(bytesToHex(signature))),
        ExpectedReply(requestId: requestId),
      );
      expect(parsed.signature, signature);
    });

    test('a broadcast/signed message divergence is a failure', () {
      final drifted = Uint8List.fromList(signData);
      drifted[0] = 0xff;
      final result = verifySolanaSignature(VerifySolanaSignatureArgs(
        signData: signData,
        signature: signature,
        publicKey: solPub,
        broadcastMessageBytes: drifted,
      ));
      expect(result.ok, isFalse);
    });
  });

  group('byte-exact golden requests vs the golden fixture', () {
    final fixture = jsonDecode(
      File('test/fixtures/reference-golden.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    final cases = (fixture['cases'] as List).cast<Map<String, dynamic>>();
    Map<String, dynamic> caseByName(String name) {
      return cases.firstWhere(
        (c) => c['name'] == name,
        orElse: () => throw StateError('fixture case $name missing'),
      );
    }

    final goldenEra =
        SolanaChain(EraConnectConfig(origin: fixture['origin'] as String));
    final goldenRequestId = fixture['requestIdHex'] as String;
    final goldenSignData = Uint8List.fromList(List.generate(40, (i) => i));
    final solPubkey = Uint8List.fromList(List.filled(32, 0x07));

    void expectGolden(String name, Ur ur) {
      final golden = caseByName(name);
      expect(ur.type, golden['urType']);
      expect(bytesToHex(ur.cbor), golden['requestCborHex']);
      expect(ur.toWireString(), golden['requestUr']);
    }

    test('sol_tx and sol_message', () {
      final tx = goldenEra.generateSignRequest(SolSignRequestProps(
        requestId: goldenRequestId,
        signData: goldenSignData,
        path: "m/44'/501'/0'",
        xfp: '33333333',
        publicKey: solPubkey,
      ));
      expectGolden('sol_tx', tx.ur);

      final msg = goldenEra.generateSignRequest(SolSignRequestProps(
        requestId: goldenRequestId,
        signData: goldenSignData,
        signType: SolSignType.message,
        path: "m/44'/501'/0'",
        xfp: '33333333',
        publicKey: solPubkey,
      ));
      expectGolden('sol_message', msg.ur);
    });
  });
}
