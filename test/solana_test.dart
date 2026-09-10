import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/chains/solana.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/registry/keypath.dart';
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

  group('derivation schemes on the wire', () {
    // The device exports three Solana derivations and tells them apart by path
    // DEPTH alone. The firmware signs at the full request path, so all three
    // are signable — this guard used to refuse two of them, which made the
    // address the device's own Receive screen shows by default unspendable.
    final pubkey = Uint8List.fromList(List.filled(32, 0x09));

    /// The levels the request actually carries: `crypto-keypath` (tag 304)
    /// key 1, parsed back out of the flat `[index, hardened, ...]` array.
    List<PathLevel> levelsOf(Ur ur) {
      final keypath = stripTags(mapGet(cborDecode(ur.cbor), 3)!);
      return parsePathComponents(mapGet(keypath, 1))!;
    }

    Ur urFor(String path) => era
        .generateSignRequest(SolSignRequestProps(
          requestId: requestId,
          signData: signData,
          path: path,
          xfp: '33333333',
          publicKey: pubkey,
        ))
        .ur;

    test("the single-account path m/44'/501' encodes two hardened levels", () {
      final levels = levelsOf(urFor("m/44'/501'"));
      expect(
          levels.map((l) => (l.index, l.hardened)), [(44, true), (501, true)]);
    });

    test("the account path m/44'/501'/idx' still encodes three", () {
      final levels = levelsOf(urFor("m/44'/501'/3'"));
      expect(levels.map((l) => (l.index, l.hardened)),
          [(44, true), (501, true), (3, true)]);
    });

    test("the sub-account path m/44'/501'/idx'/0' encodes four", () {
      final levels = levelsOf(urFor("m/44'/501'/3'/0'"));
      expect(levels.map((l) => (l.index, l.hardened)),
          [(44, true), (501, true), (3, true), (0, true)]);
    });

    test('a depth outside 2..4 is refused', () {
      for (final path in ["m/44'", "m/44'/501'/0'/0'/0'"]) {
        expect(
          () => urFor(path),
          throwsA(isA<EraSdkError>()
              .having((e) => e.code, 'code', 'invalid-props')),
          reason: path,
        );
      }
    });

    test('an unhardened level is refused at every depth', () {
      for (final path in ['m/44/501', "m/44'/501'/0", "m/44'/501'/0'/0"]) {
        expect(
          () => urFor(path),
          throwsA(isA<EraSdkError>()
              .having((e) => e.code, 'code', 'invalid-props')),
          reason: path,
        );
      }
    });

    test('the coin type is deliberately not policed', () {
      // The guard never checked it. Tightening that here would refuse paths
      // that sign on the device today, in a release that only claims to
      // ACCEPT more.
      expect(() => urFor("m/44'/784'/0'"), returnsNormally);
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
