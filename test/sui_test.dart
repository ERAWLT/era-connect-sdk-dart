import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/chains/sui.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:era_connect/src/verify/sui.dart';
import 'package:test/test.dart';

void main() {
  final sui = SuiChain(const EraConnectConfig(origin: 'Rest Test'));
  final requestId = Uint8List.fromList(List<int>.generate(16, (i) => i + 1));

  group('Sui', () {
    final privSeed = Uint8List.fromList(List<int>.filled(32, 3));
    final priv = ed.newKeyFromSeed(privSeed);
    final pub = Uint8List.fromList(ed.public(priv).bytes);
    final intentMessage =
        Uint8List.fromList([0, 0, 0, ...List<int>.generate(60, (i) => i)]);
    final request = sui.generateSignRequest(SuiSignRequestProps(
      requestId: requestId,
      intentMessage: intentMessage,
      path: "m/44'/784'/0'/0'/0'",
      xfp: 'deadbeef',
    ));

    test(
        'wire shape: uuid37, bytes, [keypath], origin; hash variant uses a hex STRING',
        () {
      final map = asMap(cborDecode(request.ur.cbor))!;
      expect(request.ur.type, 'sui-sign-request');
      expect(asBytes(mapGet(map, 2)), intentMessage);
      final hashReq = sui.generateSignHashRequest(SuiSignHashRequestProps(
        requestId: requestId,
        messageHash: suiIntentDigest(intentMessage),
        path: "m/44'/784'/0'/0'/0'",
        xfp: 'deadbeef',
      ));
      final hashMap = asMap(cborDecode(hashReq.ur.cbor))!;
      expect(hashReq.ur.type, 'sui-sign-hash-request');
      expect(asText(mapGet(hashMap, 2)),
          bytesToHex(suiIntentDigest(intentMessage)));
    });

    test('refuses soft path components', () {
      expect(
        () => sui.generateSignRequest(SuiSignRequestProps(
          intentMessage: intentMessage,
          path: "m/44'/784'/0'/0/0",
          xfp: 1,
        )),
        throwsA(isA<EraSdkError>()
            .having((e) => e.message, 'message', contains('hardened'))),
      );
    });

    test('round-trips a reply and verifies the intent digest', () {
      final signature = ed.sign(priv, suiIntentDigest(intentMessage));
      final reply = Ur(
        'sui-signature',
        cborEncode(
          cbMap([
            (1, cbTag(37, cbBytes(requestId))),
            (2, cbBytes(signature)),
            (3, cbBytes(pub)),
          ]),
        ),
      );
      final scanner = request.scanner();
      scanner.receivePart(reply.toWireString());
      final parsed = scanner.parse();
      final verdict = verifySuiSignature(VerifySuiSignatureArgs(
        intentMessage: intentMessage,
        signature: parsed.signature,
        publicKey: parsed.publicKey,
        expectedPublicKey: pub,
      ));
      expect(verdict.ok, isTrue);
      expect(verdict.checked, isTrue);
      final wrongKey = verifySuiSignature(VerifySuiSignatureArgs(
        intentMessage: intentMessage,
        signature: parsed.signature,
        publicKey: parsed.publicKey,
        expectedPublicKey: Uint8List.fromList(ed
            .public(
                ed.newKeyFromSeed(Uint8List.fromList(List<int>.filled(32, 9))))
            .bytes),
      ));
      expect(wrongKey.ok, isFalse);
    });
  });
}
