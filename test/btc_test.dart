import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/btc.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/scan/ur_scanner.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:era_connect/src/verify/btc.dart';
import 'package:test/test.dart';

Matcher throwsSdkError(String code) =>
    throwsA(isA<EraSdkError>().having((e) => e.code, 'code', code));

/// Device replies synthesized with test keys: the exact CBOR shapes the
/// firmware emits. No fixture material from any private source.
void main() {
  final btc = BtcChain(const EraConnectConfig(origin: 'Test Wallet'));
  final requestId = Uint8List.fromList(List<int>.generate(16, (i) => i + 1));
  final pubKeyCompressed = hexToBytes(
      '02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f');
  final signData = Uint8List.fromList(List<int>.generate(48, (i) => i * 3));

  group('BTC message reply parsing', () {
    final request = btc.generateMessageSignRequest(BtcMessageSignRequestProps(
      requestId: requestId,
      message: signData,
      path: "m/84'/0'/0'/0/0",
      xfp: '22222222',
      address: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
    ));
    // Compressed P2PKH header.
    final rawSignature =
        Uint8List.fromList([31, ...List<int>.filled(64, 0x44)]);

    Ur btcReply(Uint8List sigBytes) {
      return Ur(
        'btc-signature',
        cborEncode(
          cbMap([
            (1, cbTag(37, cbBytes(requestId))),
            (2, cbBytes(sigBytes)),
            (3, cbBytes(pubKeyCompressed)),
          ]),
        ),
      );
    }

    test('decodes the base64-in-ASCII device quirk', () {
      final wire = Uint8List.fromList(base64Encode(rawSignature).codeUnits);
      final scanner = request.scanner();
      scanner.receivePart(btcReply(wire).toWireString());
      final parsed = scanner.parse();
      expect(parsed.signature, rawSignature);
      expect(parsed.signatureBase64, base64Encode(rawSignature));
      expect(parsed.publicKey, pubKeyCompressed);
    });

    test('accepts the raw 65-byte form newer firmware sends', () {
      final scanner = request.scanner();
      scanner.receivePart(btcReply(rawSignature).toWireString());
      final parsed = scanner.parse();
      expect(parsed.signature, rawSignature);
      expect(parsed.signatureBase64, base64Encode(rawSignature));
    });

    test('an empty signature is the typed segwit refusal, not zero bytes', () {
      final scanner = request.scanner();
      scanner.receivePart(btcReply(Uint8List(0)).toWireString());
      expect(scanner.parse, throwsSdkError('empty-signature'));
    });

    test('BIP-137 header ranges match address kinds', () {
      expect(
        verifyBtcMessageHeader(VerifyBtcMessageHeaderArgs(
          address: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
          signature: rawSignature,
        )).ok,
        isTrue,
      );
      final wrongForSegwit = verifyBtcMessageHeader(VerifyBtcMessageHeaderArgs(
        address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
        signature: rawSignature,
      ));
      expect(wrongForSegwit.ok, isFalse);
      final taproot = verifyBtcMessageHeader(VerifyBtcMessageHeaderArgs(
        address:
            'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297',
        signature: rawSignature,
      ));
      expect(taproot.ok, isTrue);
      expect(taproot.checked, isFalse);
    });
  });

  // --- Minimal PSBT construction helpers (BIP-174 v0) ----------------------

  Uint8List compactSize(int n) {
    if (n < 0xfd) return Uint8List.fromList([n]);
    return Uint8List.fromList([0xfd, n & 0xff, n >> 8]);
  }

  Uint8List keyValue(int keyType, Uint8List keyData, Uint8List value) {
    final key = concatBytes([
      Uint8List.fromList([keyType]),
      keyData,
    ]);
    return concatBytes(
        [compactSize(key.length), key, compactSize(value.length), value]);
  }

  Uint8List unsignedTx(Uint8List outputScript) {
    return concatBytes([
      Uint8List.fromList([2, 0, 0, 0]), // version
      compactSize(1), // one input
      Uint8List.fromList(List<int>.filled(32, 0xaa)), // prev txid
      Uint8List.fromList([0, 0, 0, 0]), // vout
      compactSize(0), // empty scriptSig
      Uint8List.fromList([0xff, 0xff, 0xff, 0xff]), // sequence
      compactSize(1), // one output
      Uint8List.fromList([0x40, 0x42, 0x0f, 0, 0, 0, 0, 0]), // 1_000_000 sats
      concatBytes([compactSize(outputScript.length), outputScript]),
      Uint8List.fromList([0, 0, 0, 0]), // locktime
    ]);
  }

  Uint8List psbtOf(
    Uint8List tx,
    List<List<Uint8List>> inputMaps, [
    List<List<Uint8List>> outputMaps = const [[]],
  ]) {
    final sep = Uint8List.fromList([0]);
    return concatBytes([
      Uint8List.fromList([0x70, 0x73, 0x62, 0x74, 0xff]),
      keyValue(0x00, Uint8List(0), tx),
      sep,
      for (final entries in inputMaps) ...[...entries, sep],
      for (final entries in outputMaps) ...[...entries, sep],
    ]);
  }

  group('PSBT verification', () {
    final script =
        Uint8List.fromList([0x00, 0x14, ...List<int>.filled(20, 0x11)]);
    final tx = unsignedTx(script);
    final sent = psbtOf(tx, [[]]);
    final partialSig = keyValue(
        0x02, pubKeyCompressed, Uint8List.fromList(List<int>.filled(71, 0x30)));
    final signed = psbtOf(tx, [
      [partialSig]
    ]);

    test('accepts the same transaction with a signature added', () {
      final result = verifySignedPsbt(
          VerifySignedPsbtArgs(sentPsbt: sent, signedPsbt: signed));
      expect(result.ok, isTrue);
      expect(result.checked, isTrue);
    });

    test(
        'refuses a returned PSBT whose unsigned tx differs (the anti-replay binding)',
        () {
      final otherTx = unsignedTx(
          Uint8List.fromList([0x00, 0x14, ...List<int>.filled(20, 0x22)]));
      final swapped = psbtOf(otherTx, [
        [partialSig]
      ]);
      final result = verifySignedPsbt(
          VerifySignedPsbtArgs(sentPsbt: sent, signedPsbt: swapped));
      expect(result.ok, isFalse);
      expect(result.reason, contains('different transaction'));
    });

    test(
        'refuses an input that came back finalized when it was not sent that way',
        () {
      final finalScript =
          keyValue(0x07, Uint8List(0), Uint8List.fromList([0xde, 0xad]));
      final finalized = psbtOf(tx, [
        [partialSig, finalScript]
      ]);
      final result = verifySignedPsbt(
          VerifySignedPsbtArgs(sentPsbt: sent, signedPsbt: finalized));
      expect(result.ok, isFalse);
      expect(result.reason, contains('finalized'));
    });

    test('refuses a substituted finalized script even when one was sent', () {
      final sentFinal =
          keyValue(0x07, Uint8List(0), Uint8List.fromList([0x01, 0x02]));
      final returnedFinal =
          keyValue(0x07, Uint8List(0), Uint8List.fromList([0x0e, 0x0f]));
      final result = verifySignedPsbt(VerifySignedPsbtArgs(
        sentPsbt: psbtOf(tx, [
          [sentFinal]
        ]),
        signedPsbt: psbtOf(tx, [
          [returnedFinal, partialSig]
        ]),
      ));
      expect(result.ok, isFalse);
      expect(result.reason, contains('different finalized'));
    });

    test('refuses a reply that signed nothing', () {
      final result = verifySignedPsbt(
          VerifySignedPsbtArgs(sentPsbt: sent, signedPsbt: psbtOf(tx, [[]])));
      expect(result.ok, isFalse);
    });

    test('parses PSBT replies through the chain module', () {
      final request =
          btc.generatePsbtSignRequest(BtcPsbtSignRequestProps(psbt: sent));
      final scanner = request.scanner();
      scanner.receivePart(
          Ur('crypto-psbt', cborEncode(cbBytes(signed))).toWireString());
      expect(scanner.parse().psbt, signed);
    });
  });

  group('Bitcoin family via crypto-psbt-extend', () {
    final psbt = Uint8List.fromList(
        [0x70, 0x73, 0x62, 0x74, 0xff, ...List<int>.generate(40, (i) => i)]);

    test('doge/ltc/dash requests carry the PSBT plus the coin id', () {
      for (final (coin, id) in [
        (PsbtCoin.doge, 3),
        (PsbtCoin.ltc, 2),
        (PsbtCoin.dash, 5),
      ]) {
        final request = btc.generatePsbtSignRequest(
            BtcPsbtSignRequestProps(psbt: psbt, coin: coin));
        expect(request.ur.type, 'crypto-psbt-extend');
        final map = asMap(cborDecode(request.ur.cbor))!;
        expect(asBytes(mapGet(map, 1)), psbt);
        expect(asUint(mapGet(map, 2))!.toInt(), id);
        expect(request.replyTypes, contains('crypto-psbt-extend'));
      }
    });

    test('parses both reply shapes (bare bytes and the extend map)', () {
      final request = btc.generatePsbtSignRequest(
          BtcPsbtSignRequestProps(psbt: psbt, coin: PsbtCoin.doge));
      final extendReply = Ur(
        'crypto-psbt-extend',
        cborEncode(
          cbMap([
            (1, cbBytes(psbt)),
            (2, cbUint(3)),
          ]),
        ),
      );
      final scanner = request.scanner();
      scanner.receivePart(extendReply.toWireString());
      expect(scanner.parse().psbt, psbt);

      final plain = btc.parsePsbt(Ur('crypto-psbt', cborEncode(cbBytes(psbt))));
      expect(plain.psbt, psbt);
    });

    test('plain btc still rides crypto-psbt', () {
      final request =
          btc.generatePsbtSignRequest(BtcPsbtSignRequestProps(psbt: psbt));
      expect(request.ur.type, 'crypto-psbt');
    });
  });

  group('byte-exact golden requests vs an independent implementation', () {
    final fixture = jsonDecode(
            File('test/fixtures/reference-golden.json').readAsStringSync())
        as Map<String, dynamic>;
    final cases =
        (fixture['cases'] as List<dynamic>).cast<Map<String, dynamic>>();
    final golden =
        BtcChain(EraConnectConfig(origin: fixture['origin'] as String));
    final goldenRequestId = fixture['requestIdHex'] as String;

    Map<String, dynamic> caseByName(String name) =>
        cases.firstWhere((c) => c['name'] == name);

    void expectGolden(String name, Ur ur) {
      final expected = caseByName(name);
      expect(ur.type, expected['urType']);
      expect(bytesToHex(ur.cbor), expected['requestCborHex']);
      expect(ur.toWireString(), expected['requestUr']);
    }

    test('btc_psbt', () {
      final psbt = Uint8List.fromList(
          [0x70, 0x73, 0x62, 0x74, 0xff, ...List<int>.generate(60, (i) => i)]);
      final req =
          golden.generatePsbtSignRequest(BtcPsbtSignRequestProps(psbt: psbt));
      expectGolden('btc_psbt', req.ur);
      expect(req.requestId, isNull);
    });

    test('btc_message', () {
      final message = Uint8List.fromList(List<int>.generate(40, (i) => i));
      final req = golden.generateMessageSignRequest(BtcMessageSignRequestProps(
        requestId: goldenRequestId,
        message: message,
        path: "m/84'/0'/0'/0/2",
        xfp: '22222222',
        address: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
      ));
      expectGolden('btc_message', req.ur);
    });
  });

  group('scanner integration', () {
    test('a stray wallet-export frame is rejected before the decoder', () {
      final request = btc.generateMessageSignRequest(BtcMessageSignRequestProps(
        requestId: requestId,
        message: signData,
        path: "m/84'/0'/0'/0/0",
        xfp: '22222222',
        address: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
      ));
      final scanner = request.scanner();
      final stray = Ur('crypto-multi-accounts',
          cborEncode(cbMap([(1, cbBytes(requestId))])));
      final first = scanner.receivePart(stray.toWireString());
      expect(first, isA<ScanRejected>());
    });
  });
}
