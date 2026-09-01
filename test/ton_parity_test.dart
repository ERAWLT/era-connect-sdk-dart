import 'dart:convert';
import 'dart:io';

import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/chains/ton.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/verify/ton.dart';
import 'package:test/test.dart';

/// Parity fixture generated from the TypeScript SDK: every request must
/// rebuild byte for byte, every recorded reply must parse (or refuse) the
/// same way, and every verify verdict must agree.
void main() {
  final fixture = jsonDecode(
    File('test/fixtures/parity/ton.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final publicKey = hexToBytes(fixture['publicKeyHex'] as String);
  final requestIdHex = fixture['requestIdHex'] as String;

  TonSignRequestProps propsFrom(Map<String, dynamic> props) {
    final requestId = props.containsKey('requestId')
        ? props['requestId'] as Object
        : hexToBytes(props['requestIdRawHex'] as String);
    return TonSignRequestProps(
      requestId: requestId,
      signData: hexToBytes(props['signDataHex'] as String),
      dataType: props['dataType'] as int?,
      path: props['path'] as String,
      xfp: props['xfp'] as Object,
      address: props['address'] as String?,
      origin: props['origin'] as String?,
    );
  }

  group('TON parity with the TypeScript SDK', () {
    test('rebuilds every request byte for byte', () {
      for (final entry in fixture['requests'] as List<dynamic>) {
        final req = entry as Map<String, dynamic>;
        final name = req['name'] as String;
        final request = TonChain().generateSignRequest(
            propsFrom(req['props'] as Map<String, dynamic>));
        expect(request.ur.type, req['urType'], reason: name);
        expect(bytesToHex(request.ur.cbor), req['cborHex'], reason: name);
      }
    });

    test('parses (or refuses) and verifies every recorded reply', () {
      for (final entry in fixture['replies'] as List<dynamic>) {
        final reply = entry as Map<String, dynamic>;
        final name = reply['name'] as String;
        final expectedId = reply['expectedRequestId'] as String;
        final failure = reply['expect'] as String?;
        if (failure != null) {
          expect(failure, startsWith('throws:'), reason: name);
          final code = failure.substring('throws:'.length);
          expect(
            () => TonChain().parseSignature(
              reply['ur'] as String,
              ExpectedReply(requestId: expectedId),
            ),
            throwsA(isA<EraSdkError>().having((e) => e.code, 'code', code)),
            reason: name,
          );
          continue;
        }
        final parsed = TonChain().parseSignature(
          reply['ur'] as String,
          ExpectedReply(requestId: expectedId),
        );
        final parsedExpect = reply['parsed'] as Map<String, dynamic>;
        expect(bytesToHex(parsed.requestId), parsedExpect['requestIdHex'],
            reason: name);
        expect(bytesToHex(parsed.signature), parsedExpect['signatureHex'],
            reason: name);
        final verify = reply['verify'] as Map<String, dynamic>;
        final verdict = verifyTonSignature(VerifyTonSignatureArgs(
          signData: hexToBytes(verify['signDataHex'] as String),
          dataType: verify['dataType'] as int,
          signature: parsed.signature,
          publicKey: publicKey,
        ));
        final shouldVerify = verify['verdict'] == 'verify:true';
        expect(verdict.ok, shouldVerify,
            reason: '$name: ${verdict.reason ?? 'ok'}');
        if (shouldVerify) expect(verdict.checked, isTrue, reason: name);
      }
    });

    test('the scanner path accepts the recorded transaction reply', () {
      final requests = fixture['requests'] as List<dynamic>;
      final txRequest = requests.first as Map<String, dynamic>;
      final request = TonChain().generateSignRequest(
          propsFrom(txRequest['props'] as Map<String, dynamic>));
      final replies = fixture['replies'] as List<dynamic>;
      final stringEcho = replies.first as Map<String, dynamic>;
      final scanner = request.scanner();
      scanner.receivePart(stringEcho['ur'] as String);
      final parsed = scanner.parse();
      expect(bytesToHex(parsed.requestId), requestIdHex);
    });

    test('rejects the verify-only tampered args', () {
      for (final entry in fixture['verifyOnly'] as List<dynamic>) {
        final args = entry as Map<String, dynamic>;
        final name = args['name'] as String;
        final verdict = verifyTonSignature(VerifyTonSignatureArgs(
          signData: hexToBytes(args['signDataHex'] as String),
          dataType: args['dataType'] as int,
          signature: hexToBytes(args['signatureHex'] as String),
          publicKey: publicKey,
        ));
        expect(verdict.ok, args['verdict'] == 'verify:true', reason: name);
      }
    });
  });
}
