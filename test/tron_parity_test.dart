import 'dart:convert';
import 'dart:io';

import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/chains/tron.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/tron_proto/gzip.dart';
import 'package:era_connect/src/verify/result.dart';
import 'package:era_connect/src/verify/tron.dart';
import 'package:test/test.dart';

Matcher throwsSdkError(String code) =>
    throwsA(isA<EraSdkError>().having((e) => e.code, 'code', code));

/// Parity against the TypeScript SDK: requests rebuilt from the recorded
/// props must produce the identical post-gunzip protobuf (gzip BYTES are not
/// comparable across implementations), and the recorded replies — genuine,
/// tampered and rebuilt — must parse and verify to the recorded verdicts.
void main() {
  final fixture = jsonDecode(
    File('test/fixtures/parity/tron.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final era = TronChain(EraConnectConfig(origin: fixture['origin'] as String));
  final requestId = fixture['requestId'] as String;
  final owner = fixture['owner'] as String;
  final rawData = hexToBytes(fixture['rawDataHex'] as String);
  final path = fixture['path'] as String;
  final xfp = fixture['xfp'] as String;
  final blockJson = fixture['latestBlock'] as Map<String, dynamic>;
  final latestBlock = TronLatestBlock(
    hash: blockJson['hash'] as String,
    number: blockJson['number'] as int,
    timestamp: blockJson['timestamp'] as int,
  );

  group('tron parity: requests rebuild to the recorded protobuf', () {
    final requests =
        (fixture['requests'] as List<dynamic>).cast<Map<String, dynamic>>();
    for (final request in requests) {
      test(request['name'] as String, () {
        final props = request['props'] as Map<String, dynamic>;
        final displayJson = props['display'] as Map<String, dynamic>?;
        final req = era.generateSignRequest(TronSignRequestProps(
          requestId: requestId,
          rawData: rawData,
          path: path,
          xfp: xfp,
          latestBlock: latestBlock,
          display: displayJson == null
              ? null
              : TronSignDisplay(
                  token: displayJson['token'] as String?,
                  contractAddress: displayJson['contractAddress'] as String?,
                  from: displayJson['from'] as String?,
                  to: displayJson['to'] as String?,
                  value: displayJson['value'] as String?,
                  memo: displayJson['memo'] as String?,
                  fee: displayJson['fee'] as int?,
                  decimals: displayJson['decimals'] as int?,
                ),
          timestamp: props['timestamp'] as int?,
          origin: props['origin'] as String?,
        ));
        expect(req.ur.type, request['urType']);
        final map = cborDecode(req.ur.cbor);
        final compressed = asBytes(mapGet(map, 1));
        expect(compressed, isNotNull);
        expect(
          bytesToHex(gunzipCapped(compressed!, 64 * 1024)),
          request['protoHex'],
        );
        expect(asText(mapGet(map, 2)), request['origin']);
      });
    }
  });

  group('tron parity: replies parse and verify to the recorded verdicts', () {
    final replies =
        (fixture['replies'] as List<dynamic>).cast<Map<String, dynamic>>();
    for (final reply in replies) {
      test(reply['name'] as String, () {
        final verdict = reply['verdict'] as String;
        if (verdict.startsWith('throws:')) {
          expect(
            () => era.parseSignature(
              reply['ur'] as String,
              ExpectedReply(requestId: requestId),
            ),
            throwsSdkError(verdict.substring('throws:'.length)),
          );
          return;
        }
        final parsed = era.parseSignature(
          reply['ur'] as String,
          ExpectedReply(requestId: requestId),
        );
        final expected = reply['parsed'] as Map<String, dynamic>;
        expect(bytesToHex(parsed.requestId), expected['requestIdHex']);
        expect(parsed.txId, expected['txId']);
        expect(parsed.rawTx, expected['rawTx']);
        expect(bytesToHex(parsed.signedTx.rawData), expected['rawDataHex']);
        expect(
          parsed.signedTx.signatures.map(bytesToHex).toList(),
          (expected['signaturesHex'] as List<dynamic>).cast<String>(),
        );
        final result = verifyTronSignature(VerifyTronSignatureArgs(
          rawData: rawData,
          from: owner,
          latestBlock: latestBlock,
          signedTx: parsed.signedTx,
        ));
        if (verdict == 'verify:true') {
          expect(result, isA<Verified>());
        } else {
          expect(verdict, 'verify:false');
          expect(result, isA<Failed>());
        }
      });
    }
  });

  group('tron parity: verify verdicts over recorded signed frames', () {
    final verifies =
        (fixture['verifies'] as List<dynamic>).cast<Map<String, dynamic>>();
    for (final entry in verifies) {
      test(entry['name'] as String, () {
        final result = verifyTronSignature(VerifyTronSignatureArgs(
          rawData: rawData,
          from: owner,
          latestBlock: entry['omitLatestBlock'] == true ? null : latestBlock,
          signedTx: entry['signedTxHex'] as String,
        ));
        if (entry['verdict'] == 'verified') {
          expect(result, isA<Verified>());
        } else {
          expect(entry['verdict'], 'verify:false');
          expect(result, isA<Failed>());
        }
      });
    }
  });
}
