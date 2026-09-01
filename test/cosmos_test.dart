import 'dart:typed_data';

import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/cosmos.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:era_connect/src/verify/cosmos.dart';
import 'package:test/test.dart';

void main() {
  final cosmos = CosmosChain(const EraConnectConfig(origin: 'Rest Test'));
  final requestId = Uint8List.fromList(List.generate(16, (i) => i + 1));

  group('Cosmos', () {
    // Synthetic key: priv = 32 bytes of 0x05. The public key and the two
    // RFC6979 signatures below are the deterministic outputs the TypeScript
    // suite computes live (this SDK deliberately cannot sign).
    final pub = hexToBytes(
        '0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7');
    final aminoDoc = utf8Encode('{"chain_id":"cosmoshub-4","msgs":[]}');
    // sign(sha256(aminoDoc), priv) — compact r||s.
    final sigSha = hexToBytes(
        '03f82dc11d6c617045c98d300e1941e5e57017890a2712bb45838f87ed544ff1'
        '3beed5a9853e1084339d22c280f0cba07ed76f4308b92bce6d5e3ef2f332aaaa');
    // sign(keccak256(aminoDoc), priv) — compact r||s.
    final sigKeccak = hexToBytes(
        '02d1e4f753b2ca852c8d6acbd570078cf82b6c0bffdedb490664b6e970d20a75'
        '02c54f3164beb107850f385a46317b78b37d15f8f6c6c97b82f86810d88c38e1');

    test('cosmos request shape + roundtrip with sha256 digest', () {
      final request = cosmos.generateSignRequest(CosmosSignRequestProps(
        requestId: requestId,
        signData: aminoDoc,
        dataType: 1,
        path: "m/44'/118'/0'/0/0",
        xfp: 'deadbeef',
        address: 'cosmos1xyz',
      ));
      final map = asMap(cborDecode(request.ur.cbor))!;
      expect(request.ur.type, 'cosmos-sign-request');
      expect(asUint(mapGet(map, 3))!.toInt(), 1);

      final reply = Ur(
        'cosmos-signature',
        cborEncode(cbMap([
          (1, cbTag(37, cbBytes(requestId))),
          (2, cbBytes(sigSha)),
          (3, cbBytes(pub)),
        ])),
      );
      final scanner = request.scanner();
      scanner.receivePart(reply.toWireString());
      final parsed = scanner.parse();
      final verdict = verifyCosmosSignature(VerifyCosmosSignatureArgs(
        signData: aminoDoc,
        digest: CosmosDigest.sha256,
        signature: parsed.signature,
        publicKey: parsed.publicKey!,
        expectedPublicKey: pub,
      ));
      expect(verdict.ok, isTrue);
    });

    test(
        'ethermint request maps dataType and rides evm-sign-request with keccak',
        () {
      final request =
          cosmos.generateEthermintSignRequest(EthermintSignRequestProps(
        requestId: requestId,
        signData: aminoDoc,
        dataType: 1, // amino -> wire 2
        path: "m/44'/60'/0'/0/0",
        xfp: 'deadbeef',
        address: '0x1111111111111111111111111111111111111111',
      ));
      final map = asMap(cborDecode(request.ur.cbor))!;
      expect(request.ur.type, 'evm-sign-request');
      expect(asUint(mapGet(map, 3))!.toInt(), 2);
      expect(asBytes(mapGet(map, 6))!.length, 42); // ASCII of the 0x string

      final reply = Ur(
        'evm-signature',
        cborEncode(cbMap([
          (1, cbTag(37, cbBytes(requestId))),
          (2, cbBytes(sigKeccak)),
        ])),
      );
      final parsed =
          cosmos.parseSignature(reply, ExpectedReply(requestId: requestId));
      expect(parsed.publicKey, isNull);
      final verdict = verifyCosmosSignature(VerifyCosmosSignatureArgs(
        signData: aminoDoc,
        digest: CosmosDigest.keccak256,
        signature: parsed.signature,
        publicKey: pub,
      ));
      expect(verdict.ok, isTrue);
    });
  });
}
