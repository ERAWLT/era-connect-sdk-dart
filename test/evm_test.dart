import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/evm.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/crypto/digests.dart';
import 'package:era_connect/src/crypto/secp256k1.dart';
import 'package:era_connect/src/scan/ur_scanner.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:era_connect/src/verify/evm.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

Matcher throwsSdkErrorCode(String code) =>
    throwsA(isA<EraSdkError>().having((e) => e.code, 'code', code));

/// Deterministic (RFC 6979) low-S secp256k1 signing over a raw digest —
/// test-only: the SDK itself never holds keys. Mirrors what the reference implementation
/// suite gets from its curve library.
({Uint8List bytes, int recovery}) signDigest(
    Uint8List digest, Uint8List privateKey) {
  final domain = pc.ECCurve_secp256k1();
  final d = bytesToBigint(privateKey);
  final signer = pc.ECDSASigner(null, pc.HMac(pc.SHA256Digest(), 64))
    ..init(true, pc.PrivateKeyParameter(pc.ECPrivateKey(d, domain)));
  final ecSig = signer.generateSignature(digest) as pc.ECSignature;
  var s = ecSig.s;
  if (s > (domain.n >> 1)) s = domain.n - s; // low-S, as the device emits
  final out = Uint8List(64);
  final rBytes = bigintToBytes(ecSig.r);
  final sBytes = bigintToBytes(s);
  out.setAll(32 - rBytes.length, rBytes);
  out.setAll(64 - sBytes.length, sBytes);
  final publicKey = Uint8List.fromList((domain.G * d)!.getEncoded(true));
  for (var recovery = 0; recovery < 2; recovery++) {
    if (equalBytes(Secp256k1.recover(out, digest, recovery), publicKey)) {
      return (bytes: out, recovery: recovery);
    }
  }
  throw StateError('no recovery id matched');
}

Uint8List uncompressedPublicKey(Uint8List privateKey) {
  final domain = pc.ECCurve_secp256k1();
  final d = bytesToBigint(privateKey);
  return Uint8List.fromList((domain.G * d)!.getEncoded(false));
}

Ur evmReply(Uint8List id, Uint8List signature,
    [String type = 'eth-signature']) {
  return Ur(
    type,
    cborEncode(cbMap([
      (1, cbTag(37, cbBytes(id))), // the device ALWAYS wraps the echo in tag 37
      (2, cbBytes(signature)),
    ])),
  );
}

void main() {
  // Device replies synthesized with test keys: the exact CBOR shapes the
  // firmware emits, signed so the verification helpers have something real
  // to recover. No fixture material from any private source.
  final era = EvmChain(const EraConnectConfig(origin: 'Test Wallet'));
  final requestId = Uint8List.fromList(List.generate(16, (i) => i + 1));
  final otherRequestId = Uint8List.fromList(List.filled(16, 9));

  final privKey = Uint8List.fromList(List.filled(32, 7));
  final pubKeyUncompressed = uncompressedPublicKey(privKey);
  final evmAddress = keccak256(pubKeyUncompressed.sublist(1)).sublist(12);
  final signData = Uint8List.fromList(List.generate(48, (i) => i * 3));

  group('EVM reply parsing + verification', () {
    final request = era.generateSignRequest(EvmSignRequestProps(
      requestId: requestId,
      signData: signData,
      dataType: EvmDataType.transaction,
      path: "m/44'/60'/0'/0/0",
      xfp: '11111111',
      chainId: 137,
      address: evmAddress,
    ));

    final digest = keccak256(signData);
    final sig = signDigest(digest, privKey);

    test('round-trips a typed-tx reply through the request scanner', () {
      final signature = concatBytes([
        sig.bytes,
        Uint8List.fromList([sig.recovery])
      ]);
      final scanner = request.scanner();
      final feed =
          scanner.receivePart(evmReply(requestId, signature).toWireString());
      expect(feed, isA<ScanComplete>());
      final parsed = scanner.parse();
      expect(parsed.recoveryId, sig.recovery);
      expect(parsed.v, BigInt.from(sig.recovery));
      final result = verifyEvmSignature(VerifyEvmSignatureArgs(
        signData: signData,
        dataType: EvmDataType.transaction,
        signature: parsed.signature,
        address: evmAddress,
      ));
      expect(result.ok, isTrue);
      expect(result.checked, isTrue);
    });

    test('accepts a legacy EIP-155 multi-byte v for chainId 137 (v = 309/310)',
        () {
      final v = sig.recovery + 137 * 2 + 35; // 309 or 310 — two bytes
      final vBytes = Uint8List.fromList([v >> 8, v & 0xff]);
      final signature = concatBytes([sig.bytes, vBytes]);
      final parsed = era.parseSignature(
        evmReply(requestId, signature),
        ExpectedReply(requestId: requestId),
      );
      expect(parsed.signature.length, 66);
      expect(parsed.recoveryId, sig.recovery);
      final result = verifyEvmSignature(VerifyEvmSignatureArgs(
        signData: signData,
        dataType: EvmDataType.transaction,
        signature: parsed.signature,
        address: evmAddress,
      ));
      expect(result.ok, isTrue);
      expect(result.checked, isTrue);
    });

    test('refuses a reply echoing a different request id', () {
      final signature = concatBytes([
        sig.bytes,
        Uint8List.fromList([sig.recovery])
      ]);
      final scanner = request.scanner();
      scanner.receivePart(evmReply(otherRequestId, signature).toWireString());
      expect(() => scanner.parse(), throwsSdkErrorCode('request-id-mismatch'));
    });

    test(
        'pins the reply type before the decoder: a wallet-export frame is rejected',
        () {
      final scanner = request.scanner();
      final stray = Ur(
        'crypto-multi-accounts',
        cborEncode(cbMap([(1, cbBytes(requestId))])),
      );
      final first = scanner.receivePart(stray.toWireString());
      expect(first, isA<ScanRejected>());
      // Rejected frames are deliberately NOT remembered (junk must not fill
      // the dedup budget) — the repeat counter is what keeps the noise down.
      final second = scanner.receivePart(stray.toWireString());
      expect(second, isA<ScanRejected>());
      expect((second as ScanRejected).rejection.repeated, 2);
    });

    test('verification catches a signature by the wrong key', () {
      final wrongSig =
          signDigest(digest, Uint8List.fromList(List.filled(32, 8)));
      final signature = concatBytes([
        wrongSig.bytes,
        Uint8List.fromList([wrongSig.recovery])
      ]);
      final result = verifyEvmSignature(VerifyEvmSignatureArgs(
        signData: signData,
        dataType: EvmDataType.transaction,
        signature: signature,
        address: evmAddress,
      ));
      expect(result.ok, isFalse);
    });

    test('personal_sign digest includes the EIP-191 prefix', () {
      final prefixed = concatBytes([
        Uint8List.fromList([0x19]),
        utf8Encode('Ethereum Signed Message:\n${signData.length}'),
        signData,
      ]);
      final msgSig = signDigest(keccak256(prefixed), privKey);
      final signature = concatBytes([
        msgSig.bytes,
        Uint8List.fromList([27 + msgSig.recovery])
      ]);
      final result = verifyEvmSignature(VerifyEvmSignatureArgs(
        signData: signData,
        dataType: EvmDataType.personalMessage,
        signature: signature,
        address: evmAddress,
      ));
      expect(result.ok, isTrue);
      expect(result.checked, isTrue);
    });

    test('EIP-712 is honestly unverifiable client-side', () {
      final result = verifyEvmSignature(VerifyEvmSignatureArgs(
        signData: signData,
        dataType: EvmDataType.typedData,
        signature: Uint8List(65),
        address: evmAddress,
      ));
      expect(result.ok, isTrue);
      expect(result.checked, isFalse);
    });
  });

  group('byte-exact golden requests vs the reference implementation', () {
    final fixture = jsonDecode(
      File('test/fixtures/reference-golden.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    final golden = EvmChain(
      EraConnectConfig(origin: fixture['origin'] as String),
    );
    final goldenRequestId = fixture['requestIdHex'] as String;

    Map<String, dynamic> caseByName(String name) {
      final cases = fixture['cases'] as List<dynamic>;
      return cases.cast<Map<String, dynamic>>().firstWhere(
            (c) => c['name'] == name,
            orElse: () => throw StateError('fixture case $name missing'),
          );
    }

    void expectGolden(String name, Ur ur) {
      final c = caseByName(name);
      expect(ur.type, c['urType']);
      expect(bytesToHex(ur.cbor), c['requestCborHex']);
      expect(ur.toWireString(), c['requestUr']);
    }

    final goldenSignData = Uint8List.fromList(List.generate(40, (i) => i));
    final bigSignData = Uint8List.fromList(List.generate(700, (i) => i % 251));
    final address = Uint8List.fromList(List.filled(20, 0xab));

    test('evm_tx_bsc', () {
      final req = golden.generateSignRequest(EvmSignRequestProps(
        requestId: goldenRequestId,
        signData: goldenSignData,
        dataType: EvmDataType.transaction,
        path: "m/44'/60'/0'/0/0",
        xfp: '11111111',
        chainId: 56,
        address: address,
      ));
      expectGolden('evm_tx_bsc', req.ur);
    });

    test('evm_tx_aurora_large_chain_id', () {
      final req = golden.generateSignRequest(EvmSignRequestProps(
        requestId: goldenRequestId,
        signData: bigSignData,
        dataType: EvmDataType.typedTransaction,
        path: "m/44'/60'/0'/0/3",
        xfp: '11111111',
        chainId: 1313161554,
        address: address,
      ));
      expectGolden('evm_tx_aurora_large_chain_id', req.ur);
    });

    test('evm_personal_message', () {
      final req = golden.generateSignRequest(EvmSignRequestProps(
        requestId: goldenRequestId,
        signData: goldenSignData,
        dataType: EvmDataType.personalMessage,
        path: "m/44'/60'/0'/0/0",
        xfp: '11111111',
        chainId: 1,
        address: address,
      ));
      expectGolden('evm_personal_message', req.ur);
    });

    test('evm_typed_data', () {
      final req = golden.generateSignRequest(EvmSignRequestProps(
        requestId: goldenRequestId,
        signData: goldenSignData,
        dataType: EvmDataType.typedData,
        path: "m/44'/60'/0'/0/1",
        xfp: '11111111',
        chainId: 137,
        address: address,
      ));
      expectGolden('evm_typed_data', req.ur);
    });
  });

  group('request property validation', () {
    test('a chainId over the u32 device ceiling is refused, not truncated', () {
      expect(
        () => era.generateSignRequest(EvmSignRequestProps(
          requestId: requestId,
          signData: signData,
          dataType: EvmDataType.transaction,
          path: "m/44'/60'/0'/0/0",
          xfp: '11111111',
          chainId: 0x100000000,
        )),
        throwsSdkErrorCode('invalid-props'),
      );
    });

    test('a transaction request without a chainId is refused', () {
      expect(
        () => era.generateSignRequest(EvmSignRequestProps(
          requestId: requestId,
          signData: signData,
          dataType: EvmDataType.transaction,
          path: "m/44'/60'/0'/0/0",
          xfp: '11111111',
        )),
        throwsSdkErrorCode('invalid-props'),
      );
    });
  });
}
