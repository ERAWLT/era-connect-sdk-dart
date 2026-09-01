import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:era_connect/src/accounts/derive.dart';
import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/chains/tron.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/crypto/digests.dart';
import 'package:era_connect/src/crypto/secp256k1.dart';
import 'package:era_connect/src/tron_proto/gzip.dart';
import 'package:era_connect/src/tron_proto/messages.dart' show SignedTronTx;
import 'package:era_connect/src/tron_proto/wire.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:era_connect/src/verify/result.dart';
import 'package:era_connect/src/verify/tron.dart';
import 'package:pointycastle/api.dart' show PrivateKeyParameter;
import 'package:pointycastle/digests/sha256.dart' show SHA256Digest;
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/macs/hmac.dart' show HMac;
import 'package:pointycastle/signers/ecdsa_signer.dart' show ECDSASigner;
import 'package:test/test.dart';

Matcher throwsSdkError(String code) =>
    throwsA(isA<EraSdkError>().having((e) => e.code, 'code', code));

// ---------------------------------------------------------------------------
// Test-only secp256k1 signing (the SDK deliberately has no signer): RFC 6979
// deterministic k, low-S normalized — the same semantics as the TypeScript
// test suite's @noble/curves signer.
// ---------------------------------------------------------------------------

final ECDomainParameters _domain = ECCurve_secp256k1();

final Uint8List privKey = Uint8List.fromList(List.filled(32, 7));
final Uint8List pubKeyCompressed = Uint8List.fromList(
  (_domain.G * bytesToBigint(privKey))!.getEncoded(true),
);

void _writeScalar(Uint8List out, int offset, BigInt value) {
  final bytes = bigintToBytes(value);
  out.setAll(offset + 32 - bytes.length, bytes);
}

/// A 65-byte `r || s || recovery` signature over [digest], as the device
/// emits them.
Uint8List signDigest(Uint8List digest) {
  final signer = ECDSASigner(null, HMac(SHA256Digest(), 64));
  signer.init(
    true,
    PrivateKeyParameter<ECPrivateKey>(
      ECPrivateKey(bytesToBigint(privKey), _domain),
    ),
  );
  final sig = signer.generateSignature(digest) as ECSignature;
  var s = sig.s;
  if (s > (_domain.n >> 1)) s = _domain.n - s;
  final out = Uint8List(65);
  _writeScalar(out, 0, sig.r);
  _writeScalar(out, 32, s);
  for (var recoveryId = 0; recoveryId < 4; recoveryId++) {
    try {
      final recovered = Secp256k1.recover(
        Uint8List.sublistView(out, 0, 64),
        digest,
        recoveryId,
      );
      if (equalBytes(recovered, pubKeyCompressed)) {
        out[64] = recoveryId;
        return out;
      }
    } on ArgumentError {
      // this recovery id names no curve point; try the next
    }
  }
  throw StateError('no recovery id reproduces the public key');
}

// ---------------------------------------------------------------------------
// Synthetic Tron transactions + firmware-shaped replies (the exact protobuf
// shapes the firmware emits, mirrored from the TypeScript test suite).
// ---------------------------------------------------------------------------

const String _transferUrl = 'type.googleapis.com/protocol.TransferContract';

Uint8List transferContractParam(Uint8List owner, Uint8List to, int amount) {
  return ProtoWriter()
      .bytesField(1, owner)
      .bytesField(2, to)
      .varintField(3, BigInt.from(amount))
      .finish();
}

Uint8List tronRawData({
  required Uint8List owner,
  required Uint8List to,
  required int amount,
  required int timestamp,
  required int expiration,
}) {
  final contract = ProtoWriter()
      .varintField(1, BigInt.one) // TransferContract
      .messageField(
        2,
        ProtoWriter()
            .stringField(1, _transferUrl)
            .bytesField(2, transferContractParam(owner, to, amount))
            .finish(),
      )
      .finish();
  return ProtoWriter()
      .bytesField(1, Uint8List.fromList([0x12, 0x34])) // ref_block_bytes
      .bytesField(4, Uint8List.fromList(List.filled(8, 0x56))) // ref_block_hash
      .varintField(8, BigInt.from(expiration))
      .messageField(11, contract)
      .varintField(14, BigInt.from(timestamp))
      .finish();
}

Ur tronReply(String id, Uint8List rawData) {
  final digest = sha256(rawData);
  final signature = signDigest(digest);
  final frame =
      ProtoWriter().bytesField(1, rawData).bytesField(2, signature).finish();
  final result = ProtoWriter()
      .stringField(1, id)
      .stringField(2, bytesToHex(digest))
      .stringField(3, bytesToHex(frame))
      .finish();
  final payload = ProtoWriter()
      .varintField(1, BigInt.from(9))
      .messageField(7, result)
      .finish();
  final base = ProtoWriter()
      .varintField(1, BigInt.one)
      .stringField(2, 'keystone qrcode')
      .messageField(3, payload)
      .finish();
  return Ur(
    'keystone-sign-result',
    cborEncode(cbMap([(1, cbBytes(gzipCompress(base)))])),
  );
}

void main() {
  final era = TronChain(const EraConnectConfig(origin: 'Test Wallet'));
  final requestId = Uint8List.fromList([for (var i = 0; i < 16; i++) i + 1]);
  final tronOwner = tronAddressFromPublicKey(pubKeyCompressed);

  final ownerRaw = Uint8List.fromList(List.filled(21, 0x41));
  final toRaw = Uint8List.fromList(List.filled(21, 0x42));
  const blockTimestamp = 1721908800000;
  const latestBlock = TronLatestBlock(
    hash: '00000000045bcdc4c2ff1c56cf2b7ecdb60e0e26e3859ca9ff0a80b2f5502424',
    number: 73256388,
    timestamp: blockTimestamp,
  );
  final rawData = tronRawData(
    owner: ownerRaw,
    to: toRaw,
    amount: 1000000,
    timestamp: 1721908801234,
    expiration: 1721908801234 + 60000,
  );

  List<Uint8List> signOf(Uint8List bytes) => [signDigest(sha256(bytes))];

  group('Tron reply parsing + verification', () {
    final request = era.generateSignRequest(TronSignRequestProps(
      requestId: requestId,
      rawData: rawData,
      path: "m/44'/195'/0'/0/0",
      xfp: '00abcdef',
      latestBlock: latestBlock,
    ));

    test('round-trips through the scanner and validates the signId echo', () {
      final scanner = request.scanner();
      const id = '01020304-0506-0708-090a-0b0c0d0e0f10';
      scanner.receivePart(tronReply(id, rawData).toWireString());
      final parsed = scanner.parse();
      expect(parsed.txId, bytesToHex(sha256(rawData)));
      expect(parsed.signedTx.rawData, rawData);
      expect(parsed.signedTx.signatures.length, 1);
      final result = verifyTronSignature(VerifyTronSignatureArgs(
        rawData: rawData,
        from: tronOwner,
        latestBlock: latestBlock,
        signedTx: parsed.signedTx,
      ));
      expect(result, isA<Verified>());
    });

    test('refuses a stale signId (the only Tron anti-replay)', () {
      final scanner = request.scanner();
      scanner.receivePart(
        tronReply('99999999-0506-0708-090a-0b0c0d0e0f10', rawData)
            .toWireString(),
      );
      expect(scanner.parse, throwsSdkError('request-id-mismatch'));
    });

    test('accepts a signId echoed in uppercase (case-insensitive echo)', () {
      final reply = tronReply('01020304-0506-0708-090A-0B0C0D0E0F10', rawData);
      final parsed =
          era.parseSignature(reply, ExpectedReply(requestId: requestId));
      expect(parsed.requestId, requestId);
      expect(parsed.signedTx.rawData, rawData);
    });

    test('rebuild fallback: same contract + in-window timestamps pass', () {
      final rebuilt = tronRawData(
        owner: ownerRaw,
        to: toRaw,
        amount: 1000000,
        timestamp:
            blockTimestamp, // stamped with the reference block, firmware-style
        expiration: blockTimestamp + 10 * 60 * 1000,
      );
      final result = verifyTronSignature(VerifyTronSignatureArgs(
        rawData: rawData,
        from: tronOwner,
        latestBlock: latestBlock,
        signedTx: SignedTronTx(rawData: rebuilt, signatures: signOf(rebuilt)),
      ));
      expect(result, isA<Verified>());
    });

    test('rebuild fallback: a different recipient is refused', () {
      final diverted = tronRawData(
        owner: ownerRaw,
        to: Uint8List.fromList(List.filled(21, 0x66)),
        amount: 1000000,
        timestamp: blockTimestamp,
        expiration: blockTimestamp + 10 * 60 * 1000,
      );
      final result = verifyTronSignature(VerifyTronSignatureArgs(
        rawData: rawData,
        from: tronOwner,
        latestBlock: latestBlock,
        signedTx: SignedTronTx(rawData: diverted, signatures: signOf(diverted)),
      ));
      expect(result.ok, isFalse);
    });

    test('rebuild fallback: a stretched validity window is refused', () {
      final stretched = tronRawData(
        owner: ownerRaw,
        to: toRaw,
        amount: 1000000,
        timestamp: blockTimestamp,
        expiration: blockTimestamp + 11 * 60 * 60 * 1000, // 11h > 10h ceiling
      );
      final result = verifyTronSignature(VerifyTronSignatureArgs(
        rawData: rawData,
        from: tronOwner,
        latestBlock: latestBlock,
        signedTx:
            SignedTronTx(rawData: stretched, signatures: signOf(stretched)),
      ));
      expect(result.ok, isFalse);
      expect(
        (result as Failed).reason,
        matches(RegExp('window|valid for')),
      );
    });
  });

  group('request validation', () {
    test('refuses a latestBlock hash that is not the FULL 64-hex block id', () {
      expect(
        () => era.generateSignRequest(TronSignRequestProps(
          requestId: requestId,
          rawData: rawData,
          path: "m/44'/195'/0'/0/0",
          xfp: '00abcdef',
          latestBlock: const TronLatestBlock(
            hash: 'c2ff1c56cf2b7ecd', // ref_block_hash slice, not the block id
            number: 73256388,
            timestamp: blockTimestamp,
          ),
        )),
        throwsSdkError('invalid-props'),
      );
      expect(
        () => era.generateSignRequest(TronSignRequestProps(
          requestId: requestId,
          rawData: rawData,
          path: "m/44'/195'/0'/0/0",
          xfp: '00abcdef',
          latestBlock: TronLatestBlock(
            hash: 'g${latestBlock.hash.substring(1)}', // right length, not hex
            number: 73256388,
            timestamp: blockTimestamp,
          ),
        )),
        throwsSdkError('invalid-props'),
      );
    });

    test('refuses empty rawData', () {
      expect(
        () => era.generateSignRequest(TronSignRequestProps(
          requestId: requestId,
          rawData: Uint8List(0),
          path: "m/44'/195'/0'/0/0",
          xfp: '00abcdef',
          latestBlock: latestBlock,
        )),
        throwsSdkError('invalid-props'),
      );
    });
  });

  group('reply payload ceilings', () {
    test('refuses a compressed payload over 8 KiB before inflating', () {
      final ur = Ur(
        'keystone-sign-result',
        cborEncode(cbMap([(1, cbBytes(Uint8List(8 * 1024 + 1)))])),
      );
      expect(() => era.parseSignature(ur), throwsSdkError('limit-exceeded'));
    });

    test('refuses a payload that inflates past 64 KiB', () {
      final bomb = gzipCompress(Uint8List(64 * 1024 + 1));
      // Small enough to pass the compressed ceiling — the inflate cap is what
      // must refuse it.
      expect(bomb.length, lessThan(8 * 1024));
      final ur = Ur(
        'keystone-sign-result',
        cborEncode(cbMap([(1, cbBytes(bomb))])),
      );
      expect(() => era.parseSignature(ur), throwsSdkError('gzip-error'));
    });
  });

  group('byte-exact golden requests vs the TypeScript implementation', () {
    final fixture = jsonDecode(
      File('test/fixtures/ts-parity-golden.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    final goldenEra =
        TronChain(EraConnectConfig(origin: fixture['origin'] as String));
    final goldenRequestId = fixture['requestIdHex'] as String;
    final goldenRawData =
        Uint8List.fromList([for (var i = 0; i < 120; i++) (i * 7) % 256]);
    const goldenLatestBlock = TronLatestBlock(
      hash: '00000000045bcdc4c2ff1c56cf2b7ecdb60e0e26e3859ca9ff0a80b2f5502424',
      number: 73256388,
      timestamp: 1721908800000,
    );

    Map<String, dynamic> caseByName(String name) {
      final cases =
          (fixture['cases'] as List<dynamic>).cast<Map<String, dynamic>>();
      return cases.firstWhere(
        (c) => c['name'] == name,
        orElse: () => throw StateError('fixture case $name missing'),
      );
    }

    ({String protoHex, String origin}) tronProtoOf(Ur ur) {
      final map = cborDecode(ur.cbor);
      final compressed = asBytes(mapGet(map, 1));
      final origin = asText(mapGet(map, 2));
      if (compressed == null || origin == null) {
        fail('bad tron request shape');
      }
      // gzip BYTES are not comparable across implementations; the protobuf
      // underneath is the golden artifact.
      return (
        protoHex: bytesToHex(gunzipCapped(compressed, 64 * 1024)),
        origin: origin,
      );
    }

    test('tron_trc20', () {
      final req = goldenEra.generateSignRequest(TronSignRequestProps(
        requestId: goldenRequestId,
        rawData: goldenRawData,
        path: "m/44'/195'/0'/0/5",
        xfp: '00abcdef',
        latestBlock: goldenLatestBlock,
        display: const TronSignDisplay(
          token: 'USDT',
          contractAddress: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
          from: 'TYPFhTLdUonqfhTJsuLdvBnWNiCdvvyyBt',
          to: 'TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA',
          value: '1000000',
          fee: 1000000,
        ),
        timestamp: 0,
      ));
      final golden = caseByName('tron_trc20');
      final proto = tronProtoOf(req.ur);
      expect(req.ur.type, 'keystone-sign-request');
      expect(proto.protoHex, golden['tronProtoHex']);
      expect(proto.origin, golden['tronOrigin']);
    });

    test('tron_rawdata_only_display_empty', () {
      final req = goldenEra.generateSignRequest(TronSignRequestProps(
        requestId: goldenRequestId,
        rawData: goldenRawData,
        path: "m/44'/195'/0'/0/0",
        xfp: '00abcdef',
        latestBlock: goldenLatestBlock,
      ));
      final golden = caseByName('tron_rawdata_only_display_empty');
      final proto = tronProtoOf(req.ur);
      expect(proto.protoHex, golden['tronProtoHex']);
    });
  });
}
