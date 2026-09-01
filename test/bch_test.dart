import 'dart:typed_data';

import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/bch.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/crypto/digests.dart';
import 'package:era_connect/src/registry/keypath.dart';
import 'package:era_connect/src/tron_proto/gzip.dart';
import 'package:era_connect/src/tron_proto/wire.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:era_connect/src/verify/bch.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

final Uint8List testSeed = hexToBytes(
  '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1'
  '9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
);

// ---------------------------------------------------------------------------
// Test-only BIP-32 signing keys (the SDK itself never holds private keys).
// ---------------------------------------------------------------------------

final pc.ECDomainParameters _domain = pc.ECCurve_secp256k1();

class HdNode {
  HdNode(this.privateKey, this.chainCode);

  final BigInt privateKey;
  final Uint8List chainCode;

  late final Uint8List publicKey =
      Uint8List.fromList((_domain.G * privateKey)!.getEncoded(true));
}

Uint8List _ser256(BigInt value) {
  final bytes = bigintToBytes(value);
  final out = Uint8List(32);
  out.setAll(32 - bytes.length, bytes);
  return out;
}

Uint8List _ser32(int value) {
  return Uint8List.fromList([
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ]);
}

HdNode deriveNode(Uint8List seed, String path) {
  final master = hmacSha512(utf8Encode('Bitcoin seed'), seed);
  var k = bytesToBigint(Uint8List.sublistView(master, 0, 32));
  var chainCode = Uint8List.fromList(master.sublist(32));
  for (final level in parsePath(path)) {
    final index = level.hardened ? level.index + 0x80000000 : level.index;
    final Uint8List data;
    if (level.hardened) {
      data = concatBytes([
        Uint8List.fromList([0]),
        _ser256(k),
        _ser32(index),
      ]);
    } else {
      data = concatBytes([
        Uint8List.fromList((_domain.G * k)!.getEncoded(true)),
        _ser32(index),
      ]);
    }
    final i = hmacSha512(chainCode, data);
    final il = bytesToBigint(Uint8List.sublistView(i, 0, 32));
    k = (il + k) % _domain.n;
    chainCode = Uint8List.fromList(i.sublist(32));
  }
  return HdNode(k, chainCode);
}

Uint8List _derEncode(BigInt r, BigInt s) {
  Uint8List intBytes(BigInt v) {
    final b = bigintToBytes(v);
    return (b[0] & 0x80 != 0) ? Uint8List.fromList([0, ...b]) : b;
  }

  final rb = intBytes(r);
  final sb = intBytes(s);
  return Uint8List.fromList([
    0x30,
    rb.length + sb.length + 4,
    0x02,
    rb.length,
    ...rb,
    0x02,
    sb.length,
    ...sb,
  ]);
}

/// Deterministic (RFC 6979) low-S ECDSA over a 32-byte digest, DER-encoded —
/// what the device's signer produces.
Uint8List signDer(Uint8List digest32, BigInt privateKey) {
  final signer = pc.ECDSASigner(null, pc.HMac(pc.SHA256Digest(), 64));
  signer.init(
    true,
    pc.PrivateKeyParameter<pc.ECPrivateKey>(
      pc.ECPrivateKey(privateKey, _domain),
    ),
  );
  final sig = signer.generateSignature(digest32) as pc.ECSignature;
  var s = sig.s;
  final n = _domain.n;
  if (s > (n >> 1)) s = n - s;
  return _derEncode(sig.r, s);
}

String bchAddress(Uint8List publicKey, {bool withPrefix = false}) {
  return encodeCashAddr(
    CashAddrType.p2pkh,
    hash160(publicKey),
    withPrefix: withPrefix,
  );
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const String receivePath = "m/44'/145'/0'/0/0";
const String changePath = "m/44'/145'/0'/1/0";
const String fixedRequestId = '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d';
const String fixedTxid =
    '142f52b7d109437403e50b1ff738b5ba5d1dc80c71b7d48c9eca347ca66a144a';

class TestKeys {
  TestKeys()
      : receive = deriveNode(testSeed, receivePath),
        change = deriveNode(testSeed, changePath);

  final HdNode receive;
  final HdNode change;
}

BchSignRequestProps baseProps(
  TestKeys keys, {
  List<BchTxInput>? inputs,
  List<BchTxOutput>? outputs,
  Object? fee,
}) {
  final receiveAddr = bchAddress(keys.receive.publicKey);
  final changeAddr = bchAddress(keys.change.publicKey);
  return BchSignRequestProps(
    requestId: fixedRequestId,
    inputs: inputs ??
        [
          BchTxInput(
            txid: fixedTxid,
            index: 0,
            value: 250000,
            publicKey: keys.receive.publicKey,
            path: receivePath,
          ),
        ],
    outputs: outputs ??
        [
          BchTxOutput(address: receiveAddr, value: 80000),
          BchTxOutput(
            address: changeAddr,
            value: 169000,
            isChange: true,
            changeAddressPath: changePath,
          ),
        ],
    fee: fee ?? 1000,
    xfp: 0x12345678,
    timestamp: 1700000000000,
  );
}

List<VerifyBchInput> verifyInputsOf(List<BchTxInput> inputs) => [
      for (final i in inputs)
        VerifyBchInput(
          txid: i.txid,
          index: i.index,
          value: i.value,
          publicKey: i.publicKey,
        ),
    ];

List<VerifyBchOutput> verifyOutputsOf(List<BchTxOutput> outputs) => [
      for (final o in outputs)
        VerifyBchOutput(address: o.address, value: o.value),
    ];

Uint8List protoOf(Ur ur) {
  final map = cborDecode(ur.cbor);
  return gunzipCapped(asBytes(mapGet(map, 1))!, 64 * 1024);
}

Matcher throwsSdkError(String messagePart) => throwsA(
      isA<EraSdkError>()
          .having((e) => e.message, 'message', contains(messagePart)),
    );

// ---------------------------------------------------------------------------
// Device emulation
// ---------------------------------------------------------------------------

Uint8List _p2pkh(Uint8List pubkeyHash) => concatBytes([
      Uint8List.fromList([0x76, 0xa9, 0x14]),
      pubkeyHash,
      Uint8List.fromList([0x88, 0xac]),
    ]);

Uint8List _le32(int value) => Uint8List.fromList([
      value & 0xff,
      (value >> 8) & 0xff,
      (value >> 16) & 0xff,
      (value >> 24) & 0xff,
    ]);

Uint8List _le64(BigInt value) {
  final out = Uint8List(8);
  final mask = BigInt.from(0xff);
  var v = value;
  for (var i = 0; i < 8; i++) {
    out[i] = (v & mask).toInt();
    v >>= 8;
  }
  return out;
}

BigInt _asBig(Object value) =>
    value is BigInt ? value : BigInt.from(value as int);

/// Emulate the device's FORKID signer: version 1, locktime 0, sequence
/// 0xfffffffd, P2PKH outputs from the request addresses, per-input BIP-143
/// sighash with FORKID, DER + 0x41 scriptSig.
String emulateDeviceSigning(BchSignRequestProps props, TestKeys keys) {
  final txStructure = DecodedBchTx(
    version: 1,
    inputs: [
      for (final input in props.inputs)
        DecodedBchInput(
          txidLE: Uint8List.fromList(hexToBytes(input.txid).reversed.toList()),
          index: input.index,
          scriptSig: Uint8List(0),
          sequence: 0xfffffffd,
        ),
    ],
    outputs: [
      for (final output in props.outputs)
        DecodedBchOutput(
          value: _asBig(output.value),
          script: _p2pkh(decodeCashAddr(output.address).hash),
        ),
    ],
    locktime: 0,
  );

  final scriptSigs = <Uint8List>[];
  for (var i = 0; i < props.inputs.length; i++) {
    final key = keys.receive; // single-input fixture: the receive key owns it
    final sighash = computeBchSighash(
      tx: txStructure,
      inputIndex: i,
      scriptCode: _p2pkh(hash160(key.publicKey)),
      value: _asBig(props.inputs[i].value),
    );
    final der = signDer(sighash, key.privateKey);
    final sigWithType = concatBytes([
      der,
      Uint8List.fromList([0x41]),
    ]);
    scriptSigs.add(concatBytes([
      Uint8List.fromList([sigWithType.length]),
      sigWithType,
      Uint8List.fromList([33]),
      key.publicKey,
    ]));
  }

  final parts = <Uint8List>[
    _le32(1),
    Uint8List.fromList([props.inputs.length]),
  ];
  for (var i = 0; i < props.inputs.length; i++) {
    parts.addAll([
      txStructure.inputs[i].txidLE,
      _le32(props.inputs[i].index),
      Uint8List.fromList([scriptSigs[i].length]),
      scriptSigs[i],
      _le32(0xfffffffd),
    ]);
  }
  parts.add(Uint8List.fromList([props.outputs.length]));
  for (final output in txStructure.outputs) {
    parts.addAll([
      _le64(output.value),
      Uint8List.fromList([output.script.length]),
      output.script,
    ]);
  }
  parts.add(_le32(0));
  return bytesToHex(concatBytes(parts));
}

Ur buildReplyUr(String signId, String txId, String rawTx) {
  final result = ProtoWriter()
      .stringField(1, signId)
      .stringField(2, txId)
      .stringField(3, rawTx)
      .finish();
  final payload = ProtoWriter()
      .varintField(1, BigInt.from(9))
      .stringField(2, '12345678')
      .messageField(7, result)
      .finish();
  final proto = ProtoWriter()
      .varintField(1, BigInt.one)
      .stringField(2, 'keystone qrcode')
      .messageField(3, payload)
      .finish();
  return Ur(
    'keystone-sign-result',
    cborEncode(cbMap([(1, cbBytes(gzipCompress(proto)))])),
  );
}

void main() {
  // -------------------------------------------------------------------------
  // CashAddr codec
  // -------------------------------------------------------------------------

  group('cashaddr codec', () {
    // The spec's own legacy-translation examples (hash160 extracted via
    // base58check and cross-checked against an independent implementation).
    const specVectors = <(CashAddrType, String, String)>[
      (
        CashAddrType.p2pkh,
        '76a04053bda0a88bda5177b86a15c3b29f559873',
        'qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a',
      ),
      (
        CashAddrType.p2pkh,
        'cb481232299cd5743151ac4b2d63ae198e7bb0a9',
        'qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy',
      ),
      (
        CashAddrType.p2sh,
        '76a04053bda0a88bda5177b86a15c3b29f559873',
        'ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq',
      ),
    ];

    test('encodes the spec vectors', () {
      for (final (type, hash, expected) in specVectors) {
        expect(encodeCashAddr(type, hexToBytes(hash)), expected);
        expect(
          encodeCashAddr(type, hexToBytes(hash), withPrefix: true),
          'bitcoincash:$expected',
        );
      }
    });

    test('decodes bare, prefixed and uppercase forms to the same payload', () {
      for (final (type, hash, addr) in specVectors) {
        for (final form in [addr, 'bitcoincash:$addr', addr.toUpperCase()]) {
          final decoded = decodeCashAddr(form);
          expect(decoded.type, type);
          expect(bytesToHex(decoded.hash), hash);
        }
      }
    });

    test('refuses mixed case, a corrupted checksum, and a foreign prefix', () {
      final addr = specVectors[0].$3;
      expect(
        () => decodeCashAddr('${addr.substring(0, addr.length - 1)}A'),
        throwsA(isA<EraSdkError>()),
      );
      final flipped =
          addr.substring(0, addr.length - 1) + (addr.endsWith('a') ? 'q' : 'a');
      expect(() => decodeCashAddr(flipped), throwsSdkError('checksum'));
      expect(() => decodeCashAddr('bchtest:$addr'), throwsSdkError('prefix'));
    });

    test('round-trips random hashes through both script types', () {
      for (var i = 0; i < 32; i++) {
        final hash = Uint8List.sublistView(
          sha256(Uint8List.fromList([i])),
          0,
          20,
        );
        for (final type in CashAddrType.values) {
          final decoded = decodeCashAddr(encodeCashAddr(type, hash));
          expect(decoded.type, type);
          expect(bytesToHex(decoded.hash), bytesToHex(hash));
        }
      }
    });
  });

  // -------------------------------------------------------------------------
  // Test-seed address vectors (sanity for the test-only HD derivation; the
  // published first addresses of the standard test seed, cross-checked
  // against an independent CashAddr implementation)
  // -------------------------------------------------------------------------

  group('bch test-seed address vectors', () {
    test('derives the published first addresses of the test seed', () {
      expect(
        bchAddress(deriveNode(testSeed, "m/44'/145'/0'/0/0").publicKey),
        'qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6',
      );
      expect(
        bchAddress(deriveNode(testSeed, "m/44'/145'/0'/0/1").publicKey),
        'qp8sfdhgjlq68hlzka9lcsxtcnvuvnd0xqxugfzzc5',
      );
      expect(
        bchAddress(deriveNode(testSeed, "m/44'/145'/0'/1/0").publicKey),
        'qr8aeharupyrmhfu0d4tdmsnc5y8cfk47y6qrsjsrx',
      );
      expect(
        bchAddress(
          deriveNode(testSeed, "m/44'/145'/0'/0/0").publicKey,
          withPrefix: true,
        ),
        'bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6',
      );
    });
  });

  // -------------------------------------------------------------------------
  // Envelope construction
  // -------------------------------------------------------------------------

  group('bch sign request envelope', () {
    final chain = BchChain();
    final keys = TestKeys();

    test('emits the Base/Payload/SignTransaction/BchTx protobuf shape', () {
      final props = baseProps(keys);
      final request = chain.generateSignRequest(props);
      expect(request.ur.type, 'keystone-sign-request');
      final proto = protoOf(request.ur);

      final base = readFields(proto);
      expect(base.firstWhere((f) => f.field == 1).value, BigInt.two);
      final payload = readFields(base.firstWhere((f) => f.field == 3).bytes);
      expect(payload.firstWhere((f) => f.field == 1).value, BigInt.two);
      expect(utf8Decode(payload.firstWhere((f) => f.field == 2).bytes),
          '12345678');
      final signTx = readFields(payload.firstWhere((f) => f.field == 4).bytes);
      expect(utf8Decode(signTx.firstWhere((f) => f.field == 1).bytes), 'BCH');
      expect(
        utf8Decode(signTx.firstWhere((f) => f.field == 2).bytes),
        '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
      );
      // No hdPath — per-input paths rule.
      expect(signTx.where((f) => f.field == 3), isEmpty);
      expect(signTx.firstWhere((f) => f.field == 4).value,
          BigInt.from(1700000000000));
      expect(signTx.firstWhere((f) => f.field == 5).value, BigInt.from(8));

      final bchTx = readFields(signTx.firstWhere((f) => f.field == 10).bytes);
      expect(bchTx.firstWhere((f) => f.field == 1).value, BigInt.from(1000));
      expect(bchTx.firstWhere((f) => f.field == 2).value, BigInt.from(546));
      final input = readFields(bchTx.firstWhere((f) => f.field == 4).bytes);
      expect(utf8Decode(input.firstWhere((f) => f.field == 1).bytes),
          props.inputs[0].txid);
      // index 0 omitted (proto3).
      expect(input.where((f) => f.field == 2), isEmpty);
      expect(input.firstWhere((f) => f.field == 3).value, BigInt.from(250000));
      expect(
        utf8Decode(input.firstWhere((f) => f.field == 4).bytes),
        bytesToHex(keys.receive.publicKey),
      );
      expect(
          utf8Decode(input.firstWhere((f) => f.field == 5).bytes), receivePath);
      final outputs = bchTx.where((f) => f.field == 5).toList();
      expect(outputs, hasLength(2));
      final first = readFields(outputs[0].bytes);
      expect(utf8Decode(first.firstWhere((f) => f.field == 1).bytes),
          props.outputs[0].address);
      expect(first.firstWhere((f) => f.field == 2).value, BigInt.from(80000));
      final change = readFields(outputs[1].bytes);
      expect(utf8Decode(change.firstWhere((f) => f.field == 1).bytes),
          props.outputs[1].address);
      expect(change.firstWhere((f) => f.field == 2).value, BigInt.from(169000));
      expect(change.firstWhere((f) => f.field == 3).value, BigInt.one);
      expect(
          utf8Decode(change.firstWhere((f) => f.field == 4).bytes), changePath);
    });

    test('refuses a fee that does not equal inputs minus outputs', () {
      expect(
        () => chain.generateSignRequest(baseProps(keys, fee: 1001)),
        throwsSdkError('fee mismatch'),
      );
    });

    test('refuses malformed inputs and outputs', () {
      final props = baseProps(keys);
      expect(
        () => chain.generateSignRequest(baseProps(keys, inputs: [
          BchTxInput(
            txid: 'nope',
            index: props.inputs[0].index,
            value: props.inputs[0].value,
            publicKey: props.inputs[0].publicKey,
            path: props.inputs[0].path,
          ),
        ])),
        throwsSdkError('txid'),
      );
      expect(
        () => chain.generateSignRequest(baseProps(keys, inputs: [
          BchTxInput(
            txid: props.inputs[0].txid,
            index: props.inputs[0].index,
            value: props.inputs[0].value,
            publicKey: Uint8List(32),
            path: props.inputs[0].path,
          ),
        ])),
        throwsSdkError('public key'),
      );
      // Fee-consistent sums, so ONLY the address gate can be what throws — a
      // bare EraSdkError assert here was satisfiable by the fee check alone.
      expect(
        () => chain.generateSignRequest(baseProps(keys, outputs: [
          const BchTxOutput(
            address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
            value: 80000,
          ),
          props.outputs[1],
        ])),
        throwsSdkError('cashaddr'),
      );
      // Unicode case-folding trick: U+212A KELVIN SIGN folds to 'k' but is
      // not ASCII.
      expect(
        () => chain.generateSignRequest(baseProps(keys, outputs: [
          const BchTxOutput(
            address: 'qpm2qsznh\u{212A}s23z7629mms6s4cwef74vcwvy22gdx6a',
            value: 80000,
          ),
          props.outputs[1],
        ])),
        throwsSdkError('character'),
      );
      expect(
        () => chain.generateSignRequest(baseProps(keys, inputs: [])),
        throwsSdkError('input'),
      );
      expect(
        () => chain.generateSignRequest(baseProps(keys, outputs: [])),
        throwsSdkError('output'),
      );
    });
  });

  // -------------------------------------------------------------------------
  // Reply parsing + verification (device emulation)
  // -------------------------------------------------------------------------

  group('bch reply parsing and verification', () {
    final chain = BchChain();
    final keys = TestKeys();
    final props = baseProps(keys);
    final rawTx = emulateDeviceSigning(props, keys);
    final txId = bytesToHex(
      Uint8List.fromList(sha256d(hexToBytes(rawTx)).reversed.toList()),
    );

    test('parses the reply and enforces the signId echo', () {
      final reply = buildReplyUr(fixedRequestId, txId, rawTx);
      final result = chain.parseSignature(
          reply, const ExpectedReply(requestId: fixedRequestId));
      expect(result.rawTx, rawTx);
      expect(result.txId, txId);

      expect(
        () => chain.parseSignature(
          reply,
          const ExpectedReply(
              requestId: '00000000-0000-4000-8000-000000000000'),
        ),
        throwsSdkError('request id'),
      );
    });

    test('accepts an uppercase signId echo (the device echoes verbatim)', () {
      final reply = buildReplyUr(fixedRequestId.toUpperCase(), txId, rawTx);
      final result = chain.parseSignature(
          reply, const ExpectedReply(requestId: fixedRequestId));
      expect(result.txId, txId);
    });

    test('verifies the emulated device transaction end-to-end', () {
      final result = verifyBchSignedTx(VerifyBchSignedTxArgs(
        rawTx: rawTx,
        inputs: verifyInputsOf(props.inputs),
        outputs: verifyOutputsOf(props.outputs),
        txId: txId,
      ));
      expect(result.ok, isTrue);
      expect(result.checked, isTrue);
      expect(result.reason, isNull);
    });

    test('decodes the raw transaction into the expected structure', () {
      final tx = decodeBchRawTx(rawTx);
      expect(tx.version, 1);
      expect(tx.locktime, 0);
      expect(tx.inputs[0].sequence, 0xfffffffd);
      expect(tx.outputs.map((o) => o.value),
          [BigInt.from(80000), BigInt.from(169000)]);
    });

    test('fails on a tampered output value', () {
      final outputs = [
        VerifyBchOutput(address: props.outputs[0].address, value: 80001),
        VerifyBchOutput(
            address: props.outputs[1].address, value: props.outputs[1].value),
      ];
      final result = verifyBchSignedTx(VerifyBchSignedTxArgs(
        rawTx: rawTx,
        inputs: verifyInputsOf(props.inputs),
        outputs: outputs,
      ));
      expect(result.ok, isFalse);
    });

    test('fails on a substituted destination address', () {
      final outputs = [
        VerifyBchOutput(
            address: props.outputs[1].address, value: props.outputs[0].value),
        VerifyBchOutput(
            address: props.outputs[1].address, value: props.outputs[1].value),
      ];
      final result = verifyBchSignedTx(VerifyBchSignedTxArgs(
        rawTx: rawTx,
        inputs: verifyInputsOf(props.inputs),
        outputs: outputs,
      ));
      expect(result.ok, isFalse);
    });

    test('fails when the request named a different owner key', () {
      final inputs = [
        VerifyBchInput(
          txid: props.inputs[0].txid,
          index: props.inputs[0].index,
          value: props.inputs[0].value,
          publicKey: keys.change.publicKey,
        ),
      ];
      final result = verifyBchSignedTx(VerifyBchSignedTxArgs(
        rawTx: rawTx,
        inputs: inputs,
        outputs: verifyOutputsOf(props.outputs),
      ));
      expect(result.ok, isFalse);
      expect(result.reason, contains('different public key'));
    });

    test('fails on a different outpoint', () {
      final inputs = [
        VerifyBchInput(
          txid: props.inputs[0].txid,
          index: 1,
          value: props.inputs[0].value,
          publicKey: props.inputs[0].publicKey,
        ),
      ];
      final result = verifyBchSignedTx(VerifyBchSignedTxArgs(
        rawTx: rawTx,
        inputs: inputs,
        outputs: verifyOutputsOf(props.outputs),
      ));
      expect(result.ok, isFalse);
    });

    test('fails on a corrupted signature and on a wrong sighash type byte', () {
      final bytes = hexToBytes(rawTx);
      // The DER signature starts at offset 4 (version) + 32 (txid) + 4 (vout)
      // + 1 (script len) + 1 (sig push len); flip a byte deep inside it.
      const sigStart = 4 + 32 + 4 + 2;
      final corrupted = Uint8List.fromList(bytes);
      corrupted[sigStart + 10] ^= 0x01;
      expect(
        verifyBchSignedTx(VerifyBchSignedTxArgs(
          rawTx: bytesToHex(corrupted),
          inputs: verifyInputsOf(props.inputs),
          outputs: verifyOutputsOf(props.outputs),
        )).ok,
        isFalse,
      );

      final tx = decodeBchRawTx(rawTx);
      final sigLen = tx.inputs[0].scriptSig[0];
      final typeByteOffset = sigStart + sigLen - 1;
      final wrongType = Uint8List.fromList(bytes);
      wrongType[typeByteOffset] = 0x01; // SIGHASH_ALL without FORKID
      final result = verifyBchSignedTx(VerifyBchSignedTxArgs(
        rawTx: bytesToHex(wrongType),
        inputs: verifyInputsOf(props.inputs),
        outputs: verifyOutputsOf(props.outputs),
      ));
      expect(result.ok, isFalse);
      expect(result.reason, contains('sighash'));
    });

    test('refuses parameters the device signer cannot have produced', () {
      // locktime is the last 4 bytes of the serialization; the pin must fire
      // BEFORE any signature math, catching a reply no ERA signer built.
      final bytes = hexToBytes(rawTx);
      bytes[bytes.length - 4] = 0x01;
      final result = verifyBchSignedTx(VerifyBchSignedTxArgs(
        rawTx: bytesToHex(bytes),
        inputs: verifyInputsOf(props.inputs),
        outputs: verifyOutputsOf(props.outputs),
      ));
      expect(result.ok, isFalse);
      expect(result.reason, contains('locktime'));
    });

    test('fails when the reply txId does not match the raw bytes', () {
      final result = verifyBchSignedTx(VerifyBchSignedTxArgs(
        rawTx: rawTx,
        inputs: verifyInputsOf(props.inputs),
        outputs: verifyOutputsOf(props.outputs),
        txId: '00${txId.substring(2)}',
      ));
      expect(result.ok, isFalse);
    });
  });

  // -------------------------------------------------------------------------
  // Address canonicalization on the wire
  // -------------------------------------------------------------------------

  group('address canonicalization on the wire', () {
    final chain = BchChain();
    final keys = TestKeys();

    List<String> wireAddresses(BchSignRequestProps props) {
      final proto = protoOf(chain.generateSignRequest(props).ur);
      final base = readFields(proto);
      final payload = readFields(base.firstWhere((f) => f.field == 3).bytes);
      final signTx = readFields(payload.firstWhere((f) => f.field == 4).bytes);
      final bchTx = readFields(signTx.firstWhere((f) => f.field == 10).bytes);
      return [
        for (final f in bchTx.where((f) => f.field == 5))
          utf8Decode(readFields(f.bytes).firstWhere((x) => x.field == 1).bytes),
      ];
    }

    test(
        'rewrites an uppercase (QR alphanumeric) address to the lowercase form',
        () {
      // The device's parser reads ONLY lowercase: its prefix rebuild makes an
      // uppercase body mixed-case, the decode fails, and the failure falls
      // open into a zero pubkey hash — a signed burn. The SDK must therefore
      // never forward the caller's spelling.
      final props = baseProps(keys);
      final upper = props.outputs[0].address.toUpperCase();
      final addresses = wireAddresses(baseProps(keys, outputs: [
        BchTxOutput(address: upper, value: props.outputs[0].value),
        props.outputs[1],
      ]));
      expect(addresses[0], props.outputs[0].address);
    });

    test('keeps the prefix presence but canonicalizes its case', () {
      final props = baseProps(keys);
      final prefixedUpper =
          'BITCOINCASH:${props.outputs[0].address.toUpperCase()}';
      final addresses = wireAddresses(baseProps(keys, outputs: [
        BchTxOutput(address: prefixedUpper, value: props.outputs[0].value),
        props.outputs[1],
      ]));
      expect(addresses[0], 'bitcoincash:${props.outputs[0].address}');
    });
  });

  // -------------------------------------------------------------------------
  // Sighash known-answer test
  // -------------------------------------------------------------------------

  group('sighash known-answer test', () {
    test('matches an independently computed BIP-143 FORKID digest', () {
      // Frozen from an implementation written separately from this codebase —
      // the committed regression pin for the one digest the SDK computes
      // itself. (Correctness against the real device is proven by the
      // env-gated firmware-corpus leg.)
      final digest = computeBchSighash(
        tx: DecodedBchTx(
          version: 1,
          inputs: [
            DecodedBchInput(
              txidLE:
                  Uint8List.fromList(hexToBytes('22' * 32).reversed.toList()),
              index: 3,
              scriptSig: Uint8List(0),
              sequence: 0xfffffffd,
            ),
          ],
          outputs: [
            DecodedBchOutput(
              value: BigInt.from(100000),
              script: hexToBytes('76a914${'44' * 20}88ac'),
            ),
          ],
          locktime: 0,
        ),
        inputIndex: 0,
        scriptCode: hexToBytes('76a914${'33' * 20}88ac'),
        value: BigInt.from(123456),
      );
      expect(
        bytesToHex(digest),
        '15df3f55c278d29e17d7b93e7f790516703b76c823f3ed1abdc7998e68da75b0',
      );
    });
  });
}
