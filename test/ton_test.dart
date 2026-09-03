import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/chains/ton.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/crypto/digests.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:era_connect/src/verify/ton.dart';
import 'package:era_connect/src/verify/ton_boc.dart';
import 'package:test/test.dart';

final _ton = TonChain(const EraConnectConfig(origin: 'TON Test'));
final _requestId = Uint8List.fromList(List.generate(16, (i) => i + 1));
const _uuidString = '01020304-0506-0708-090a-0b0c0d0e0f10';

// --- hand-built BoC helpers (test-side only) --------------------------------

typedef CellSpec = ({int bits, List<int> data, List<int> refs});

/// Serialize a tiny generic BoC (refSize 1, offSize 1, no index/crc).
Uint8List bocOf(List<CellSpec> cells) {
  final body = <int>[];
  for (final c in cells) {
    final dataBytes = (c.bits + 7) >> 3;
    final incomplete = c.bits % 8 != 0;
    body
      ..add(c.refs.length)
      ..add(dataBytes * 2 - (incomplete ? 1 : 0));
    final data = [...c.data];
    if (incomplete) {
      final shift = 7 - (c.bits % 8);
      final last = dataBytes - 1;
      final existing = last < data.length ? data[last] : 0;
      while (data.length <= last) {
        data.add(0);
      }
      data[last] = (existing | (1 << shift)) & (0xff << shift) & 0xff;
    }
    body
      ..addAll(data.sublist(0, dataBytes))
      ..addAll(c.refs);
  }
  return Uint8List.fromList([
    0xb5, 0xee, 0x9c, 0x72, // magic
    0x01, // flags: no idx/crc, refSize 1
    0x01, // offSize 1
    cells.length,
    0x01,
    0x00, // cells, roots, absent
    body.length, // tot cell size (unchecked)
    0x00, // root index 0
    ...body,
  ]);
}

/// Independent representation-hash computation for the KAT (no shared code
/// path).
({int depth, Uint8List hash}) reprHash(
  ({int bits, List<int> data}) cell,
  List<({int depth, Uint8List hash})> children,
) {
  final dataBytes = (cell.bits + 7) >> 3;
  final incomplete = cell.bits % 8 != 0;
  final repr = <int>[
    children.length,
    dataBytes * 2 - (incomplete ? 1 : 0),
    ...cell.data.sublist(0, dataBytes),
  ];
  if (incomplete) {
    final shift = 7 - (cell.bits % 8);
    final last = repr.length - 1;
    repr[last] = (repr[last] | (1 << shift)) & (0xff << shift) & 0xff;
  }
  for (final child in children) {
    repr
      ..add(child.depth >> 8)
      ..add(child.depth & 0xff);
  }
  var bytes = Uint8List.fromList(repr);
  for (final child in children) {
    bytes = concatBytes([bytes, child.hash]);
  }
  var depth = 0;
  if (children.isNotEmpty) {
    for (final c in children) {
      if (c.depth + 1 > depth) depth = c.depth + 1;
    }
  }
  return (depth: depth, hash: sha256(bytes));
}

void main() {
  group('TON request wire shape', () {
    final request = _ton.generateSignRequest(TonSignRequestProps(
      requestId: _requestId,
      signData: bocOf([
        (bits: 16, data: [0xab, 0xcd], refs: <int>[])
      ]),
      path: "m/44'/607'/0'",
      xfp: 'deadbeef',
      address: 'UQABCDEFtestaddress',
    ));

    test(
        'carries the request id as tag-37 ASCII UUID-string bytes '
        '(the ecosystem quirk)', () {
      final map = asMap(cborDecode(request.ur.cbor))!;
      final idValue = mapGet(map, 1)!;
      expect(idValue, isA<CborTag>().having((t) => t.tag, 'tag', 37));
      final idBytes = asBytes(idValue)!;
      expect(idBytes.length, 36);
      expect(asciiDecode(idBytes), _uuidString);
      expect(asUint(mapGet(map, 3))!.toInt(), TonDataType.transaction);
      expect(asText(mapGet(map, 5)), 'UQABCDEFtestaddress');
      expect(asText(mapGet(map, 6)), 'TON Test');
      expect(request.ur.type, 'ton-sign-request');
      expect(request.replyTypes, ['ton-signature']);
    });

    test('pins the request CBOR golden', () {
      // Self-golden: any byte change here is a wire-format change and must be
      // deliberate.
      expect(
        bytesToHex(request.ur.cbor),
        'a601d825582430313032303330342d303530362d303730382d303930612d3062'
        '30633064306530663130024fb5ee9c72010101010004000004abcd030104d901'
        '30a20186182cf519025ff500f5021adeadbeef05735551414243444546746573'
        '74616464726573730668544f4e2054657374',
      );
    });
  });

  group('TON reply parsing', () {
    final priv = ed.newKeyFromSeed(Uint8List.fromList(List.filled(32, 6)));
    final pub = Uint8List.fromList(ed.public(priv).bytes);
    final boc = bocOf([
      (bits: 16, data: [0xab, 0xcd], refs: <int>[])
    ]);
    final request = _ton.generateSignRequest(TonSignRequestProps(
      requestId: _requestId,
      signData: boc,
      path: "m/44'/607'/0'",
      xfp: 'deadbeef',
    ));

    Ur reply(CborValue echo, Uint8List sig) {
      return Ur(
        'ton-signature',
        cborEncode(cbMap([
          (1, cbTag(37, echo)),
          (2, cbBytes(sig)),
          (3, cbText('ERA Wallet')),
        ])),
      );
    }

    final signature = ed.sign(priv, bocRootHash(boc));

    test(
        'accepts the string-bytes echo and verifies the BoC root hash '
        'signature', () {
      final scanner = request.scanner();
      scanner.receivePart(
        reply(cbBytes(utf8Encode(_uuidString)), signature).toWireString(),
      );
      final parsed = scanner.parse();
      expect(parsed.requestId, _requestId);
      final verdict = verifyTonSignature(VerifyTonSignatureArgs(
        signData: boc,
        dataType: TonDataType.transaction,
        signature: parsed.signature,
        publicKey: pub,
      ));
      expect(verdict.ok, isTrue);
      expect(verdict.checked, isTrue);
    });

    test('accepts a raw 16-byte binary echo (forward compatibility)', () {
      final parsed = _ton.parseSignature(
        reply(cbBytes(_requestId), signature),
        ExpectedReply(requestId: _requestId),
      );
      expect(parsed.signature, signature);
    });

    test('refuses a stale echo', () {
      final stale = reply(
        cbBytes(utf8Encode('99999999-0506-0708-090a-0b0c0d0e0f10')),
        signature,
      );
      expect(
        () => _ton.parseSignature(stale, ExpectedReply(requestId: _requestId)),
        throwsA(
          isA<EraSdkError>()
              .having((e) => e.code, 'code', 'request-id-mismatch'),
        ),
      );
    });

    test('verifies the TON Connect proof digest', () {
      final payload = utf8Encode('ton-proof-item-v2/example');
      final digest = sha256(concatBytes([
        Uint8List.fromList([0xff, 0xff]),
        utf8Encode('ton-connect'),
        sha256(payload),
      ]));
      final proofSig = ed.sign(priv, digest);
      final verdict = verifyTonSignature(VerifyTonSignatureArgs(
        signData: payload,
        dataType: TonDataType.tonProof,
        signature: proofSig,
        publicKey: pub,
      ));
      expect(verdict.ok, isTrue);
      expect(verdict.checked, isTrue);
      final wrong = verifyTonSignature(VerifyTonSignatureArgs(
        signData: utf8Encode('other payload'),
        dataType: TonDataType.tonProof,
        signature: proofSig,
        publicKey: pub,
      ));
      expect(wrong.ok, isFalse);
    });
  });

  group('BoC root hash (KAT against an independent computation)', () {
    test('single incomplete-byte cell', () {
      const cell = (bits: 13, data: [0xf0, 0xf0], refs: <int>[]);
      expect(
        bytesToHex(bocRootHash(bocOf([cell]))),
        bytesToHex(
          reprHash((bits: cell.bits, data: cell.data), []).hash,
        ),
      );
    });

    test('root with two children (depths + hashes concatenated)', () {
      const childA = (bits: 8, data: [0x11]);
      const childB = (bits: 4, data: [0x20]);
      const root = (bits: 16, data: [0xde, 0xad]);
      final ha = reprHash(childA, []);
      final hb = reprHash(childB, []);
      final expected = reprHash(root, [ha, hb]).hash;
      expect(
        bytesToHex(bocRootHash(bocOf([
          (bits: root.bits, data: root.data, refs: [1, 2]),
          (bits: childA.bits, data: childA.data, refs: <int>[]),
          (bits: childB.bits, data: childB.data, refs: <int>[]),
        ]))),
        bytesToHex(expected),
      );
    });

    test(
        'refuses malformed input: magic, backward refs, truncation, '
        'size bombs', () {
      expect(
        () => bocRootHash(Uint8List.fromList([1, 2, 3])),
        throwsA(isA<EraSdkError>()),
      );
      expect(
        () => bocRootHash(Uint8List.fromList(List.filled(12, 0xaa))),
        throwsA(
          isA<EraSdkError>()
              .having((e) => e.message, 'message', contains('generic BoC')),
        ),
      );
      // backward reference (cell 1 refers to cell 0)
      final backward = bocOf([
        (bits: 8, data: [0x01], refs: [1]),
        (bits: 8, data: [0x02], refs: [0]),
      ]);
      expect(
        () => bocRootHash(backward),
        throwsA(
          isA<EraSdkError>()
              .having((e) => e.message, 'message', contains('non-topological')),
        ),
      );
      final truncated = bocOf([
        (bits: 64, data: [1, 2, 3, 4, 5, 6, 7, 8], refs: <int>[]),
      ]).sublist(0, 14);
      expect(() => bocRootHash(truncated), throwsA(isA<EraSdkError>()));
    });
  });

  // The reference suite's "TON linking (Tonkeeper-style standalone
  // crypto-hdkey)" block exercises EraAccounts, which lives in the registry
  // port — its TON coverage belongs to the accounts test file.
}
