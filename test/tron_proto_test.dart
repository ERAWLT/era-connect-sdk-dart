import 'dart:typed_data';

import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/tron_proto/gzip.dart';
import 'package:era_connect/src/tron_proto/messages.dart';
import 'package:era_connect/src/tron_proto/wire.dart';
import 'package:test/test.dart';

Matcher throwsSdkError(String code, String messagePart) => throwsA(
      isA<EraSdkError>()
          .having((e) => e.code, 'code', code)
          .having((e) => e.message, 'message', contains(messagePart)),
    );

void expectVarint(ProtoField f, int field, BigInt value) {
  expect(f.field, field);
  expect(f.wireType, 0);
  expect(f.value, value);
}

void expectString(ProtoField f, int field, String value) {
  expect(f.field, field);
  expect(f.wireType, 2);
  expect(utf8Decode(f.bytes), value);
}

void expectMessage(ProtoField f, int field) {
  expect(f.field, field);
  expect(f.wireType, 2);
}

void main() {
  group('ProtoWriter / varint', () {
    test('varint encodes canonical base-128', () {
      expect(varint(BigInt.zero), [0]);
      expect(varint(BigInt.from(1)), [1]);
      expect(varint(BigInt.from(127)), [127]);
      expect(varint(BigInt.from(128)), [0x80, 0x01]);
      expect(varint(BigInt.from(300)), [0xac, 0x02]);
      expect(
        varint(BigInt.parse('ffffffffffffffff', radix: 16)),
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
      );
    });

    test('varint refuses a negative value', () {
      expect(
        () => varint(BigInt.from(-1)),
        throwsSdkError('protobuf-error', 'negative varint'),
      );
    });

    test('writer emits fields in append order with correct tags', () {
      final bytes = ProtoWriter()
          .varintField(1, BigInt.two)
          .stringField(2, 'hi')
          .bytesField(3, Uint8List.fromList([0xde, 0xad]))
          .finish();
      expect(
          bytes, [0x08, 0x02, 0x12, 0x02, 0x68, 0x69, 0x1a, 0x02, 0xde, 0xad]);
    });
  });

  group('readFields hardening', () {
    test('truncated varint refused', () {
      expect(
        () => readFields(Uint8List.fromList([0x08, 0x80])),
        throwsSdkError('protobuf-error', 'truncated varint'),
      );
      expect(
        () => readFields(Uint8List.fromList([0x80])),
        throwsSdkError('protobuf-error', 'truncated varint'),
      );
    });

    test('varint over 64 bits refused', () {
      expect(
        () => readFields(
          Uint8List.fromList([0x08, ...List.filled(10, 0x80), 0x01]),
        ),
        throwsSdkError('protobuf-error', 'varint exceeds 64 bits'),
      );
    });

    test('field number 0 refused', () {
      expect(
        () => readFields(Uint8List.fromList([0x00])),
        throwsSdkError('protobuf-error', 'field number 0'),
      );
    });

    test('length-delimited field past the input refused', () {
      expect(
        () => readFields(Uint8List.fromList([0x0a, 0x05, 0x01])),
        throwsSdkError(
            'protobuf-error', 'length-delimited field exceeds input'),
      );
    });

    test('group wire types refused', () {
      expect(
        () => readFields(Uint8List.fromList([0x0b])),
        throwsSdkError('protobuf-error', 'unsupported wire type 3'),
      );
      expect(
        () => readFields(Uint8List.fromList([0x0c])),
        throwsSdkError('protobuf-error', 'unsupported wire type 4'),
      );
    });

    test('fixed64/fixed32 are skippable and bounds-checked', () {
      final fields = readFields(Uint8List.fromList([
        0x09, 1, 2, 3, 4, 5, 6, 7, 8, // field 1, fixed64
        0x15, 9, 10, 11, 12, // field 2, fixed32
      ]));
      expect(fields, hasLength(2));
      expect(fields[0].field, 1);
      expect(fields[0].wireType, 1);
      expect(fields[0].bytes, [1, 2, 3, 4, 5, 6, 7, 8]);
      expect(fields[1].field, 2);
      expect(fields[1].wireType, 5);
      expect(fields[1].bytes, [9, 10, 11, 12]);

      expect(
        () => readFields(Uint8List.fromList([0x09, 1, 2, 3])),
        throwsSdkError('protobuf-error', 'truncated fixed64'),
      );
      expect(
        () => readFields(Uint8List.fromList([0x15, 1])),
        throwsSdkError('protobuf-error', 'truncated fixed32'),
      );
    });
  });

  group('encodeSignRequestProto (Tron)', () {
    const blockHash =
        '0000000002bc75e18d05bd63b934e4e9f3e13f8b54f2eec97a0b5c6c118a5c85';
    final rawData = Uint8List.fromList([0x0a, 0x02, 0xab, 0xcd, 0x40]);

    TronSignRequestProto fullRequest() => TronSignRequestProto(
          xfpHex: '01020304',
          signId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
          hdPath: "m/44'/195'/0'/0/0",
          timestamp: 1700000000000,
          decimals: 6,
          token: 'USDT',
          contractAddress: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
          from: 'TYs2MO9Wb2eYkVLZfCkQXHnZutQpWWK9We',
          to: 'TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVjjW',
          memo: 'coffee',
          value: '12.5',
          fee: 1100000,
          latestBlock: const TronLatestBlock(
            hash: blockHash,
            number: 45970913,
            timestamp: 1700000000123,
          ),
          rawData: rawData,
        );

    test('round-trips through readFields with every field in order', () {
      final base = readFields(encodeSignRequestProto(fullRequest()));
      expect(base, hasLength(3));
      expectVarint(base[0], 1, BigInt.two); // Base.version
      expectString(base[1], 2, 'QrCode Protocol');
      expectMessage(base[2], 3);

      final payload = readFields(base[2].bytes);
      expect(payload, hasLength(3));
      expectVarint(payload[0], 1, BigInt.two); // SIGN_TX
      expectString(payload[1], 2, '01020304');
      expectMessage(payload[2], 4);

      final signTx = readFields(payload[2].bytes);
      expect(signTx, hasLength(6));
      expectString(signTx[0], 1, 'TRON');
      expectString(signTx[1], 2, '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d');
      expectString(signTx[2], 3, "m/44'/195'/0'/0/0");
      expectVarint(signTx[3], 4, BigInt.from(1700000000000));
      expectVarint(signTx[4], 5, BigInt.from(6));
      expectMessage(signTx[5], 8);

      final tronTx = readFields(signTx[5].bytes);
      expect(tronTx, hasLength(9));
      expectString(tronTx[0], 1, 'USDT');
      expectString(tronTx[1], 2, 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t');
      expectString(tronTx[2], 3, 'TYs2MO9Wb2eYkVLZfCkQXHnZutQpWWK9We');
      expectString(tronTx[3], 4, 'TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVjjW');
      expectString(tronTx[4], 5, 'coffee');
      expectString(tronTx[5], 6, '12.5');
      expectMessage(tronTx[6], 7);
      expectVarint(tronTx[7], 9, BigInt.from(1100000));
      expectMessage(tronTx[8], 10);
      expect(tronTx[8].bytes, rawData);

      final latestBlock = readFields(tronTx[6].bytes);
      expect(latestBlock, hasLength(3));
      expectString(latestBlock[0], 1, blockHash);
      expectVarint(latestBlock[1], 2, BigInt.from(45970913));
      expectVarint(latestBlock[2], 3, BigInt.from(1700000000123));
    });

    test('explicitly set defaults ARE written; absent optionals are not', () {
      final minimal = TronSignRequestProto(
        xfpHex: '01020304',
        signId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
        hdPath: "m/44'/195'/0'/0/0",
        timestamp: 0,
        decimals: 0,
        token: 'TRX',
        latestBlock: const TronLatestBlock(
          hash: blockHash,
          number: 45970913,
          timestamp: 1700000000123,
        ),
        rawData: rawData,
      );
      final base = readFields(encodeSignRequestProto(minimal));
      final payload = readFields(base[2].bytes);
      final signTx = readFields(payload[2].bytes);
      expect(signTx.map((f) => f.field), [1, 2, 3, 4, 5, 8]);
      expectVarint(signTx[3], 4, BigInt.zero); // timestamp 0 still on the wire
      expectVarint(signTx[4], 5, BigInt.zero); // decimals 0 still on the wire

      final tronTx = readFields(signTx[5].bytes);
      expect(tronTx.map((f) => f.field), [1, 7, 10]); // no optionals, no fee
    });

    test('fee outside a positive int32 refused', () {
      final withFee = TronSignRequestProto(
        xfpHex: '01020304',
        signId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
        hdPath: "m/44'/195'/0'/0/0",
        timestamp: 0,
        decimals: 6,
        token: 'TRX',
        fee: 0x80000000,
        latestBlock: const TronLatestBlock(
          hash: blockHash,
          number: 1,
          timestamp: 2,
        ),
        rawData: rawData,
      );
      expect(
        () => encodeSignRequestProto(withFee),
        throwsSdkError('invalid-props', 'positive int32'),
      );
    });
  });

  group('encodeBchSignRequestProto', () {
    test('round-trips through readFields with proto3 default omission', () {
      final req = BchSignRequestProto(
        xfpHex: 'f23f9fd2',
        signId: '3b5b5ef1-8f61-4bc2-9e34-90a0a91908d9',
        timestamp: 1700000000000,
        fee: BigInt.from(1000),
        dustThreshold: 546,
        memo: 'note',
        inputs: [
          BchProtoInput(
            txidHex: 'aa' * 32,
            index: 1,
            value: BigInt.from(90000),
            publicKeyHex: '02${'11' * 32}',
            ownerKeyPath: "m/44'/145'/0'/0/3",
          ),
          BchProtoInput(
            txidHex: 'bb' * 32,
            index: 0,
            value: BigInt.zero,
            publicKeyHex: '03${'22' * 32}',
            ownerKeyPath: "m/44'/145'/0'/0/4",
          ),
        ],
        outputs: [
          BchProtoOutput(
            address: 'bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy',
            value: BigInt.from(80000),
            isChange: false,
          ),
          BchProtoOutput(
            address: 'bitcoincash:qq2azmyyv6dtgczexyalqar70q036yund53jvfde0x',
            value: BigInt.from(9000),
            isChange: true,
            changeAddressPath: "m/44'/145'/0'/1/2",
          ),
        ],
      );

      final base = readFields(encodeBchSignRequestProto(req));
      expect(base, hasLength(3));
      expectVarint(base[0], 1, BigInt.two);
      expectString(base[1], 2, 'QrCode Protocol');
      expectMessage(base[2], 3);

      final payload = readFields(base[2].bytes);
      expectVarint(payload[0], 1, BigInt.two);
      expectString(payload[1], 2, 'f23f9fd2');
      expectMessage(payload[2], 4);

      final signTx = readFields(payload[2].bytes);
      // No hdPath (field 3) — the device reads the per-input ownerKeyPath.
      expect(signTx.map((f) => f.field), [1, 2, 4, 5, 10]);
      expectString(signTx[0], 1, 'BCH');
      expectString(signTx[1], 2, '3b5b5ef1-8f61-4bc2-9e34-90a0a91908d9');
      expectVarint(signTx[2], 4, BigInt.from(1700000000000));
      expectVarint(signTx[3], 5, BigInt.from(8)); // decimal: always 8
      expectMessage(signTx[4], 10); // BchTx at oneof tag 10

      final bchTx = readFields(signTx[4].bytes);
      expect(bchTx.map((f) => f.field), [1, 2, 3, 4, 4, 5, 5]);
      expectVarint(bchTx[0], 1, BigInt.from(1000));
      expectVarint(bchTx[1], 2, BigInt.from(546));
      expectString(bchTx[2], 3, 'note');

      final input1 = readFields(bchTx[3].bytes);
      expect(input1.map((f) => f.field), [1, 2, 3, 4, 5]);
      expectString(input1[0], 1, 'aa' * 32);
      expectVarint(input1[1], 2, BigInt.one);
      expectVarint(input1[2], 3, BigInt.from(90000));
      expectString(input1[3], 4, '02${'11' * 32}');
      expectString(input1[4], 5, "m/44'/145'/0'/0/3");

      // index 0 and value 0 are proto3 defaults — omitted.
      final input2 = readFields(bchTx[4].bytes);
      expect(input2.map((f) => f.field), [1, 4, 5]);
      expectString(input2[0], 1, 'bb' * 32);
      expectString(input2[1], 4, '03${'22' * 32}');
      expectString(input2[2], 5, "m/44'/145'/0'/0/4");

      // isChange false and absent changeAddressPath — omitted.
      final output1 = readFields(bchTx[5].bytes);
      expect(output1.map((f) => f.field), [1, 2]);
      expectString(
        output1[0],
        1,
        'bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy',
      );
      expectVarint(output1[1], 2, BigInt.from(80000));

      final output2 = readFields(bchTx[6].bytes);
      expect(output2.map((f) => f.field), [1, 2, 3, 4]);
      expectVarint(output2[1], 2, BigInt.from(9000));
      expectVarint(output2[2], 3, BigInt.one);
      expectString(output2[3], 4, "m/44'/145'/0'/1/2");
    });

    test('zero fee/dust/timestamp and empty memo are omitted', () {
      final req = BchSignRequestProto(
        xfpHex: 'f23f9fd2',
        signId: '3b5b5ef1-8f61-4bc2-9e34-90a0a91908d9',
        timestamp: 0,
        fee: BigInt.zero,
        dustThreshold: 0,
        memo: '',
        inputs: [],
        outputs: [],
      );
      final base = readFields(encodeBchSignRequestProto(req));
      final payload = readFields(base[2].bytes);
      final signTx = readFields(payload[2].bytes);
      expect(signTx.map((f) => f.field), [1, 2, 5, 10]); // no timestamp
      expectMessage(signTx[3], 10);
      expect(signTx[3].bytes, isEmpty); // BchTx omits every default
    });
  });

  group('decodeSignResultProto', () {
    Uint8List buildReply(Uint8List payload) => ProtoWriter()
        .varintField(1, BigInt.two)
        .stringField(2, 'QrCode Protocol')
        .messageField(3, payload)
        .finish();

    test('reads signId/txId/rawTx out of the nested result', () {
      final result = ProtoWriter()
          .stringField(1, '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
          .stringField(2, 'cafe' * 16)
          .stringField(3, '0a02abcd')
          .finish();
      final payload = ProtoWriter().messageField(7, result).finish();
      final decoded = decodeSignResultProto(buildReply(payload));
      expect(decoded.signId, '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d');
      expect(decoded.txId, 'cafe' * 16);
      expect(decoded.rawTx, '0a02abcd');
    });

    test('missing payload refused; missing result yields empty fields', () {
      final noPayload = ProtoWriter().varintField(1, BigInt.two).finish();
      expect(
        () => decodeSignResultProto(noPayload),
        throwsSdkError('malformed-reply', 'carries no payload'),
      );

      final emptyPayload = ProtoWriter().varintField(1, BigInt.two).finish();
      final decoded = decodeSignResultProto(buildReply(emptyPayload));
      expect(decoded.signId, '');
      expect(decoded.txId, '');
      expect(decoded.rawTx, '');
    });

    test('non-UTF-8 string field refused', () {
      final result = ProtoWriter()
          .bytesField(1, Uint8List.fromList([0xff, 0xfe]))
          .finish();
      final payload = ProtoWriter().messageField(7, result).finish();
      expect(
        () => decodeSignResultProto(buildReply(payload)),
        throwsSdkError('malformed-reply', 'not valid UTF-8'),
      );
    });
  });

  group('splitSignedTronTx', () {
    test('splits a hand-built {1: raw_data, 2: sig, 2: sig2} frame', () {
      final rawData = Uint8List.fromList([1, 2, 3, 4]);
      final sig1 = Uint8List.fromList(List.filled(65, 0x11));
      final sig2 = Uint8List.fromList(List.filled(65, 0x22));
      final frame = ProtoWriter()
          .bytesField(1, rawData)
          .bytesField(2, sig1)
          .bytesField(2, sig2)
          .finish();
      final split = splitSignedTronTx(bytesToHex(frame));
      expect(split.rawData, rawData);
      expect(split.signatures, hasLength(2));
      expect(split.signatures[0], sig1);
      expect(split.signatures[1], sig2);
    });

    test('refuses non-hex, varint top-level fields and missing raw_data', () {
      expect(
        () => splitSignedTronTx('zz'),
        throwsSdkError('malformed-reply', 'not hex'),
      );
      final varintTop = ProtoWriter().varintField(1, BigInt.one).finish();
      expect(
        () => splitSignedTronTx(bytesToHex(varintTop)),
        throwsSdkError('malformed-reply', 'unexpected wire type'),
      );
      final noRawData = ProtoWriter()
          .bytesField(2, Uint8List.fromList(List.filled(65, 0x11)))
          .finish();
      expect(
        () => splitSignedTronTx(bytesToHex(noRawData)),
        throwsSdkError('malformed-reply', 'carries no raw_data'),
      );
    });
  });

  group('gzip', () {
    final payload = Uint8List.fromList(
      List.generate(100, (i) => (i * 7 + 3) & 0xff),
    );

    test('compress -> gunzipCapped round-trips', () {
      final blob = gzipCompress(payload);
      expect(blob[3], 0, reason: 'compressor writes no optional header fields');
      expect(gunzipCapped(blob, 64 * 1024), payload);
      expect(gunzipCapped(gzipCompress(Uint8List(0)), 16), isEmpty);
    });

    test('compressed bytes are deterministic (zeroed mtime)', () {
      expect(gzipCompress(payload), gzipCompress(payload));
      expect(gzipCompress(payload).sublist(4, 8), [0, 0, 0, 0]);
    });

    test('corrupted CRC trailer refused', () {
      final blob = gzipCompress(payload);
      blob[blob.length - 5] ^= 0xff; // high byte of the CRC32 trailer
      expect(
        () => gunzipCapped(blob, 64 * 1024),
        throwsSdkError('gzip-error', 'CRC mismatch'),
      );
    });

    test('wrong ISIZE trailer refused', () {
      final blob = gzipCompress(payload);
      blob[blob.length - 4] ^= 0x01; // declared length no longer matches
      expect(
        () => gunzipCapped(blob, 64 * 1024),
        throwsSdkError('gzip-error', 'truncated or malformed'),
      );
    });

    test('declared size over the cap refused before inflating', () {
      final blob = gzipCompress(payload);
      expect(
        () => gunzipCapped(blob, payload.length - 1),
        throwsSdkError('gzip-error', 'byte ceiling'),
      );
    });

    test('understated ISIZE cannot dodge the cap', () {
      final blob = gzipCompress(payload);
      // Declare 40 bytes (under the 50-byte cap); the real output is 100.
      blob.setRange(blob.length - 4, blob.length, [40, 0, 0, 0]);
      expect(
        () => gunzipCapped(blob, 50),
        throwsSdkError('gzip-error', 'inflates past the 50 byte ceiling'),
      );
    });

    test('reserved FLG bits refused', () {
      final blob = gzipCompress(payload);
      blob[3] |= 0x80;
      expect(
        () => gunzipCapped(blob, 64 * 1024),
        throwsSdkError('gzip-error', 'reserved header flag bits'),
      );
    });

    test('FNAME header field is skipped', () {
      final blob = gzipCompress(payload);
      final named = Uint8List.fromList([
        0x1f, 0x8b, 0x08, 0x08, // magic, CM=deflate, FLG=FNAME
        0, 0, 0, 0, // mtime
        blob[8], blob[9], // XFL, OS
        ...'payload.bin'.codeUnits, 0, // zero-terminated name
        ...blob.sublist(10), // deflate body + trailer
      ]);
      expect(gunzipCapped(named, 64 * 1024), payload);
    });

    test('concatenated members refused', () {
      final a = gzipCompress(Uint8List.fromList(List.filled(100, 1)));
      final b = gzipCompress(Uint8List.fromList(List.filled(112, 2)));
      final joined = concatBytes([a, b]);
      expect(
        () => gunzipCapped(joined, 64 * 1024),
        throwsSdkError('gzip-error', 'compressed payload'),
      );
    });

    test('not-a-gzip inputs refused', () {
      expect(
        () => gunzipCapped(Uint8List(10), 1024),
        throwsSdkError('gzip-error', 'too short'),
      );
      expect(
        () => gunzipCapped(Uint8List(18), 1024),
        throwsSdkError('gzip-error', 'not a gzip stream'),
      );
      final badMethod = gzipCompress(payload);
      badMethod[2] = 7;
      expect(
        () => gunzipCapped(badMethod, 64 * 1024),
        throwsSdkError('gzip-error', 'unknown compression method'),
      );
    });
  });
}
