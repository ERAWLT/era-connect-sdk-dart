import 'dart:math';
import 'dart:typed_data';

import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:test/test.dart';

Matcher throwsCborError([String? substring]) => throwsA(
      isA<EraSdkError>().having((e) => e.code, 'code', 'malformed-cbor').having(
          (e) => e.message,
          'message',
          substring == null ? anything : contains(substring)),
    );

/// Fixed-seed replacement for the TS fast-check arbitrary: same value space
/// (uint / bytes / ascii text / bool / array / integer-keyed map / protocol
/// tags), leaves only past depth 4.
CborValue randomValue(Random rng, int depth) {
  const protocolTags = [37, 304, 305, 310, 1103, 1301, 1302];
  final choice = depth >= 4 ? rng.nextInt(4) : rng.nextInt(7);
  switch (choice) {
    case 0:
      final v = (BigInt.from(rng.nextInt(1 << 32)) << 32) |
          BigInt.from(rng.nextInt(1 << 32));
      return cbUint(v);
    case 1:
      return cbBytes(Uint8List.fromList(
          List.generate(rng.nextInt(41), (_) => rng.nextInt(256))));
    case 2:
      return cbText(String.fromCharCodes(
          List.generate(rng.nextInt(21), (_) => 0x20 + rng.nextInt(0x5f))));
    case 3:
      return cbBool(rng.nextBool());
    case 4:
      return cbArray(
          List.generate(rng.nextInt(5), (_) => randomValue(rng, depth + 1)));
    case 5:
      final n = rng.nextInt(5);
      final seen = <int>{};
      final entries = <(int, CborValue)>[];
      for (var i = 0; i < n; i++) {
        final k = rng.nextInt(101);
        if (!seen.add(k)) continue;
        entries.add((k, randomValue(rng, depth + 1)));
      }
      return cbMap(entries);
    default:
      return cbTag(protocolTags[rng.nextInt(protocolTags.length)],
          randomValue(rng, depth + 1));
  }
}

/// [levels] arrays wrapped around a uint leaf.
CborValue nest(int levels) {
  CborValue v = cbUint(0);
  for (var i = 0; i < levels; i++) {
    v = cbArray([v]);
  }
  return v;
}

void main() {
  group('CBOR round-trip properties', () {
    test('our decoder round-trips what our encoder emits', () {
      final rng = Random(20260901);
      for (var i = 0; i < 200; i++) {
        final value = randomValue(rng, 0);
        final bytes = cborEncode(value);
        expect(bytesToHex(cborEncode(cborDecode(bytes))), bytesToHex(bytes));
      }
    });

    test('hostile CBOR is a typed error, never a crash', () {
      final rng = Random(0xC0B0);
      for (var i = 0; i < 200; i++) {
        final bytes = Uint8List.fromList(
            List.generate(1 + rng.nextInt(100), (_) => rng.nextInt(256)));
        final CborValue decoded;
        try {
          decoded = cborDecode(bytes);
        } on EraSdkError catch (e) {
          expect(e.code, 'malformed-cbor');
          continue;
        }
        // Whatever we accept re-encodes canonically (definite, minimal
        // width), and canonicalization is idempotent: decode-then-encode is a
        // fixed point. (The decoder tolerates non-minimal length heads, as
        // the reference implementation does — a stricter refusal could turn
        // away a genuine reply.)
        final canonical = cborEncode(decoded);
        expect(bytesToHex(cborEncode(cborDecode(canonical))),
            bytesToHex(canonical));
      }
    });
  });

  group('depth cap (review: depth cap)', () {
    test('a tree nested to the cap (16) round-trips', () {
      final bytes = cborEncode(nest(16));
      expect(bytesToHex(cborEncode(cborDecode(bytes))), bytesToHex(bytes));
    });

    test('one level past the cap is refused by the encoder', () {
      expect(() => cborEncode(nest(17)), throwsCborError('nesting too deep'));
    });

    test('one level past the cap is refused by the decoder', () {
      final bytes = Uint8List.fromList([...List.filled(17, 0x81), 0x00]);
      expect(() => cborDecode(bytes), throwsCborError('nesting too deep'));
    });
  });

  group('RFC 8949 known answers', () {
    final vectors = <(String, CborValue)>[
      // Unsigned integers, minimal-width heads.
      ('00', cbUint(0)),
      ('01', cbUint(1)),
      ('0a', cbUint(10)),
      ('17', cbUint(23)),
      ('1818', cbUint(24)),
      ('1819', cbUint(25)),
      ('1864', cbUint(100)),
      ('1903e8', cbUint(1000)),
      ('1a000f4240', cbUint(1000000)),
      ('1b000000e8d4a51000', cbUint(1000000000000)),
      ('1bffffffffffffffff', cbUint(BigInt.parse('18446744073709551615'))),
      // Negative integers (the model holds the magnitude: -1 - value).
      ('20', CborNegint(BigInt.from(0))), // -1
      ('29', CborNegint(BigInt.from(9))), // -10
      ('3863', CborNegint(BigInt.from(99))), // -100
      ('3903e7', CborNegint(BigInt.from(999))), // -1000
      // Simple values.
      ('f4', cbBool(false)),
      ('f5', cbBool(true)),
      ('f6', const CborNull()),
      // Byte strings.
      ('40', cbBytes(Uint8List(0))),
      ('4401020304', cbBytes(Uint8List.fromList([1, 2, 3, 4]))),
      // Text strings.
      ('60', cbText('')),
      ('6161', cbText('a')),
      ('6449455446', cbText('IETF')),
      ('62225c', cbText('"\\')),
      ('62c3bc', cbText('ü')),
      ('63e6b0b4', cbText('水')),
      ('64f0908591', cbText('\u{10151}')),
      // Arrays.
      ('80', cbArray([])),
      ('83010203', cbArray([cbUint(1), cbUint(2), cbUint(3)])),
      (
        '8301820203820405',
        cbArray([
          cbUint(1),
          cbArray([cbUint(2), cbUint(3)]),
          cbArray([cbUint(4), cbUint(5)]),
        ])
      ),
      (
        '98190102030405060708090a0b0c0d0e0f101112131415161718181819',
        cbArray([for (var i = 1; i <= 25; i++) cbUint(i)])
      ),
      // Maps (entry order preserved).
      ('a0', const CborMap([])),
      ('a201020304', cbMap([(1, cbUint(2)), (3, cbUint(4))])),
      (
        'a26161016162820203',
        CborMap([
          (cbText('a'), cbUint(1)),
          (cbText('b'), cbArray([cbUint(2), cbUint(3)])),
        ])
      ),
      (
        '826161a161626163',
        cbArray([
          cbText('a'),
          const CborMap([(CborText('b'), CborText('c'))]),
        ])
      ),
      // Tags (encoded structurally, never transformed).
      ('c11a514b67b0', cbTag(1, cbUint(1363896240))),
      ('d74401020304', cbTag(23, cbBytes(Uint8List.fromList([1, 2, 3, 4])))),
    ];

    test('encoder emits the RFC bytes; decode-encode returns them', () {
      for (final (hex, value) in vectors) {
        expect(bytesToHex(cborEncode(value)), hex);
        expect(bytesToHex(cborEncode(cborDecode(hexToBytes(hex)))), hex);
      }
    });

    test('a non-minimal integer head is tolerated and re-encoded minimally',
        () {
      // 0x1817 is uint 23 with a needlessly wide head.
      final decoded = cborDecode(hexToBytes('1817'));
      expect(decoded, isA<CborUint>());
      expect((decoded as CborUint).value, BigInt.from(23));
      expect(bytesToHex(cborEncode(decoded)), '17');
    });
  });

  group('decoder policy refusals', () {
    test('indefinite lengths are refused', () {
      expect(() => cborDecode(hexToBytes('5f410100ff')),
          throwsCborError('indefinite lengths are refused'));
      expect(() => cborDecode(hexToBytes('9fff')),
          throwsCborError('indefinite lengths are refused'));
    });

    test('floats and unknown simple values are refused', () {
      expect(() => cborDecode(hexToBytes('f93c00')),
          throwsCborError('unsupported simple/float'));
      expect(() => cborDecode(hexToBytes('fb3ff199999999999a')),
          throwsCborError('unsupported simple/float'));
      expect(() => cborDecode(hexToBytes('f0')),
          throwsCborError('unsupported simple/float'));
      // Undefined (simple 23) is not in the protocol either.
      expect(() => cborDecode(hexToBytes('f7')),
          throwsCborError('unsupported simple/float'));
    });

    test('duplicate map keys are refused', () {
      expect(() => cborDecode(hexToBytes('a201020103')),
          throwsCborError('duplicate map key'));
    });

    test('duplicate detection compares keys canonically, not byte-wise', () {
      // Keys 0x01 and 0x1801 are both uint 1.
      expect(() => cborDecode(hexToBytes('a20102180103')),
          throwsCborError('duplicate map key'));
    });

    test('trailing bytes after the top-level item are refused', () {
      expect(() => cborDecode(hexToBytes('0101')),
          throwsCborError('trailing bytes'));
    });

    test('truncated input is refused', () {
      expect(() => cborDecode(hexToBytes('18')), throwsCborError('truncated'));
      expect(() => cborDecode(hexToBytes('4401')),
          throwsCborError('length exceeds input'));
      expect(() => cborDecode(hexToBytes('8301')),
          throwsCborError('length exceeds input'));
      expect(() => cborDecode(hexToBytes('a2010203')),
          throwsCborError('map length exceeds input'));
    });

    test('reserved additional info is refused', () {
      expect(() => cborDecode(hexToBytes('1c')),
          throwsCborError('reserved additional info'));
    });

    test('a tag past 32 bits is refused', () {
      expect(() => cborDecode(hexToBytes('db0100000000000000')),
          throwsCborError('tag exceeds 32 bits'));
    });

    test('invalid UTF-8 in a text string is refused', () {
      expect(() => cborDecode(hexToBytes('61ff')),
          throwsCborError('not valid UTF-8'));
      // Overlong encoding of NUL.
      expect(() => cborDecode(hexToBytes('62c080')),
          throwsCborError('not valid UTF-8'));
    });
  });

  group('encoder guards', () {
    test('an argument past 64 bits is refused', () {
      expect(() => cborEncode(CborUint(BigInt.one << 64)),
          throwsCborError('exceeds 64 bits'));
    });

    test('a negative nint magnitude is refused', () {
      expect(() => cborEncode(CborNegint(BigInt.from(-1))),
          throwsCborError('nint holds the magnitude'));
    });
  });

  group('model helpers', () {
    test('cbUint refuses a negative value', () {
      expect(
          () => cbUint(-1),
          throwsA(isA<EraSdkError>()
              .having((e) => e.code, 'code', 'invalid-props')));
    });

    test('cbMap preserves insertion order', () {
      final map = cbMap([(2, cbText('b')), (1, cbText('a'))]);
      expect(bytesToHex(cborEncode(map)), 'a2026162016161');
    });

    test('mapGet finds integer keys and is null-safe on non-maps', () {
      final map = cbMap([(2, cbText('b')), (1, cbText('a'))]);
      expect(asText(mapGet(map, 1)), 'a');
      expect(asText(mapGet(map, 2)), 'b');
      expect(mapGet(map, 3), isNull);
      expect(mapGet(cbUint(1), 1), isNull);
    });

    test('as* accessors strip tag wrappers', () {
      expect(asUint(cbTag(37, cbUint(5))), BigInt.from(5));
      expect(asBytes(cbTag(304, cbTag(37, cbBytes(Uint8List.fromList([9]))))),
          Uint8List.fromList([9]));
      expect(asText(cbTag(1103, cbText('x'))), 'x');
      expect(asBool(cbTag(37, cbBool(true))), true);
      final arr = asArray(cbTag(1301, cbArray([cbUint(1)])));
      expect(arr, isNotNull);
      expect(arr!.length, 1);
      final map = asMap(cbTag(1302, cbMap([(1, cbUint(2))])));
      expect(map, isNotNull);
      expect(asUint(mapGet(map!, 1)), BigInt.from(2));
    });

    test('as* accessors return null on kind mismatch and null input', () {
      expect(asUint(cbText('1')), isNull);
      expect(asBytes(cbUint(1)), isNull);
      expect(asText(cbBytes(Uint8List(0))), isNull);
      expect(asArray(cbUint(1)), isNull);
      expect(asMap(cbArray([])), isNull);
      expect(asBool(const CborNull()), isNull);
      expect(asUint(null), isNull);
      expect(asBytes(null), isNull);
      expect(asText(null), isNull);
      expect(asArray(null), isNull);
      expect(asMap(null), isNull);
      expect(asBool(null), isNull);
    });
  });
}
