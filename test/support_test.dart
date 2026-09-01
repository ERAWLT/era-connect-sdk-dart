import 'dart:typed_data';

import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/qr/animated_ur.dart';
import 'package:era_connect/src/raw.dart';
import 'package:era_connect/src/registry/keypath.dart';
import 'package:era_connect/src/scan/ur_scanner.dart';
import 'package:era_connect/src/ur/bytewords.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:test/test.dart';

Matcher throwsSdkError(String code) =>
    throwsA(isA<EraSdkError>().having((e) => e.code, 'code', code));

/// A single-part UR frame of [type] carrying [cbor], as the wire sends it.
String singlePartFrame(String type, Uint8List cbor) =>
    'ur:$type/${bytewordsEncode(cbor)}';

void main() {
  group('keypath parsing', () {
    test('parses a full hardened/unhardened path', () {
      final levels = parsePath("m/44'/60'/0'/0/5");
      expect(levels.length, 5);
      expect(levels[0].index, 44);
      expect(levels[0].hardened, isTrue);
      expect(levels[1].index, 60);
      expect(levels[1].hardened, isTrue);
      expect(levels[3].index, 0);
      expect(levels[3].hardened, isFalse);
      expect(levels[4].index, 5);
      expect(levels[4].hardened, isFalse);
    });

    test('formatPath round-trips parsePath', () {
      const path = "m/44'/195'/0'/0/7";
      expect(formatPath(parsePath(path)), path);
      expect(formatPath(parsePath('m/0')), 'm/0');
    });

    test('accepts the largest unhardened index', () {
      final levels = parsePath("m/2147483647'");
      expect(levels.single.index, 0x7fffffff);
      expect(levels.single.hardened, isTrue);
    });

    test('refuses paths without the m/ prefix', () {
      expect(() => parsePath("44'/60'"), throwsSdkError('invalid-props'));
      expect(() => parsePath("M/44'"), throwsSdkError('invalid-props'));
      expect(() => parsePath(''), throwsSdkError('invalid-props'));
    });

    test('refuses malformed segments', () {
      expect(() => parsePath('m/'), throwsSdkError('invalid-props'));
      expect(() => parsePath('m/4a'), throwsSdkError('invalid-props'));
      expect(() => parsePath("m/44''"), throwsSdkError('invalid-props'));
      expect(() => parsePath('m/-1'), throwsSdkError('invalid-props'));
      expect(() => parsePath("m/44'/"), throwsSdkError('invalid-props'));
    });

    test('refuses an index at or past the hardened offset', () {
      expect(() => parsePath('m/2147483648'), throwsSdkError('invalid-props'));
      expect(
        () => parsePath('m/99999999999999999999'),
        throwsSdkError('invalid-props'),
      );
    });

    test('pathEquals compares level by level', () {
      final a = parsePath("m/44'/60'/0'/0/0");
      expect(pathEquals(a, parsePath("m/44'/60'/0'/0/0")), isTrue);
      expect(pathEquals(a, parsePath("m/44'/60'/0'/0")), isFalse);
      expect(pathEquals(a, parsePath("m/44'/60'/0'/0/0'")), isFalse);
      expect(pathEquals(a, parsePath("m/44'/60'/0'/0/1")), isFalse);
    });
  });

  group('keypath CBOR', () {
    test('keypath304 with an xfp encodes the canonical shape', () {
      final value = keypath304(parsePath("m/44'/60'/0'/0/0"), 0x12345678);
      expect(
        bytesToHex(cborEncode(value)),
        'd90130a2018a182cf5183cf500f500f400f4021a12345678',
      );
    });

    test('keypath304 without an xfp omits key 2', () {
      final value = keypath304(parsePath("m/44'/60'/0'/0/0"));
      expect(
        bytesToHex(cborEncode(value)),
        'd90130a1018a182cf5183cf500f500f400f4',
      );
    });

    test('parsePathComponents round-trips pathComponentsCbor', () {
      final levels = parsePath("m/44'/501'/0'/0'");
      final parsed = parsePathComponents(pathComponentsCbor(levels));
      expect(parsed, isNotNull);
      expect(pathEquals(parsed!, levels), isTrue);
    });

    test('parsePathComponents returns null on malformed lists', () {
      expect(parsePathComponents(null), isNull);
      expect(parsePathComponents(cbUint(1)), isNull);
      // Odd-length component list.
      expect(parsePathComponents(cbArray([cbUint(44)])), isNull);
      // Hardened flag is not a bool.
      expect(
        parsePathComponents(cbArray([cbUint(44), cbUint(1)])),
        isNull,
      );
      // Index at the hardened offset.
      expect(
        parsePathComponents(cbArray([cbUint(0x80000000), cbBool(true)])),
        isNull,
      );
    });
  });

  group('xfp normalization', () {
    test('accepts a u32 int as-is', () {
      expect(normalizeXfp(0), 0);
      expect(normalizeXfp(0x1a2b3c4d), 0x1a2b3c4d);
      expect(normalizeXfp(0xffffffff), 0xffffffff);
    });

    test('accepts hex strings, 0x-prefixed and uppercase', () {
      expect(normalizeXfp('1a2b3c4d'), 0x1a2b3c4d);
      expect(normalizeXfp('0x1A2B3C4D'), 0x1a2b3c4d);
      expect(normalizeXfp('f'), 0xf);
    });

    test('refuses out-of-range and malformed xfps', () {
      expect(() => normalizeXfp(-1), throwsSdkError('invalid-props'));
      expect(() => normalizeXfp(0x100000000), throwsSdkError('invalid-props'));
      expect(() => normalizeXfp('xyz'), throwsSdkError('invalid-props'));
      expect(() => normalizeXfp('123456789'), throwsSdkError('invalid-props'));
      expect(() => normalizeXfp(''), throwsSdkError('invalid-props'));
    });

    test('xfpToHex pads to 8 lowercase hex characters', () {
      expect(xfpToHex(0x1a), '0000001a');
      expect(xfpToHex(0x1a2b3c4d), '1a2b3c4d');
      expect(xfpToHex(normalizeXfp('0000001a')), '0000001a');
    });
  });

  group('scanner single-frame flow', () {
    final payload = cborEncode(cbMap([(1, cbBytes(hexToBytes('deadbeef')))]));

    test('a pinned scanner completes on one matching frame', () {
      final scanner = UrScanner(
        const UrScannerOptions(expectedTypes: ['eth-signature']),
      );
      expect(scanner.isComplete, isFalse);
      expect(scanner.urType, isNull);

      final result =
          scanner.receivePart(singlePartFrame('eth-signature', payload));
      expect(result, isA<ScanComplete>());
      final ur = (result as ScanComplete).ur;
      expect(ur.type, 'eth-signature');
      expect(equalBytes(ur.cbor, payload), isTrue);
      expect(scanner.isComplete, isTrue);
      expect(scanner.progress, 1.0);
      expect(scanner.result().type, 'eth-signature');

      // Any further frame just reports completion.
      expect(scanner.receivePart('junk'), isA<ScanComplete>());
    });

    test('uppercase wire frames are accepted', () {
      final scanner = UrScanner();
      final result =
          scanner.receivePart(singlePartFrame('bytes', payload).toUpperCase());
      expect(result, isA<ScanComplete>());
      expect((result as ScanComplete).ur.type, 'bytes');
    });

    test('frames of another type are rejected before decoding', () {
      final scanner = UrScanner(
        const UrScannerOptions(expectedTypes: ['eth-signature']),
      );
      final frame = singlePartFrame('btc-signature', payload);
      final first = scanner.receivePart(frame);
      expect(first, isA<ScanRejected>());
      final rejection = (first as ScanRejected).rejection;
      expect(rejection.code, 'wrong-ur-type');
      expect(rejection.repeated, 1);

      // A static wrong-type QR repeats the identical rejection, counted.
      final second = scanner.receivePart(frame);
      expect((second as ScanRejected).rejection.repeated, 2);
      expect(scanner.lastRejection!.repeated, 2);
      expect(scanner.isComplete, isFalse);
    });

    test('non-UR text is rejected, never thrown', () {
      final scanner = UrScanner();
      final result = scanner.receivePart('hello world');
      expect(result, isA<ScanRejected>());
      expect((result as ScanRejected).rejection.code, 'not-a-ur');
    });

    test('an unreadable frame is rejected once, then deduplicated', () {
      final scanner = UrScanner();
      const frame = 'ur:eth-signature/aaaa';
      expect(scanner.receivePart(frame), isA<ScanRejected>());
      expect(scanner.receivePart(frame), isA<ScanDuplicate>());
    });

    test('TypedUrScanner.parse assembles and parses in one call', () {
      final scanner = TypedUrScanner<String>(
        const UrScannerOptions(expectedTypes: ['eth-signature']),
        (ur) => ur.type.toUpperCase(),
      );
      expect(() => scanner.parse(), throwsSdkError('incomplete-scan'));
      scanner.receivePart(singlePartFrame('eth-signature', payload));
      expect(scanner.parse(), 'ETH-SIGNATURE');
    });
  });

  group('animated UR', () {
    test('a small payload is a single frame', () {
      final cbor = cborEncode(cbBytes(hexToBytes('00010203')));
      final ur = Ur('eth-sign-request', cbor);
      final animated = AnimatedUr(ur);
      expect(animated.isSingleFrame, isTrue);
      expect(animated.fragmentCount, 1);
      expect(animated.urType, 'eth-sign-request');
      expect(animated.nextFrame(), ur.toString().toUpperCase());
      expect(animated.nextFrame(), animated.nextFrame());
      expect(animated.toString(), ur.toString());
    });

    test('a large payload animates and reassembles through the scanner', () {
      final cbor = cborEncode(
        cbBytes(Uint8List.fromList(List.generate(400, (i) => i & 0xff))),
      );
      final animated = AnimatedUr(
        Ur('eth-sign-request', cbor),
        const AnimatedUrOptions(maxFragmentLength: 100),
      );
      expect(animated.isSingleFrame, isFalse);
      expect(animated.fragmentCount, greaterThan(1));

      final scanner = UrScanner(
        const UrScannerOptions(expectedTypes: ['eth-sign-request']),
      );
      ScanFeedResult result = scanner.receivePart(animated.nextFrame());
      var frames = 1;
      while (result is! ScanComplete && frames < 60) {
        result = scanner.receivePart(animated.nextFrame());
        frames += 1;
      }
      expect(result, isA<ScanComplete>());
      expect(equalBytes((result as ScanComplete).ur.cbor, cbor), isTrue);
    });
  });

  group('request plumbing', () {
    final context = resolveContext();

    test('resolveContext applies defaults and keeps overrides', () {
      expect(context.origin, 'ERA Connect');
      expect(context.maxFragmentLength, 180);
      expect(context.randomBytes, isNull);

      final custom = resolveContext(
        const EraConnectConfig(origin: 'My Wallet', maxFragmentLength: 120),
      );
      expect(custom.origin, 'My Wallet');
      expect(custom.maxFragmentLength, 120);

      // A resolved context resolves to itself unchanged.
      final again = resolveContext(custom);
      expect(again.origin, 'My Wallet');
      expect(again.maxFragmentLength, 120);
    });

    test('resolveRequestId mints 16 bytes or normalizes the given id', () {
      final minted = resolveRequestId(context, null);
      expect(minted.length, 16);
      final given =
          resolveRequestId(context, '00112233-4455-6677-8899-aabbccddeeff');
      expect(bytesToHex(given), '00112233445566778899aabbccddeeff');
      expect(() => resolveRequestId(context, 'nope'),
          throwsSdkError('invalid-props'));
    });

    test('toUr accepts a Ur or a single-part string, never a multi-part one',
        () {
      final cbor = cborEncode(cbBytes(hexToBytes('cafe')));
      final ur = Ur('bytes', cbor);
      expect(identical(toUr(ur), ur), isTrue);
      final parsed = toUr(singlePartFrame('bytes', cbor));
      expect(parsed.type, 'bytes');
      expect(equalBytes(parsed.cbor, cbor), isTrue);

      final multi = AnimatedUr(
        Ur('bytes', cborEncode(cbBytes(Uint8List(400)))),
        const AnimatedUrOptions(maxFragmentLength: 100),
      );
      expect(() => toUr(multi.nextFrame()), throwsSdkError('invalid-props'));
    });

    test('requireUrType refuses other types with a truncated name', () {
      final ur = Ur('tron-signature', cborEncode(cbUint(1)));
      requireUrType(ur, const ['tron-signature'], 'reply');
      expect(
        () => requireUrType(ur, const ['eth-signature'], 'reply'),
        throwsSdkError('wrong-ur-type'),
      );
    });

    test('requireReplyMap wants readable CBOR that is a map', () {
      final id = hexToBytes('00112233445566778899aabbccddeeff');
      final map = requireReplyMap(
        Ur('eth-signature', cborEncode(cbMap([(1, cbBytes(id))]))),
        'reply',
      );
      expect(mapGet(map, 1), isNotNull);
      expect(
        () => requireReplyMap(
            Ur('eth-signature', cborEncode(cbUint(5))), 'reply'),
        throwsSdkError('malformed-reply'),
      );
      expect(
        () => requireReplyMap(Ur('eth-signature', hexToBytes('ff')), 'reply'),
        throwsSdkError('malformed-cbor'),
      );
    });

    test('requireRequestIdEcho compares bytes through the UUID tag', () {
      final id = hexToBytes('00112233445566778899aabbccddeeff');
      final tagged = cbMap([(1, cbTag(37, cbBytes(id)))]);
      expect(bytesToHex(requireRequestIdEcho(tagged, 1, id, 'reply')),
          bytesToHex(id));
      final untagged = cbMap([(1, cbBytes(id))]);
      expect(bytesToHex(requireRequestIdEcho(untagged, 1, id, 'reply')),
          bytesToHex(id));

      final other = cbMap(
        [
          (
            1,
            cbTag(37, cbBytes(hexToBytes('ffffffffffffffffffffffffffffffff')))
          )
        ],
      );
      expect(
        () => requireRequestIdEcho(other, 1, id, 'reply'),
        throwsSdkError('request-id-mismatch'),
      );
      final absent = cbMap([(2, cbBytes(id))]);
      expect(
        () => requireRequestIdEcho(absent, 1, id, 'reply'),
        throwsSdkError('malformed-reply'),
      );
    });

    test('requireSignatureBytes enforces the length window', () {
      expect(
        requireSignatureBytes(cbBytes(Uint8List(65)), 'reply', 64, 65).length,
        65,
      );
      expect(
        requireSignatureBytes(
                cbTag(99, cbBytes(Uint8List(64))), 'reply', 64, 65)
            .length,
        64,
      );
      expect(
        () => requireSignatureBytes(cbBytes(Uint8List(63)), 'reply', 64, 65),
        throwsSdkError('malformed-reply'),
      );
      expect(
        () => requireSignatureBytes(null, 'reply', 64, 65),
        throwsSdkError('malformed-reply'),
      );
      expect(
        () => requireSignatureBytes(cbUint(7), 'reply', 64, 65),
        throwsSdkError('malformed-reply'),
      );
    });

    test('makeSignRequest wires the QR, the scanner pin and the echo check',
        () {
      final requestId = hexToBytes('00112233445566778899aabbccddeeff');
      final signature = Uint8List.fromList(List.generate(65, (i) => i));
      final request = makeSignRequest<Uint8List>(
        ur: Ur(
            'eth-sign-request', cborEncode(cbMap([(1, cbBytes(requestId))]))),
        requestId: requestId,
        replyTypes: const ['eth-signature'],
        context: context,
        parse: (ur) {
          requireUrType(ur, const ['eth-signature'], 'reply');
          final map = requireReplyMap(ur, 'reply');
          requireRequestIdEcho(map, 1, requestId, 'reply');
          return requireSignatureBytes(mapGet(map, 2), 'reply', 65, 65);
        },
      );
      expect(request.warnings, isEmpty);
      expect(request.toAnimated().urType, 'eth-sign-request');

      final replyCbor = cborEncode(
        cbMap([(1, cbTag(37, cbBytes(requestId))), (2, cbBytes(signature))]),
      );
      final scanner = request.scanner();
      // The pin rejects foreign types...
      final rejected =
          scanner.receivePart(singlePartFrame('sol-signature', replyCbor));
      expect((rejected as ScanRejected).rejection.code, 'wrong-ur-type');
      // ...and the genuine reply assembles and parses.
      final done =
          scanner.receivePart(singlePartFrame('eth-signature', replyCbor));
      expect(done, isA<ScanComplete>());
      expect(equalBytes(scanner.parse(), signature), isTrue);
    });

    test('RawModule wraps, parses and animates arbitrary URs', () {
      final raw = RawModule(context);
      final cbor = cborEncode(cbBytes(hexToBytes('0badf00d')));
      final ur = raw.ur('my-custom-type', cbor);
      expect(ur.type, 'my-custom-type');
      final animated = raw.animate(ur);
      expect(animated.isSingleFrame, isTrue);
      final parsed = raw.parse(animated.nextFrame());
      expect(parsed.type, 'my-custom-type');
      expect(equalBytes(parsed.cbor, cbor), isTrue);
    });
  });
}
