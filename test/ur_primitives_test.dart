import 'dart:typed_data';

import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/ur/bytewords.dart';
import 'package:era_connect/src/ur/crc32.dart';
import 'package:era_connect/src/ur/limits.dart';
import 'package:era_connect/src/ur/sampler.dart';
import 'package:era_connect/src/ur/xoshiro.dart';
import 'package:crypto/crypto.dart' show sha256;
import 'package:test/test.dart';

/// Canonical BCR-2020-005 single-part vector: the bytewords body pins the
/// word table, the minimal (first+last letter) style and the CRC32 append
/// in one assertion.
const String singlePartCbor =
    '5832916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccba4'
    '4f7f04f2de44f42d84c374a0e149136f25b018';
const String singlePartBody =
    'hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsbox'
    'gwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch';

/// Canonical BCR-2020-005 multi-part message (the 9-fragment vector).
const String multiPartCbor =
    '590100916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccb'
    'a44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a8cde6d0e2e'
    'c43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f965e25ee29039fdf8c'
    'a74f1c769fc07eb7ebaec46e0695aea6cbd60b3ec4bbff1b9ffe8a9e7240129377'
    'b9d3711ed38d412fbb4442256f1e6f595e0fc57fed451fb0a0101fb76b1fb1e1b8'
    '8cfdfdaa946294a47de8fff173f021c0e6f65b05c0a494e50791270a0050a73ae6'
    '9b6725505a2ec8a5791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb824'
    '8b717c22951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d';

Matcher throwsSdkError(String code, String messagePart) => throwsA(
      isA<EraSdkError>()
          .having((e) => e.code, 'code', code)
          .having((e) => e.message, 'message', contains(messagePart)),
    );

void main() {
  group('crc32', () {
    test('known answers', () {
      expect(crc32(utf8Encode('Hello, world!')), 0xebe6c6e6);
      expect(crc32(Uint8List(0)), 0x00000000);
      // The classic IEEE check value.
      expect(crc32(utf8Encode('123456789')), 0xcbf43926);
    });

    test('checksum of the canonical multi-part message', () {
      // Independently derived with Node's zlib.crc32 over the same bytes.
      expect(crc32(hexToBytes(multiPartCbor)), 0xeda0ae73);
    });
  });

  group('bytewords', () {
    test('encodes the canonical single-part vector body', () {
      expect(bytewordsEncode(hexToBytes(singlePartCbor)), singlePartBody);
    });

    test('decodes the canonical single-part vector body', () {
      expect(bytesToHex(bytewordsDecode(singlePartBody)), singlePartCbor);
    });

    test('a well-formed round trip is untouched', () {
      final data = Uint8List.fromList([0, 1, 2, 253, 254, 255]);
      expect(bytewordsDecode(bytewordsEncode(data)), data);
    });

    test('an invalid byteword pair is refused instead of decoding to 0xFF', () {
      expect(
        () => bytewordsDecode('zzzzzzzzzzzz'),
        throwsSdkError('malformed-bytewords', 'byteword'),
      );
    });

    test('a corrupted trailing CRC is refused', () {
      final good = bytewordsEncode(Uint8List.fromList([1, 2, 3]));
      final corrupted = good.substring(0, good.length - 2) +
          (good.endsWith('ae') ? 'ao' : 'ae');
      expect(() => bytewordsDecode(corrupted), throwsA(isA<EraSdkError>()));
    });

    test('a body too short to hold a CRC is refused', () {
      expect(
        () => bytewordsDecode('aeae'),
        throwsSdkError('malformed-bytewords', 'checksum plus one byte'),
      );
    });

    test('an odd number of letters is refused', () {
      expect(
        () => bytewordsDecode('aea'),
        throwsSdkError('malformed-bytewords', 'odd number of letters'),
      );
    });

    test('a letter outside a..z is refused', () {
      expect(
        () => bytewordsDecode('aeaeaeaeaA'),
        throwsSdkError('malformed-bytewords', 'letter out of range'),
      );
      expect(
        () => bytewordsDecode('aeaeaeaea!'),
        throwsSdkError('malformed-bytewords', 'letter out of range'),
      );
    });
  });

  group('xoshiro256**', () {
    // Pinned sequence: seed = sha256('test vector seed'). The raw values were
    // produced by this port and cross-checked against an independent Node
    // BigInt implementation of the same reference algorithm.
    final seed = Uint8List.fromList(
      sha256.convert(utf8Encode('test vector seed')).bytes,
    );

    test('the seed digest itself is what we think it is', () {
      expect(
        bytesToHex(seed),
        '80b1d8e107d21b007fc82cfa21b13433b4f35d142462cfe6c9a37f33f7e0deb8',
      );
    });

    test('first 8 raw 64-bit draws are pinned', () {
      final rng = Xoshiro256ss(seed);
      final expected = [
        '17f3fbf613167db7',
        'afdbd1ad2a42ba9c',
        '4b1985637360ad7a',
        'ae76c1c019dd39d7',
        '1fae6274a484a355',
        '999eeba1efa1129f',
        '3558a4ab31fbb4e2',
        '94a5752b22ec5581',
      ];
      for (final hex in expected) {
        expect(rng.nextRaw64().toRadixString(16).padLeft(16, '0'), hex);
      }
    });

    test('first 4 doubles are pinned (top 53 bits, exact)', () {
      final rng = Xoshiro256ss(seed);
      expect(rng.nextDouble(), 0.093566653801724686);
      expect(rng.nextDouble(), 0.68694792249358272);
      expect(rng.nextDouble(), 0.29335817029948663);
      expect(rng.nextDouble(), 0.68149958553282353);
    });

    test('a seed of the wrong length is refused', () {
      expect(() => Xoshiro256ss(Uint8List(31)), throwsFormatException);
      expect(() => Xoshiro256ss(Uint8List(33)), throwsFormatException);
    });

    test('an all-zero seed is refused', () {
      expect(() => Xoshiro256ss(Uint8List(32)), throwsFormatException);
    });
  });

  group('fountain sampler', () {
    // crc32 of the canonical multi-part message, see above.
    const canonicalChecksum = 0xeda0ae73;

    test('seqNum <= seqLength is the source fragment itself', () {
      expect(chooseFragmentIndexes(1, 1, 0), [0]);
      expect(chooseFragmentIndexes(5, 9, canonicalChecksum), [4]);
      expect(chooseFragmentIndexes(9, 9, canonicalChecksum), [8]);
    });

    test('fountain frames of the canonical vector cover pinned indexes', () {
      // Cross-checked two ways: an independent Node implementation of the
      // reference sampler, and the published 20-frame BCR-2020-005 sequence
      // (frame 10-9 repeats fragment 0's bytes, frame 11-9 fragment 2's).
      expect(chooseFragmentIndexes(10, 9, canonicalChecksum), [0]);
      expect(chooseFragmentIndexes(11, 9, canonicalChecksum), [2]);
      expect(chooseFragmentIndexes(12, 9, canonicalChecksum), [6, 2]);
      expect(chooseFragmentIndexes(20, 9, canonicalChecksum), [2, 1, 6]);
    });

    test('a larger draw is pinned too (order matters, not just membership)',
        () {
      expect(
        chooseFragmentIndexes(100, 50, 0xdeadbeef),
        [
          40, 22, 12, 32, 18, 7, 5, 0, 16, 26, 34,
          47, 35, 49, 3, 24, 37, 29, 44, 39, 31, //
        ],
      );
    });

    test('the sampler refuses a length the protocol cannot produce', () {
      expect(() => chooseFragmentIndexes(5000, 4096, 1), throwsRangeError);
      expect(() => chooseFragmentIndexes(1, 0, 1), throwsRangeError);
    });
  });

  group('UrLimits / headerIsConsistent', () {
    test('a genuine three-fragment header is consistent', () {
      for (var seqNum = 1; seqNum <= 3; seqNum++) {
        expect(
          headerIsConsistent(
            seqNum: seqNum,
            seqLength: 3,
            messageLength: 60,
            checksum: 1,
            fragmentLength: 20,
          ),
          isTrue,
        );
      }
    });

    test('a huge seqLength is refused instead of sizing a list', () {
      expect(
        headerIsConsistent(
          seqNum: 1,
          seqLength: 500000,
          messageLength: 100,
          checksum: 1,
          fragmentLength: 10,
        ),
        isFalse,
      );
    });

    test('a huge messageLength is refused', () {
      expect(
        headerIsConsistent(
          seqNum: 1,
          seqLength: 2,
          messageLength: 500 * 1024 * 1024,
          checksum: 1,
          fragmentLength: 10,
        ),
        isFalse,
      );
    });

    test('one byte over the message cap is refused, consistent header and all',
        () {
      // 64 KiB + 1 across 17 fragments of 4096 bytes: the ceil relation
      // holds, so ONLY the cap can be the reason.
      expect(
        headerIsConsistent(
          seqNum: 1,
          seqLength: 17,
          messageLength: 64 * 1024 + 1,
          checksum: 1,
          fragmentLength: 4096,
        ),
        isFalse,
      );
      // At the cap exactly, the same shape is accepted.
      expect(
        headerIsConsistent(
          seqNum: 1,
          seqLength: 16,
          messageLength: 64 * 1024,
          checksum: 1,
          fragmentLength: 4096,
        ),
        isTrue,
      );
    });

    test('a seqLength of 1 cannot bind', () {
      expect(
        headerIsConsistent(
          seqNum: 1,
          seqLength: 1,
          messageLength: 10,
          checksum: 1,
          fragmentLength: 10,
        ),
        isFalse,
      );
    });

    test('the ceil relation itself is enforced', () {
      // Claims 3 fragments for a message 2 would cover.
      expect(
        headerIsConsistent(
          seqNum: 1,
          seqLength: 3,
          messageLength: 40,
          checksum: 1,
          fragmentLength: 20,
        ),
        isFalse,
      );
      // Claims fewer fragments than the message needs.
      expect(
        headerIsConsistent(
          seqNum: 1,
          seqLength: 2,
          messageLength: 61,
          checksum: 1,
          fragmentLength: 20,
        ),
        isFalse,
      );
    });
  });
}
