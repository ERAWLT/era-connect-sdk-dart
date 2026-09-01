import 'dart:typed_data';

import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/ur/bytewords.dart';
import 'package:era_connect/src/ur/crc32.dart';
import 'package:era_connect/src/ur/decoder.dart';
import 'package:era_connect/src/ur/sampler.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:test/test.dart';

/// Everything a scanned QR can dictate to the decoder, and what the decoder is
/// required to refuse. The camera is an untrusted input channel: a sticker on
/// the device, a poster, a screenshot from the gallery — every case below is
/// one QR string.

String hostileFrame({
  String? type,
  required int seqNum,
  required int seqLen,
  required int messageLen,
  required int checksum,
  Uint8List? part,
  int? partLen,
}) {
  final payload = cborEncode(
    cbArray([
      cbUint(seqNum),
      cbUint(seqLen),
      cbUint(messageLen),
      cbUint(checksum),
      cbBytes(part ?? Uint8List(partLen ?? 10)),
    ]),
  );
  final frameType = type ?? 'eth-signature';
  return 'ur:$frameType/$seqNum-$seqLen/${bytewordsEncode(payload)}';
}

List<String> genuineFrames(
  Uint8List body, [
  int parts = 3,
  String type = 'eth-signature',
]) {
  final fragmentLen = (body.length + parts - 1) ~/ parts;
  final checksum = crc32(body);
  final frames = <String>[];
  for (var i = 0; i < parts; i++) {
    final slice = Uint8List(fragmentLen);
    for (var j = i * fragmentLen;
        j < (i + 1) * fragmentLen && j < body.length;
        j++) {
      slice[j - i * fragmentLen] = body[j];
    }
    frames.add(
      hostileFrame(
        type: type,
        seqNum: i + 1,
        seqLen: parts,
        messageLen: body.length,
        checksum: checksum,
        part: slice,
      ),
    );
  }
  return frames;
}

final Uint8List body =
    Uint8List.fromList(List.generate(60, (i) => (i * 7) % 256));

/// Two frames of the same hostile stream must not bind (refused headers never bind).
void expectHeaderRefused({
  String? type,
  required int seqLen,
  required int messageLen,
  required int checksum,
  int? partLen,
}) {
  final decoder = UrDecoder();
  for (final seqNum in [1, 2]) {
    expect(
      decoder.receivePart(hostileFrame(
        type: type,
        seqNum: seqNum,
        seqLen: seqLen,
        messageLen: messageLen,
        checksum: checksum,
        partLen: partLen,
      )),
      false,
    );
  }
  expect(decoder.type, '');
  expect(decoder.partsExpected, 0);
}

void feedPasses(
  UrDecoder decoder,
  List<String> frames,
  int passes, [
  String? interleave,
]) {
  for (var p = 0; p < passes; p++) {
    for (final f in frames) {
      if (interleave != null) decoder.receivePart(interleave);
      decoder.receivePart(f);
    }
  }
}

void main() {
  group('genuine multi-part URs still assemble', () {
    test('three fragments reassemble to the exact payload', () {
      final decoder = UrDecoder();
      for (final f in genuineFrames(body)) {
        decoder.receivePart(f);
      }
      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);
    });

    test('fragments arriving out of order still assemble', () {
      final decoder = UrDecoder();
      final frames = genuineFrames(body);
      for (final f in [frames[2], frames[0], frames[1]]) {
        decoder.receivePart(f);
      }
      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);
    });

    test(
        'an unreadable sequence segment is refused, not promoted to single-part',
        () {
      final decoder = UrDecoder();
      final payload = cborEncode(cbBytes(Uint8List(10)));
      final frame =
          'ur:eth-signature/99999999999999999999999-3/${bytewordsEncode(payload)}';
      expect(
        () => decoder.receivePart(frame),
        throwsA(isA<EraSdkError>()
            .having((e) => e.message, 'message', contains('sequence'))),
      );
      expect(decoder.isComplete, false);
    });

    test(
        'a single-part UR over the ceiling is refused; at the ceiling accepted',
        () {
      final over = Ur('bytes', Uint8List(64 * 1024 + 1));
      final decoder = UrDecoder();
      expect(decoder.receivePart(over.toString()), false);
      expect(decoder.lastRefusal?.code, 'limit-exceeded');

      final at = Ur('bytes', Uint8List(64 * 1024)..fillRange(0, 64 * 1024, 1));
      final fresh = UrDecoder();
      expect(fresh.receivePart(at.toString()), true);
    });
  });

  group('one frame cannot dictate an unbounded allocation', () {
    test('a huge seqLength is refused instead of sizing a list', () {
      expectHeaderRefused(seqLen: 500000, messageLen: 100, checksum: 1);
    });

    test('a huge messageLength is refused', () {
      expectHeaderRefused(
          seqLen: 2, messageLen: 500 * 1024 * 1024, checksum: 1);
    });

    test('one byte over the message cap is refused, consistent header and all',
        () {
      // 64 KiB + 1 across 17 fragments of 4096 bytes... keep the header
      // internally consistent so ONLY the cap can be the reason.
      expectHeaderRefused(
        seqLen: 17,
        messageLen: 64 * 1024 + 1,
        checksum: 1,
        partLen: 4096,
      );
    });

    test('the sampler refuses a length the protocol cannot produce', () {
      expect(() => chooseFragmentIndexes(5000, 4096, 1), throwsRangeError);
    });

    test(
        'a seqLength of 1 cannot bind (defeats the two-fragment rule with two stickers)',
        () {
      expectHeaderRefused(seqLen: 1, messageLen: 10, checksum: 1);
    });
  });

  group('the fragment header is parsed, not cast', () {
    test('a header that is not a five-item list is refused', () {
      final payload = cborEncode(cbArray([cbUint(1), cbUint(2)]));
      final decoder = UrDecoder();
      expect(
        decoder.receivePart('ur:eth-signature/1-2/${bytewordsEncode(payload)}'),
        false,
      );
      expect(decoder.lastRefusal?.code, 'limit-exceeded');
    });

    test('a header whose items are the wrong CBOR types is refused', () {
      final payload = cborEncode(
        cbArray([
          cbBytes(Uint8List(2)),
          cbUint(2),
          cbUint(10),
          cbUint(1),
          cbBytes(Uint8List(5)),
        ]),
      );
      final decoder = UrDecoder();
      expect(
        decoder.receivePart('ur:eth-signature/1-2/${bytewordsEncode(payload)}'),
        false,
      );
    });

    test('a header disagreeing with the path sequence is refused', () {
      final frame =
          hostileFrame(seqNum: 1, seqLen: 3, messageLen: 25, checksum: 9);
      final lied = frame.replaceFirst('/1-3/', '/2-3/');
      final decoder = UrDecoder();
      expect(decoder.receivePart(lied), false);
      expect(decoder.lastRefusal?.code, 'fragment-mismatch');
    });
  });

  group('bytewords are validated, not trusted', () {
    test('an invalid byteword pair is refused instead of decoding to 0xFF', () {
      expect(
        () => bytewordsDecode('zzzzzzzzzzzz'),
        throwsA(isA<EraSdkError>()
            .having((e) => e.message, 'message', contains('byteword'))),
      );
    });

    test('a corrupted trailing CRC is refused', () {
      final good = bytewordsEncode(Uint8List.fromList([1, 2, 3]));
      final corrupted = good.substring(0, good.length - 2) +
          (good.endsWith('ae') ? 'ao' : 'ae');
      expect(() => bytewordsDecode(corrupted), throwsA(anything));
    });

    test('a body too short to hold a CRC is refused', () {
      expect(
        () => bytewordsDecode('aeae'),
        throwsA(isA<EraSdkError>().having(
            (e) => e.message, 'message', contains('checksum plus one byte'))),
      );
    });

    test('a well-formed round trip is untouched', () {
      final data = Uint8List.fromList([0, 1, 2, 253, 254, 255]);
      expect(bytewordsDecode(bytewordsEncode(data)), data);
    });
  });

  group('the assembled payload is checked against the declared checksum', () {
    test('a stream whose fragments lie about the checksum is refused', () {
      final decoder = UrDecoder();
      final frames = genuineFrames(body).map((f) => f).toList();
      // Hand-build: three fragments declaring checksum 1 (wrong).
      final fragmentLen = (body.length + 2) ~/ 3;
      for (var i = 0; i < 3; i++) {
        final slice = Uint8List(fragmentLen);
        for (var j = i * fragmentLen;
            j < (i + 1) * fragmentLen && j < body.length;
            j++) {
          slice[j - i * fragmentLen] = body[j];
        }
        decoder.receivePart(
          hostileFrame(
            seqNum: i + 1,
            seqLen: 3,
            messageLen: body.length,
            checksum: 1,
            part: slice,
          ),
        );
      }
      expect(decoder.isComplete, false);
      expect(frames.length, 3);
    });

    test('a rogue fragment costs the accumulation but NOT the binding', () {
      final decoder = UrDecoder();
      final frames = genuineFrames(body);
      final checksum = crc32(body);
      decoder.receivePart(frames[0]);
      decoder.receivePart(frames[1]);
      // Rogue: same fingerprint (type/len/msgLen/checksum/partLen), poisoned bytes.
      decoder.receivePart(
        hostileFrame(
          seqNum: 3,
          seqLen: 3,
          messageLen: body.length,
          checksum: checksum,
          part: Uint8List((body.length + 2) ~/ 3)
            ..fillRange(0, (body.length + 2) ~/ 3, 0xee),
        ),
      );
      // Accumulation was discarded on the failed join; binding survives, so a
      // clean pass assembles.
      expect(decoder.isComplete, false);
      for (final f in frames) {
        decoder.receivePart(f);
      }
      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);
    });
  });

  group('a hostile frame cannot jam the scanner (EXTRA-08)', () {
    test('a single static frame holds the binding only provisionally', () {
      final decoder = UrDecoder();
      decoder.receivePart(
        hostileFrame(
          type: 'crypto-psbt',
          seqNum: 1,
          seqLen: 3,
          messageLen: 30,
          checksum: 123,
        ),
      );
      feedPasses(decoder, genuineFrames(body), 16);
      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);
    });

    test('a static frame of the EXPECTED type is given up too', () {
      final decoder = UrDecoder();
      decoder.receivePart(
        hostileFrame(
            seqNum: 1, seqLen: 2, messageLen: 40, checksum: 12345, partLen: 20),
      );
      feedPasses(decoder, genuineFrames(body), 16);
      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);
    });

    test('the same frame shown over and over cannot confirm itself', () {
      final decoder = UrDecoder();
      final hostile = hostileFrame(
        seqNum: 1,
        seqLen: 2,
        messageLen: 40,
        checksum: 999,
        partLen: 20,
      );
      for (var i = 0; i < 50; i++) {
        decoder.receivePart(hostile);
      }
      feedPasses(decoder, genuineFrames(body), 16);
      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);
    });

    test(
        'the device head start is decisive: two stickers cannot take a held binding',
        () {
      final hostileBody =
          Uint8List.fromList(List.generate(40, (i) => 0xee - (i % 17)));
      final stickers = genuineFrames(hostileBody, 2);
      final genuine = genuineFrames(body, 6);

      final decoder = UrDecoder();
      decoder
          .receivePart(genuine[0]); // the device lands exactly one frame first
      expect(decoder.type, 'eth-signature');

      for (final s in stickers) {
        decoder.receivePart(s);
        decoder.receivePart(s);
      }
      for (var i = 1; i < genuine.length; i++) {
        decoder.receivePart(genuine[i]);
      }

      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);
    });

    test('nor can an animated attacker at a rate advantage', () {
      final hostileBody =
          Uint8List.fromList(List.generate(60, (i) => 0xc0 + (i % 31)));
      final hostile = genuineFrames(hostileBody, 3);
      final genuine = genuineFrames(body, 6);

      final decoder = UrDecoder();
      decoder.receivePart(genuine[0]);
      for (var round = 1;
          round < genuine.length && !decoder.isComplete;
          round++) {
        for (var i = 0; i < 4; i++) {
          decoder.receivePart(hostile[i % hostile.length]);
        }
        decoder.receivePart(genuine[round]);
      }
      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);
    });

    test(
        'a static hostile frame interleaved with every genuine frame still loses',
        () {
      final decoder = UrDecoder();
      final hostile = hostileFrame(
        seqNum: 1,
        seqLen: 2,
        messageLen: 40,
        checksum: 999,
        partLen: 20,
      );
      feedPasses(decoder, genuineFrames(body), 16, hostile);
      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);
    });

    test(
        'a single-part UR cannot walk over a confirmed assembly, but is accepted fresh',
        () {
      final decoder = UrDecoder();
      final genuine = genuineFrames(body, 4);
      decoder.receivePart(genuine[0]);
      decoder.receivePart(genuine[1]);
      expect(decoder.partsReceived, greaterThan(1));

      final hostileSingle =
          Ur('eth-signature', Uint8List(42)..fillRange(0, 42, 0xee)).toString();
      expect(decoder.receivePart(hostileSingle), false);
      expect(decoder.lastRefusal?.code, 'fragment-mismatch');
      expect(decoder.isComplete, false);

      decoder.receivePart(genuine[2]);
      decoder.receivePart(genuine[3]);
      expect(decoder.isComplete, true);
      expect(decoder.result().cbor, body);

      final fresh = UrDecoder();
      expect(fresh.receivePart(hostileSingle), true);
    });
  });
}
