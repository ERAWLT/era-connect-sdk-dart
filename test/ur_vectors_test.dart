import 'package:era_connect/src/core/errors.dart';
import 'dart:typed_data';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/ur/decoder.dart';
import 'package:era_connect/src/ur/encoder.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:test/test.dart';

/// Canonical BCR-2020-005 vectors. The 20-frame sequence pins the whole wire
/// stack at once: sha256 seeding, Xoshiro256**, the alias-method degree
/// chooser, the draw-without-replacement shuffle, XOR mixing, bytewords and
/// CRC32. A single differing character means a device cannot decode us.

const String singlePartCbor =
    '5832916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccba4'
    '4f7f04f2de44f42d84c374a0e149136f25b018';
const String singlePartUr =
    'ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfn'
    'sboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch';

const String multiPartCbor =
    '590100916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccb'
    'a44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a8cde6d0e2e'
    'c43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f965e25ee29039fdf8c'
    'a74f1c769fc07eb7ebaec46e0695aea6cbd60b3ec4bbff1b9ffe8a9e7240129377'
    'b9d3711ed38d412fbb4442256f1e6f595e0fc57fed451fb0a0101fb76b1fb1e1b8'
    '8cfdfdaa946294a47de8fff173f021c0e6f65b05c0a494e50791270a0050a73ae6'
    '9b6725505a2ec8a5791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb824'
    '8b717c22951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d';

const List<String> multiPartFrames = [
  'ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh',
  'ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz',
  'ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol',
  'ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas',
  'ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf',
  'ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp',
  'ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy',
  'ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk',
  'ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny',
  'ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs',
  'ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk',
  'ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs',
  'ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd',
  'ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt',
  'ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt',
  'ur:bytes/16-9/lpbeascfadaxcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmukirlrsbtamjtpd',
  'ur:bytes/17-9/lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnytyisincxmhtbceaykolduortotiaiaiafhiaoyce',
  'ur:bytes/18-9/lpbgascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy',
  'ur:bytes/19-9/lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbncxgslgftvtsrjtksplcpeo',
  'ur:bytes/20-9/lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrtrdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot',
];

void main() {
  _urGrammarRegression();
  group('BCR-2020-005 reference vectors', () {
    test('decodes and re-encodes the single-part vector', () {
      final decoder = UrDecoder();
      expect(decoder.receivePart(singlePartUr), true);
      final ur = decoder.result();
      expect(ur.type, 'bytes');
      expect(bytesToHex(ur.cbor), singlePartCbor);
      expect(ur.toWireString(), singlePartUr.toUpperCase());
    });

    test('assembles the multi-part vector from its first 9 frames', () {
      final decoder = UrDecoder();
      var complete = false;
      for (final frame in multiPartFrames) {
        complete = decoder.receivePart(frame);
        if (complete) break;
      }
      expect(complete, true);
      expect(bytesToHex(decoder.result().cbor), multiPartCbor);
    });

    test(
        're-emits the exact 20 canonical frames (fountain PRNG pinned bit-for-bit)',
        () {
      final encoder =
          UrFountainEncoder(Ur('bytes', hexToBytes(multiPartCbor)), 30, 10);
      expect(encoder.fragmentCount, 9);
      for (final frame in multiPartFrames) {
        expect(encoder.nextPart().toLowerCase(), frame);
      }
    });

    test(
        'assembles out of order and with duplicates/losses (fountain property)',
        () {
      final decoder = UrDecoder();
      // Drop the first four source frames entirely; feed the tail + fountain
      // frames, shuffled deterministically, with duplicates.
      final frames = [
        ...multiPartFrames.sublist(4),
        ...multiPartFrames.sublist(9),
      ].reversed.toList();
      var complete = false;
      for (final frame in frames) {
        complete = decoder.receivePart(frame) || complete;
      }
      expect(complete, true);
      expect(bytesToHex(decoder.result().cbor), multiPartCbor);
    });
  });
}

void _urGrammarRegression() {
  group('UR type grammar', () {
    test('a type containing a digit round-trips', () {
      // The constructor has always accepted [a-z][a-z0-9-]*, while the parser
      // accepted only [a-z-]+ — so a digit-bearing type could be built and
      // then refused as not-a-ur on the way back in. No registry type in use
      // today carries a digit; this pins the grammar for the next one that does.
      final ur = Ur('sui2-sign-request', Uint8List.fromList([0xa0]));
      final parsed = parseUrString(ur.toString());
      expect(parsed.type, 'sui2-sign-request');
      expect(parsed.payload, ur.cbor);
    });

    test('a type starting with a digit is still refused', () {
      expect(() => parseUrString('ur:2sui/oyaa'), throwsA(isA<EraSdkError>()));
    });
  });
}
