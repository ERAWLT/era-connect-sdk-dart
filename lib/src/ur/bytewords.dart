import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';
import 'crc32.dart';

const String _byteWords =
    'ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabias'
    'bluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcost'
    'cruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdull'
    'dutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfish'
    'fizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglow'
    'goodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhope'
    'hornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowl'
    'judojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamb'
    'lavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmany'
    'mathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnote'
    'numbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolpose'
    'puffpumapurrquadquizraceramprealredorichroadrockroofrubyruinruns'
    'rustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotask'
    'taxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuser'
    'vastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebs'
    'whatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom';

const int _dim = 26;
const int _a = 0x61; // 'a'

/// Lookup keyed on (first letter, last letter); -1 = not a byteword.
final Int16List _lookup = () {
  final table = Int16List(_dim * _dim)..fillRange(0, _dim * _dim, -1);
  for (var i = 0; i < 256; i++) {
    final x = _byteWords.codeUnitAt(i * 4) - _a;
    final y = _byteWords.codeUnitAt(i * 4 + 3) - _a;
    table[y * _dim + x] = i;
  }
  return table;
}();

/// Bytewords codec (minimal style only), per BCR-2020-012.
///
/// Decode hardening (each of these used to turn malformed input into plausible
/// bytes in naive implementations):
///  - a letter pair that is not a byteword is a refusal, never a fallback byte;
///  - a body shorter than the four CRC words plus one byte is a refusal;
///  - the trailing CRC32 (big-endian) is verified and stripped.
///
/// The checksum is unkeyed and is not an authentication control — whoever
/// prints the QR prints the CRC too. What it buys is that garbage stops being
/// accepted as data, which frame dedup and reassembly downstream both assume.
String bytewordsEncode(Uint8List data) {
  final buf = concatBytes([data, u32be(crc32(data))]);
  final out = StringBuffer();
  for (final byte in buf) {
    out
      ..writeCharCode(_byteWords.codeUnitAt(byte * 4))
      ..writeCharCode(_byteWords.codeUnitAt(byte * 4 + 3));
  }
  return out.toString();
}

/// Decode a minimal-style bytewords body, verifying and stripping the
/// trailing CRC32. See [bytewordsEncode] for the hardening rules.
Uint8List bytewordsDecode(String body) {
  if (body.length % 2 != 0) {
    throw EraSdkError(
        'malformed-bytewords', 'bytewords: odd number of letters');
  }
  final words = Uint8List(body.length ~/ 2);
  for (var i = 0; i < words.length; i++) {
    final x = body.codeUnitAt(i * 2) - _a;
    final y = body.codeUnitAt(i * 2 + 1) - _a;
    if (x < 0 || x >= _dim || y < 0 || y >= _dim) {
      throw EraSdkError(
          'malformed-bytewords', 'bytewords: letter out of range');
    }
    final value = _lookup[y * _dim + x];
    if (value < 0) {
      throw EraSdkError('malformed-bytewords', 'bytewords: not a byteword');
    }
    words[i] = value;
  }
  if (words.length < 5) {
    throw EraSdkError(
      'malformed-bytewords',
      'bytewords: shorter than a checksum plus one byte',
    );
  }
  final bodyBytes = words.sublist(0, words.length - 4);
  final declared = ((words[words.length - 4] << 24) |
          (words[words.length - 3] << 16) |
          (words[words.length - 2] << 8) |
          words[words.length - 1]) &
      0xffffffff;
  if (crc32(bodyBytes) != declared) {
    throw EraSdkError('checksum-mismatch', 'bytewords: checksum mismatch');
  }
  return bodyBytes;
}
