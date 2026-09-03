import 'dart:typed_data';

import '../core/errors.dart';
import 'bytewords.dart';

final RegExp _urTypePattern = RegExp(r'^[a-z][a-z0-9-]*$');

/// An immutable Uniform Resource: a registry type string plus its CBOR payload.
class Ur {
  Ur(this.type, this.cbor) {
    if (!_urTypePattern.hasMatch(type)) {
      throw EraSdkError('invalid-props', '"$type" is not a valid UR type');
    }
  }

  /// The registry type (`bytes`, `eth-sign-request`, ...).
  final String type;

  /// The CBOR payload.
  final Uint8List cbor;

  /// The whole UR as one single-part `ur:` string, lowercase (the loggable form).
  @override
  String toString() => 'ur:$type/${bytewordsEncode(cbor)}';

  /// The single-part wire form, uppercase (QR alphanumeric mode).
  String toWireString() => toString().toUpperCase();
}

final RegExp _urGrammar =
    RegExp(r'^ur:([a-z][a-z0-9-]*)(/(\d+-\d+))?/([a-z]+)$');

/// The `seqNum-seqLength` segment of a multi-part `ur:` path.
class UrSequence {
  const UrSequence({required this.num, required this.length});

  /// The 1-based sequence number.
  final int num;

  /// The declared number of source fragments.
  final int length;
}

/// One parsed `ur:` string: (type, sequence, decoded payload).
class ParsedUrParts {
  const ParsedUrParts({
    required this.type,
    required this.seq,
    required this.payload,
  });

  /// The registry type from the path.
  final String type;

  /// null for a single-part UR.
  final UrSequence? seq;

  /// The bytewords-decoded body (CRC verified and stripped).
  final Uint8List payload;
}

/// The largest sequence number/length a `ur:` path may carry — the same
/// 2^53-1 safe-integer bound (web builds cannot represent more).
const int _maxSafeInteger = 9007199254740991;

/// Parse one `ur:` string into (type, sequence, decoded payload).
///
/// An ABSENT sequence segment means a single-part UR. A segment that is present
/// but unreadable (a number too wide, `0-0`) is a malformed frame and throws —
/// promoting it to "single-part" would send a broken fragment down the branch
/// that completes a scan.
ParsedUrParts parseUrString(String text) {
  final lower = text.toLowerCase();
  final match = _urGrammar.firstMatch(lower);
  if (match == null) {
    throw EraSdkError('not-a-ur', 'not a ur: string');
  }
  final type = match.group(1)!;
  final seqSegment = match.group(3);
  final payload = bytewordsDecode(match.group(4)!);

  if (seqSegment == null) {
    return ParsedUrParts(type: type, seq: null, payload: payload);
  }
  final dash = seqSegment.indexOf('-');
  final num = int.tryParse(seqSegment.substring(0, dash));
  final length = int.tryParse(seqSegment.substring(dash + 1));
  if (num == null ||
      length == null ||
      num > _maxSafeInteger ||
      length > _maxSafeInteger ||
      num <= 0 ||
      length <= 0) {
    throw EraSdkError('malformed-sequence', 'unreadable ur sequence segment');
  }
  return ParsedUrParts(
    type: type,
    seq: UrSequence(num: num, length: length),
    payload: payload,
  );
}

/// The `ur:<type>/` prefix of a frame, without decoding the bytewords body.
final RegExp _typePrefix = RegExp(r'^ur:([a-z][a-z0-9-]*)/');

/// The UR type of [text], or null when it does not start `ur:<type>/`.
String? urTypeOf(String text) {
  final match = _typePrefix.firstMatch(text.toLowerCase());
  return match?.group(1);
}
