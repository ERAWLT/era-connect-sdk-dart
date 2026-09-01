import 'dart:typed_data';

import '../core/errors.dart';
import 'bytewords.dart';
import 'crc32.dart';
import 'fragment.dart';
import 'sampler.dart';
import 'ur.dart';

/// BC-UR fountain encoder.
///
/// Partitioning picks the LARGEST fragment length `<= maxFragmentLength` that
/// evenly covers the payload (`ceil(len/count)` for the smallest sufficient
/// `count`), and the last fragment is zero-padded to the common length — both
/// exactly as the reference encoders do, because the receiving side's header
/// consistency check assumes this relation.
///
/// A payload that fits one fragment is emitted as the plain single-part
/// `ur:<type>/<body>` form on every call — never as a `1-1` sequence.
class UrFountainEncoder {
  factory UrFountainEncoder(
    Ur ur, [
    int maxFragmentLength = 180,
    int minFragmentLength = 10,
  ]) {
    if (ur.cbor.isEmpty) {
      throw EraSdkError('invalid-props', 'cannot encode an empty UR payload');
    }
    if (maxFragmentLength < minFragmentLength ||
        maxFragmentLength <= 0 ||
        minFragmentLength <= 0) {
      throw EraSdkError('invalid-props', 'invalid fragment length bounds');
    }
    return UrFountainEncoder._(
      ur,
      crc32(ur.cbor),
      _partition(ur.cbor, maxFragmentLength, minFragmentLength),
    );
  }

  UrFountainEncoder._(this.ur, this._checksum, this._fragments);

  /// The UR being emitted.
  final Ur ur;

  final List<Uint8List> _fragments;
  final int _checksum;
  int _seqNum = 0;

  /// Whether the payload fits one fragment (emitted as a plain single-part UR).
  bool get isSinglePart => _fragments.length <= 1;

  /// How many source fragments the payload was split into (1 for single-part).
  int get fragmentCount => _fragments.length;

  /// Next wire frame, uppercase. Single-part payloads return the same string every call.
  String nextPart() {
    if (isSinglePart) return ur.toWireString();

    _seqNum += 1;
    final indexes =
        chooseFragmentIndexes(_seqNum, _fragments.length, _checksum);
    final first = _fragments[0];
    final mixed = Uint8List(first.length);
    for (final index in indexes) {
      final fragment = _fragments[index];
      for (var i = 0; i < mixed.length; i++) {
        mixed[i] = mixed[i] ^ (i < fragment.length ? fragment[i] : 0);
      }
    }
    final body = fragmentCbor(
      _seqNum,
      _fragments.length,
      ur.cbor.length,
      _checksum,
      mixed,
    );
    return 'ur:${ur.type}/$_seqNum-${_fragments.length}/${bytewordsEncode(body)}'
        .toUpperCase();
  }
}

/// Largest `ceil(len/count) <= maxLength` split, last fragment zero-padded.
List<Uint8List> _partition(Uint8List payload, int maxLength, int minLength) {
  final maxCount = (payload.length + minLength - 1) ~/ minLength;
  var fragmentLength = payload.length;
  for (var count = 1; count <= maxCount; count++) {
    fragmentLength = (payload.length + count - 1) ~/ count;
    if (fragmentLength <= maxLength) break;
  }
  final fragments = <Uint8List>[];
  for (var offset = 0; offset < payload.length; offset += fragmentLength) {
    final end = offset + fragmentLength;
    final slice =
        payload.sublist(offset, end < payload.length ? end : payload.length);
    if (slice.length < fragmentLength) {
      final padded = Uint8List(fragmentLength)..setAll(0, slice);
      fragments.add(padded);
    } else {
      fragments.add(slice);
    }
  }
  return fragments;
}
