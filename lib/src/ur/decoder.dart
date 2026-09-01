import 'dart:typed_data';

import '../core/errors.dart';
import 'crc32.dart';
import 'fragment.dart';
import 'limits.dart';
import 'ur.dart';

/// Why the last frame was turned away by validation (null = used or buffered).
class UrRefusal {
  const UrRefusal({required this.code, required this.message});

  /// Stable machine-readable code (same closed set as [EraSdkError.code]).
  final String code;

  /// Human-readable explanation. Not stable API.
  final String message;
}

/// BC-UR fountain decoder with hostile-input stream binding.
///
/// The naive decoder pins its expectations to the FIRST fragment it ever sees
/// and drops everything that disagrees. That is right while the only thing in
/// front of the camera is the device — and it is exactly how one hostile QR (a
/// sticker, a poster, a second screen) used to end the whole session: it bound
/// first, and the device's real answer could never assemble.
///
/// The cure is to make binding harder, not reversible:
///
///  - a stream binds only PROVISIONALLY on its first fragment, and is
///    CONFIRMED only when a second, distinct fragment of the same stream
///    arrives (same fingerprint, different seqNum). A static QR is one
///    fragment forever and can never confirm itself;
///  - a provisional binding is dropped after 32 non-matching frames — a
///    genuine stream confirms on its very next frame, so this cannot be aimed
///    at one;
///  - a CONFIRMED binding is never evicted. Any recovery path is an eviction
///    path, so there is none. A rogue fragment that poisons the XOR costs the
///    accumulated progress (rescan one animation pass), never the binding;
///  - a single-part UR cannot complete the scan while a confirmed multi-part
///    assembly holds received fragments.
///
/// What this does not defend against is an attacker who owns the camera
/// outright — if the only well-formed UR in view is theirs, it assembles. The
/// layers above (type pinning per request, request-id echo, verification
/// helpers) are what refuse that.
class UrDecoder {
  String _boundType = '';
  int _seqLength = 0;
  int _expectedMessageLength = 0;
  int _expectedChecksum = 0;
  int _expectedFragmentLength = 0;
  bool _confirmed = false;
  int _framesSinceBinding = 0;
  int _bindingSeqNum = 0;

  final List<int> _expectedIndexes = [];
  final List<int> _receivedIndexes = [];
  List<Fragment> _mixedParts = [];
  final List<Fragment> _queuedParts = [];
  final List<Fragment> _simpleParts = [];

  Uint8List? _payload;
  String _completedType = '';

  /// How long a provisional binding may stand without a second fragment of its own.
  static const int _framesBeforeDroppingProvisional = 32;

  /// Why the last frame was refused (null = used or buffered).
  UrRefusal? lastRefusal;

  /// Whether the UR is fully assembled.
  bool get isComplete => _payload != null;

  /// The type of the bound (or completed) stream; empty until one binds.
  String get type => _payload != null ? _completedType : _boundType;

  /// How many source fragments the bound stream declares.
  int get partsExpected => _expectedIndexes.length;

  /// How many distinct source fragments have been recovered.
  int get partsReceived => _receivedIndexes.length;

  /// Assembly progress in [0, 1].
  double get progress {
    if (isComplete) return 1;
    if (_expectedIndexes.isEmpty) return 0;
    return _receivedIndexes.length / _expectedIndexes.length;
  }

  /// The assembled UR. Throws until [isComplete].
  Ur result() {
    final payload = _payload;
    if (payload == null) {
      throw EraSdkError('incomplete-scan', 'UR not fully assembled yet');
    }
    return Ur(_completedType, payload);
  }

  /// Feed one scanned frame. Returns true once the UR is fully assembled.
  ///
  /// Throws [EraSdkError] for frames that are not parseable URs at all
  /// (`not-a-ur`, `malformed-bytewords`, `checksum-mismatch`,
  /// `malformed-sequence`); refusals of parseable frames set [lastRefusal]
  /// and return false.
  bool receivePart(String text) {
    if (isComplete) return false;
    lastRefusal = null;

    final parsed = parseUrString(text);

    final seq = parsed.seq;
    if (seq == null) {
      // Single-part branch. It never reaches the fragment-header bounds, so
      // the ceiling is enforced here too — otherwise this is the one shape
      // that can hand an unbounded payload to the layers above.
      if (parsed.payload.isEmpty ||
          parsed.payload.length > UrLimits.maxMessageBytes) {
        lastRefusal = UrRefusal(
          code: 'limit-exceeded',
          message: 'single-part payload of ${parsed.payload.length} bytes '
              'is outside 1..${UrLimits.maxMessageBytes}',
        );
        return false;
      }
      // A single-part frame must not walk over an assembly under way: every
      // genuine device reply is single-part, so the veto is deliberately
      // narrow — only a CONFIRMED multi-part stream with collected fragments.
      if (_confirmed && _receivedIndexes.isNotEmpty) {
        lastRefusal = UrRefusal(
          code: 'fragment-mismatch',
          message: 'a single-part UR arrived while a "$_boundType" assembly '
              'was under way',
        );
        return false;
      }
      _completedType = parsed.type;
      _payload = parsed.payload;
      return true;
    }

    // Validated BEFORE construction: index derivation is quadratic in the
    // header's seqLength, so an unchecked header has already cost whatever
    // the attacker asked for by the time anyone could reject it.
    final fragment = tryParseFragment(parsed.type, parsed.payload);
    if (fragment == null) {
      lastRefusal = const UrRefusal(
        code: 'limit-exceeded',
        message: 'fragment header is malformed or outside the UrLimits bounds',
      );
      return false;
    }
    if (fragment.seqNum != seq.num || fragment.seqLength != seq.length) {
      lastRefusal = const UrRefusal(
        code: 'fragment-mismatch',
        message: 'fragment header disagrees with the ur: path sequence',
      );
      return false;
    }
    if (!_checkBinding(fragment)) return false;

    _queuedParts.add(fragment);
    while (!isComplete && _queuedParts.isNotEmpty) {
      _processQueuedItem();
    }
    return isComplete;
  }

  String _fingerprintOf(
    String type,
    int seqLength,
    int messageLength,
    int checksum,
    int fragmentLength,
  ) {
    return '$type|$seqLength|$messageLength|$checksum|$fragmentLength';
  }

  /// Decide whether the fragment belongs to the bound stream; bind/confirm/drop per the rules above.
  bool _checkBinding(Fragment fragment) {
    final fingerprint = _fingerprintOf(
      fragment.type,
      fragment.seqLength,
      fragment.messageLength,
      fragment.checksum,
      fragment.part.length,
    );

    if (_boundType != '') {
      final bound = _fingerprintOf(
        _boundType,
        _seqLength,
        _expectedMessageLength,
        _expectedChecksum,
        _expectedFragmentLength,
      );
      if (fingerprint == bound) {
        // A second DISTINCT fragment is the proof; the same frame held in
        // front of the camera cannot confirm itself.
        if (!_confirmed && fragment.seqNum != _bindingSeqNum) _confirmed = true;
        return true;
      }
      if (_confirmed) {
        lastRefusal = const UrRefusal(
          code: 'fragment-mismatch',
          message:
              'fragment belongs to a different stream than the confirmed assembly',
        );
        return false;
      }
      _framesSinceBinding += 1;
      if (_framesSinceBinding < _framesBeforeDroppingProvisional) {
        lastRefusal = const UrRefusal(
          code: 'fragment-mismatch',
          message:
              'fragment belongs to a different stream than the provisional binding',
        );
        return false;
      }
      _discardBinding();
    }

    _boundType = fragment.type;
    _seqLength = fragment.seqLength;
    _expectedMessageLength = fragment.messageLength;
    _expectedChecksum = fragment.checksum;
    _expectedFragmentLength = fragment.part.length;
    _bindingSeqNum = fragment.seqNum;
    _confirmed = false;
    _framesSinceBinding = 0;

    _expectedIndexes.clear();
    for (var i = 0; i < fragment.seqLength; i++) {
      _expectedIndexes.add(i);
    }
    return true;
  }

  /// Drop a binding that never proved itself (provisional only).
  void _discardBinding() {
    _boundType = '';
    _seqLength = 0;
    _expectedMessageLength = 0;
    _expectedChecksum = 0;
    _expectedFragmentLength = 0;
    _confirmed = false;
    _framesSinceBinding = 0;
    _bindingSeqNum = 0;
    _expectedIndexes.clear();
    _receivedIndexes.clear();
    _mixedParts = [];
    _queuedParts.clear();
    _simpleParts.clear();
  }

  /// Throw away the accumulation, KEEPING the binding.
  ///
  /// Reached when the reassembled payload does not hash to the stream's own
  /// declared checksum — a rogue fragment that copied the visible header and
  /// poisoned the XOR. Unbinding here would hand back the eviction primitive
  /// the binding rule denies, so only the collected fragments are discarded:
  /// one pass of the animation for the genuine sender, one fragment per pass
  /// for the attacker, forever.
  void _discardAccumulation() {
    _expectedIndexes.clear();
    if (_seqLength > 0) {
      for (var i = 0; i < _seqLength; i++) {
        _expectedIndexes.add(i);
      }
    }
    _receivedIndexes.clear();
    _mixedParts = [];
    _queuedParts.clear();
    _simpleParts.clear();
  }

  void _processQueuedItem() {
    if (_queuedParts.isEmpty) return;
    final part = _queuedParts.removeAt(0);
    if (isSimple(part)) {
      _processSimplePart(part);
    } else {
      _processMixedPart(part);
    }
  }

  void _processSimplePart(Fragment fragment) {
    final fragmentIndex = fragment.indexes[0];
    if (_receivedIndexes.contains(fragmentIndex)) return;

    _simpleParts.add(fragment);
    _receivedIndexes.add(fragmentIndex);

    if (_sameMembers(_receivedIndexes, _expectedIndexes)) {
      final sorted = [..._simpleParts]
        ..sort((a, b) => a.indexes[0] - b.indexes[0]);
      var joinedLength = 0;
      for (final p in sorted) {
        joinedLength += p.part.length;
      }
      final joined = Uint8List(joinedLength);
      var offset = 0;
      for (final p in sorted) {
        joined.setAll(offset, p.part);
        offset += p.part.length;
      }
      if (joined.length < _expectedMessageLength) {
        _discardAccumulation();
        return;
      }
      final candidate = joined.sublist(0, _expectedMessageLength);
      // Between fragments the checksum only proves they agree with each
      // other; against the assembled message it proves the message is the one
      // the stream was describing. This is the single check that catches a
      // rogue fragment XOR'd into a genuine stream.
      if (crc32(candidate) != _expectedChecksum) {
        _discardAccumulation();
        return;
      }
      _completedType = _boundType;
      _payload = candidate;
    } else {
      _reduceMixedBy(fragment);
    }
  }

  void _processMixedPart(Fragment fragment) {
    if (_mixedParts.any((e) => _sameMembers(e.indexes, fragment.indexes))) {
      return;
    }
    // Distinct mixed parts are attacker-suppliable one per frame and each is
    // compared against every other on the next reduction. A real stream never
    // holds more mixed parts than it has source fragments. Backstop only —
    // the reduction's collapse rate keeps real lists tiny.
    if (_mixedParts.length >= UrLimits.maxFragmentCount) return;

    var simple = fragment;
    for (final s in _simpleParts) {
      simple = _reducePartByPart(simple, s);
    }

    var part = simple;
    for (final m in _mixedParts) {
      part = _reducePartByPart(part, m);
    }

    if (isSimple(part)) {
      _queuedParts.add(part);
    } else {
      _reduceMixedBy(part);
      _mixedParts.add(part);
    }
  }

  void _reduceMixedBy(Fragment fragment) {
    final newMixed = <Fragment>[];
    for (final item in _mixedParts) {
      final reduced = _reducePartByPart(item, fragment);
      if (isSimple(reduced)) {
        _queuedParts.add(item);
      } else {
        newMixed.add(reduced);
      }
    }
    _mixedParts = newMixed;
  }

  Fragment _reducePartByPart(Fragment a, Fragment b) {
    if (!b.indexes.every(a.indexes.contains)) return a;

    final newIndexes = a.indexes.where((e) => !b.indexes.contains(e)).toList();
    final newLength =
        a.part.length > b.part.length ? a.part.length : b.part.length;
    final newPart = Uint8List(newLength);
    for (var i = 0; i < newLength; i++) {
      newPart[i] = (i < a.part.length ? a.part[i] : 0) ^
          (i < b.part.length ? b.part[i] : 0);
    }
    return Fragment(
      type: a.type,
      seqNum: a.seqNum,
      seqLength: a.seqLength,
      messageLength: _expectedMessageLength,
      checksum: crc32(a.part),
      part: newPart,
      indexes: newIndexes,
    );
  }
}

/// Order-insensitive membership equality (mirrors the reference `arraysEqual`).
bool _sameMembers(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  return a.every(b.contains);
}
