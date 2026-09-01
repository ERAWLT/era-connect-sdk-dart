import '../core/errors.dart';
import '../ur/decoder.dart';
import '../ur/ur.dart';

/// Options for [UrScanner].
class UrScannerOptions {
  const UrScannerOptions({this.expectedTypes});

  /// Pin: frames of any other UR type are rejected BEFORE the fountain
  /// decoder sees them. The decoder commits to a stream once one binds, so a
  /// frame that gets that far has a say in what the rest of the session may
  /// look like — pinning is the cheap half of the hostile-QR cure (the
  /// decoder's two-fragment binding rule is the other half).
  final List<String>? expectedTypes;
}

/// Why a scanned frame was turned away.
class ScanRejection {
  const ScanRejection({
    required this.code,
    required this.message,
    required this.repeated,
  });

  /// Stable machine-readable code (see [EraSdkError.code]).
  final String code;

  /// Human-readable explanation. Not stable API.
  final String message;

  /// Consecutive occurrences of this same rejection. A static hostile or
  /// malformed QR produces the identical rejection at camera framerate; this
  /// counter lets a UI or a log show it once instead of ~10 times per second.
  final int repeated;
}

/// One outcome of feeding a frame to [UrScanner.receivePart].
sealed class ScanFeedResult {
  const ScanFeedResult();
}

/// The frame was consumed; the scan is not complete yet.
final class ScanProgress extends ScanFeedResult {
  const ScanProgress({
    required this.progress,
    required this.framesReceived,
    required this.framesExpected,
  });

  /// Assembly progress in `[0, 1]`.
  final double progress;

  /// Frames received so far.
  final int framesReceived;

  /// Frames the bound stream declares.
  final int framesExpected;
}

/// A frame already seen this session (camera framerate re-reads).
final class ScanDuplicate extends ScanFeedResult {
  const ScanDuplicate();
}

/// The frame was turned away; see [rejection].
final class ScanRejected extends ScanFeedResult {
  const ScanRejected(this.rejection);

  /// Why the frame was turned away.
  final ScanRejection rejection;
}

/// The scan is complete; [ur] is the assembled UR.
final class ScanComplete extends ScanFeedResult {
  const ScanComplete(this.ur);

  /// The assembled UR.
  final Ur ur;
}

/// Accumulates camera frames into a UR. Synchronous and non-throwing on the
/// feed path (safe to call from camera callbacks); malformed frames come back
/// as typed rejections, never exceptions.
class UrScanner {
  UrScanner([UrScannerOptions? options])
      : _expectedTypes = switch (options?.expectedTypes) {
          null => null,
          final types => Set<String>.of(types),
        };

  final UrDecoder _decoder = UrDecoder();
  final Set<String>? _expectedTypes;

  /// Distinct frames remembered for dedup. Attacker-suppliable strings, so
  /// capped.
  static const int _maxRememberedFrames = 4096;

  final Set<String> _seen = <String>{};
  ScanRejection? _rejection;

  /// Whether the UR is fully assembled.
  bool get isComplete => _decoder.isComplete;

  /// Assembly progress in `[0, 1]`.
  double get progress => _decoder.progress;

  /// The UR type of the bound stream, or null until one binds.
  String? get urType => _decoder.type == '' ? null : _decoder.type;

  /// Frames received so far.
  int get framesReceived => _decoder.partsReceived;

  /// Frames the bound stream declares.
  int get framesExpected => _decoder.partsExpected;

  /// The most recent rejection, or null.
  ScanRejection? get lastRejection => _rejection;

  /// Feed one scanned frame.
  ScanFeedResult receivePart(String frame) {
    if (_decoder.isComplete) {
      return ScanComplete(_decoder.result());
    }
    if (_seen.contains(frame)) return const ScanDuplicate();

    // Type pin BEFORE any decoding work.
    final type = urTypeOf(frame);
    if (type == null) {
      return _reject('not-a-ur', 'not a UR frame');
    }
    final expected = _expectedTypes;
    if (expected != null && !expected.contains(type)) {
      // The type is attacker-sized (the grammar allows an unbounded letter
      // run) — truncate before it reaches a message or a log.
      final shown = type.length > 32 ? '${type.substring(0, 32)}…' : type;
      return _reject(
        'wrong-ur-type',
        'ignored a "$shown" frame; expected ${expected.join(' or ')}',
      );
    }

    // Remembered only now: junk that never reached the decoder must not be
    // able to fill the dedup budget.
    if (_seen.length < _maxRememberedFrames) _seen.add(frame);

    bool complete;
    try {
      complete = _decoder.receivePart(frame);
    } on EraSdkError catch (e) {
      // Only the code, never the frame contents — attacker-sized, and on the
      // linking path a wallet's own bytes.
      return _reject(e.code, 'unreadable UR frame');
    } catch (_) {
      return _reject('not-a-ur', 'unreadable UR frame');
    }
    final refusal = _decoder.lastRefusal;
    if (refusal != null) {
      return _reject(refusal.code, refusal.message);
    }
    if (complete) {
      _rejection = null;
      return ScanComplete(_decoder.result());
    }
    return ScanProgress(
      progress: _decoder.progress,
      framesReceived: _decoder.partsReceived,
      framesExpected: _decoder.partsExpected,
    );
  }

  /// The assembled UR. Throws `incomplete-scan` until done.
  Ur result() => _decoder.result();

  ScanFeedResult _reject(String code, String message) {
    final previous = _rejection;
    final next =
        previous != null && previous.code == code && previous.message == message
            ? ScanRejection(
                code: code, message: message, repeated: previous.repeated + 1)
            : ScanRejection(code: code, message: message, repeated: 1);
    _rejection = next;
    return ScanRejected(next);
  }
}

/// A scanner whose completed UR parses into a typed result (a chain
/// signature).
class TypedUrScanner<TResult> extends UrScanner {
  TypedUrScanner(UrScannerOptions super.options, this._parseResult);

  final TResult Function(Ur ur) _parseResult;

  /// Assemble + parse + validate (UR type, request-id echo) in one call.
  TResult parse() => _parseResult(result());
}
