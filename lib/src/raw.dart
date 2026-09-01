import 'dart:typed_data';

import 'chains/shared.dart';
import 'qr/animated_ur.dart';
import 'ur/ur.dart';

/// Escape hatch for UR types this SDK has no dedicated module for (future
/// chains, custom registry items). You bring the CBOR; the SDK brings the UR
/// plumbing, fountain frames and the hardened scanner
/// (`EraConnect.scanner(expectedTypes: ...)`).
class RawModule {
  RawModule(ChainContext context) : _context = context;

  final ChainContext _context;

  /// Wrap raw CBOR bytes in a UR of the given registry type.
  Ur ur(String type, Uint8List cbor) => Ur(type, cbor);

  /// Parse a single-part `ur:` string into a Ur.
  Ur parse(String text) => toUr(text);

  /// Fragment + animate any UR.
  AnimatedUr animate(Ur ur, [AnimatedUrOptions? options]) {
    return AnimatedUr(
      ur,
      AnimatedUrOptions(
        maxFragmentLength:
            options?.maxFragmentLength ?? _context.maxFragmentLength,
      ),
    );
  }
}
