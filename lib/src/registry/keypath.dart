import '../cbor/model.dart';
import '../core/errors.dart';

/// One BIP-32 derivation level: child index plus the hardened flag (`'`).
class PathLevel {
  const PathLevel({required this.index, required this.hardened});

  /// The child index (below 0x80000000; the hardened bit lives in [hardened]).
  final int index;

  /// Whether the level is hardened.
  final bool hardened;
}

final RegExp _pathLevel = RegExp(r"^(\d+)('?)$");
const int _hardenedOffset = 0x80000000;
final BigInt _hardenedOffsetBig = BigInt.from(_hardenedOffset);

/// Parse `m/44'/60'/0'/0/5` into levels. Throws `invalid-props` on anything
/// else.
List<PathLevel> parsePath(String path) {
  if (!path.startsWith('m/')) {
    throw EraSdkError(
        'invalid-props', 'derivation path must start with "m/": $path');
  }
  final segments = path.substring(2).split('/');
  final levels = <PathLevel>[];
  for (final segment in segments) {
    final match = _pathLevel.firstMatch(segment);
    if (match == null) {
      throw EraSdkError(
          'invalid-props', 'bad derivation path segment "$segment"');
    }
    final index = int.tryParse(match.group(1)!);
    if (index == null || index >= _hardenedOffset) {
      throw EraSdkError(
          'invalid-props', 'derivation index out of range in "$segment"');
    }
    levels.add(PathLevel(index: index, hardened: match.group(2) == "'"));
  }
  if (levels.isEmpty) {
    throw EraSdkError('invalid-props', 'derivation path has no levels');
  }
  return levels;
}

/// Render levels back into an `m/...` path string.
String formatPath(List<PathLevel> levels) {
  final out = StringBuffer('m');
  for (final level in levels) {
    out
      ..write('/')
      ..write(level.index);
    if (level.hardened) out.write("'");
  }
  return out.toString();
}

/// Level-by-level equality of two paths.
bool pathEquals(List<PathLevel> a, List<PathLevel> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i].index != b[i].index || a[i].hardened != b[i].hardened) {
      return false;
    }
  }
  return true;
}

/// Flat `[index, hardened, index, hardened, ...]` component list.
CborValue pathComponentsCbor(List<PathLevel> levels) {
  final items = <CborValue>[];
  for (final level in levels) {
    items
      ..add(cbUint(level.index))
      ..add(cbBool(level.hardened));
  }
  return cbArray(items);
}

/// A `crypto-keypath` (tag 304): `{1: components, 2: xfp}` (key 2 omitted
/// when no xfp).
CborValue keypath304(List<PathLevel> levels, [int? xfp]) {
  final entries = <(int, CborValue)>[(1, pathComponentsCbor(levels))];
  if (xfp != null) entries.add((2, cbUint(xfp)));
  return cbTag(304, cbMap(entries));
}

/// Parse the flat component list of a `crypto-keypath` back into levels (null
/// on malformed).
List<PathLevel>? parsePathComponents(CborValue? value) {
  final items = asArray(value);
  if (items == null || items.length % 2 != 0) return null;
  final levels = <PathLevel>[];
  for (var i = 0; i < items.length; i += 2) {
    final index = asUint(items[i]);
    final hardened = asBool(items[i + 1]);
    if (index == null || hardened == null || index >= _hardenedOffsetBig) {
      return null;
    }
    levels.add(PathLevel(index: index.toInt(), hardened: hardened));
  }
  return levels;
}

final RegExp _xfpHex = RegExp(r'^[0-9a-fA-F]{1,8}$');

/// Normalize an xfp given as a u32 [int] or an 8-hex [String] into a u32 int.
int normalizeXfp(Object xfp) {
  if (xfp is int) {
    if (xfp < 0 || xfp > 0xffffffff) {
      throw EraSdkError(
          'invalid-props', 'xfp must be an unsigned 32-bit integer');
    }
    return xfp;
  }
  if (xfp is String) {
    final hex = xfp.startsWith('0x') ? xfp.substring(2) : xfp;
    if (!_xfpHex.hasMatch(hex)) {
      throw EraSdkError(
          'invalid-props', 'xfp string must be up to 8 hex characters');
    }
    return int.parse(hex, radix: 16);
  }
  throw EraSdkError('invalid-props',
      'xfp must be an unsigned 32-bit integer or a hex string');
}

/// Lowercase 8-hex form of an xfp (the display / Tron wire form).
String xfpToHex(int xfp) => xfp.toRadixString(16).padLeft(8, '0');
