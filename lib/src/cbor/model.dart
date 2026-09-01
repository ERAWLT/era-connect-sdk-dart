import 'dart:typed_data';

import '../core/errors.dart';

/// Minimal CBOR value model for the ERA wire protocol.
///
/// Maps are ENTRY LISTS, not hash maps: insertion order is preserved for
/// byte-exact re-encoding, and the decoder can reject duplicate keys.
sealed class CborValue {
  const CborValue();
}

/// An unsigned integer (major type 0).
final class CborUint extends CborValue {
  const CborUint(this.value);

  /// The non-negative integer value.
  final BigInt value;
}

/// A negative integer (major type 1), holding the MAGNITUDE:
/// encoded as -1 - value.
final class CborNegint extends CborValue {
  const CborNegint(this.value);

  /// The non-negative magnitude; the encoded integer is `-1 - value`.
  final BigInt value;
}

/// A byte string (major type 2).
final class CborBytes extends CborValue {
  const CborBytes(this.value);

  /// The raw bytes.
  final Uint8List value;
}

/// A UTF-8 text string (major type 3).
final class CborText extends CborValue {
  const CborText(this.value);

  /// The decoded text.
  final String value;
}

/// An array (major type 4).
final class CborArray extends CborValue {
  const CborArray(this.items);

  /// The items in order.
  final List<CborValue> items;
}

/// A map (major type 5), kept as an entry list in insertion order.
final class CborMap extends CborValue {
  const CborMap(this.entries);

  /// The `(key, value)` pairs in insertion order.
  final List<(CborValue, CborValue)> entries;
}

/// A boolean (major type 7, simple value 20/21).
final class CborBool extends CborValue {
  const CborBool(this.value);

  /// The boolean value.
  final bool value;
}

/// Null (major type 7, simple value 22).
final class CborNull extends CborValue {
  const CborNull();
}

/// A tagged value (major type 6).
final class CborTag extends CborValue {
  const CborTag(this.tag, this.value);

  /// The tag number.
  final int tag;

  /// The tagged content.
  final CborValue value;
}

/// An unsigned integer value. Accepts an [int] or a [BigInt].
CborValue cbUint(Object value) {
  final BigInt v = switch (value) {
    final int i => BigInt.from(i),
    final BigInt b => b,
    _ => throw EraSdkError(
        'invalid-props', 'cbUint: value must be an int or BigInt'),
  };
  if (v < BigInt.zero) {
    throw EraSdkError('invalid-props', 'cbUint: negative value');
  }
  return CborUint(v);
}

/// A byte-string value.
CborValue cbBytes(Uint8List value) => CborBytes(value);

/// A text-string value.
CborValue cbText(String value) => CborText(value);

/// An array value.
CborValue cbArray(List<CborValue> items) => CborArray(items);

/// A boolean value.
CborValue cbBool(bool value) => CborBool(value);

/// A tagged value.
CborValue cbTag(int tag, CborValue value) => CborTag(tag, value);

/// Integer-keyed map in the given entry order (the shape every ERA payload uses).
CborValue cbMap(List<(int, CborValue)> entries) =>
    CborMap([for (final (k, v) in entries) (cbUint(k), v)]);

/// Strip any tag wrappers (tag-37 UUID echoes, tag-304 keypaths, ...).
CborValue stripTags(CborValue value) {
  var v = value;
  while (v is CborTag) {
    v = v.value;
  }
  return v;
}

/// Look up an integer key in a map value. Tag-agnostic on the VALUE is the
/// caller's choice.
CborValue? mapGet(CborValue map, int key) {
  if (map is! CborMap) return null;
  final k = BigInt.from(key);
  for (final (ek, ev) in map.entries) {
    if (ek is CborUint && ek.value == k) return ev;
  }
  return null;
}

/// The unsigned-integer value, through tags; `null` if [value] is not one.
BigInt? asUint(CborValue? value) {
  if (value == null) return null;
  final v = stripTags(value);
  return v is CborUint ? v.value : null;
}

/// The byte string, through tags; `null` if [value] is not one.
Uint8List? asBytes(CborValue? value) {
  if (value == null) return null;
  final v = stripTags(value);
  return v is CborBytes ? v.value : null;
}

/// The text string, through tags; `null` if [value] is not one.
String? asText(CborValue? value) {
  if (value == null) return null;
  final v = stripTags(value);
  return v is CborText ? v.value : null;
}

/// The array items, through tags; `null` if [value] is not one.
List<CborValue>? asArray(CborValue? value) {
  if (value == null) return null;
  final v = stripTags(value);
  return v is CborArray ? v.items : null;
}

/// The map, through tags; `null` if [value] is not one.
CborMap? asMap(CborValue? value) {
  if (value == null) return null;
  final v = stripTags(value);
  return v is CborMap ? v : null;
}

/// The boolean, through tags; `null` if [value] is not one.
bool? asBool(CborValue? value) {
  if (value == null) return null;
  final v = stripTags(value);
  return v is CborBool ? v.value : null;
}
