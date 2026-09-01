/// Minimal PSBT v0 (BIP-174) reader — just enough structure for the
/// verification guard: the global unsigned transaction (verbatim slice, never
/// re-serialized), the PSBT version, and per-input key/value maps.
///
/// Hardened: compact-size lengths bounds-checked before slicing, duplicate
/// keys within one map refused (a hostile PSBT carrying two final scriptSigs
/// for one input must not survive parsing).
library;

import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';

/// One key/value entry of a PSBT map.
class PsbtKeyValue {
  const PsbtKeyValue({
    required this.keyType,
    required this.keyData,
    required this.value,
  });

  /// The first key byte (the entry type).
  final int keyType;

  /// The key bytes after the type byte.
  final Uint8List keyData;

  /// The entry value.
  final Uint8List value;
}

/// A structurally parsed PSBT v0.
class ParsedPsbt {
  const ParsedPsbt({
    required this.unsignedTx,
    required this.version,
    required this.inputs,
    required this.outputs,
  });

  /// The global UNSIGNED_TX value, verbatim.
  final Uint8List unsignedTx;

  /// Global PSBT_GLOBAL_VERSION (0xFB) if present; v0 files normally omit it.
  final int version;

  /// Per-input key/value maps.
  final List<List<PsbtKeyValue>> inputs;

  /// Per-output key/value maps.
  final List<List<PsbtKeyValue>> outputs;
}

const List<int> _magic = [0x70, 0x73, 0x62, 0x74, 0xff]; // "psbt\xff"

/// PSBT per-input key types the verification guard cares about.
abstract final class PsbtInputType {
  static const int partialSig = 0x02;
  static const int finalScriptSig = 0x07;
  static const int finalScriptWitness = 0x08;
  static const int taprootKeySpendSignature = 0x13;
  static const int taprootScriptSpendSignature = 0x14;
}

EraSdkError _err(String message) {
  return EraSdkError('malformed-reply', 'psbt: $message');
}

/// The same `Number.isSafeInteger` bound (2^53 - 1) the TypeScript SDK
/// enforces on compact-size lengths.
final BigInt _maxSafeInteger = BigInt.from(9007199254740991);

class _Reader {
  _Reader(this.bytes);

  final Uint8List bytes;
  int offset = 0;

  int get remaining => bytes.length - offset;

  int u8() {
    if (offset >= bytes.length) throw _err('truncated');
    final b = bytes[offset];
    offset += 1;
    return b;
  }

  /// Bitcoin compact-size integer, MINIMAL encoding required (as consensus
  /// does).
  int compactSize() {
    final first = u8();
    if (first < 0xfd) return first;
    int width;
    BigInt minimum;
    if (first == 0xfd) {
      width = 2;
      minimum = BigInt.from(0xfd);
    } else if (first == 0xfe) {
      width = 4;
      minimum = BigInt.from(0x10000);
    } else {
      width = 8;
      minimum = BigInt.from(0x100000000);
    }
    var value = BigInt.zero;
    for (var i = 0; i < width; i++) {
      value |= BigInt.from(u8()) << (8 * i);
    }
    if (value < minimum) throw _err('non-minimal compact-size encoding');
    if (value > _maxSafeInteger) throw _err('length exceeds safe range');
    return value.toInt();
  }

  Uint8List take(int length) {
    if (length > remaining) throw _err('length exceeds input');
    final out = bytes.sublist(offset, offset + length);
    offset += length;
    return out;
  }
}

/// Read one key/value map (ends at the 0x00 separator).
List<PsbtKeyValue> _readMap(_Reader reader) {
  final entries = <PsbtKeyValue>[];
  final seen = <String>{};
  for (;;) {
    final keyLength = reader.compactSize();
    if (keyLength == 0) return entries;
    final key = reader.take(keyLength);
    final value = reader.take(reader.compactSize());
    final keyId = bytesToHex(key);
    if (seen.contains(keyId)) throw _err('duplicate key within one map');
    seen.add(keyId);
    entries.add(PsbtKeyValue(
      keyType: key[0],
      keyData: key.sublist(1),
      value: value,
    ));
  }
}

/// Count of inputs/outputs in a (non-witness) unsigned transaction.
({int inputs, int outputs}) _countTxInputsOutputs(Uint8List tx) {
  final reader = _Reader(tx);
  reader.take(4); // version
  final inputs = reader.compactSize();
  if (inputs == 0) {
    // A zero here would be a segwit marker — the PSBT unsigned tx must not
    // carry witness data, so this is not a transaction we can count.
    throw _err(
        'unsigned transaction has zero inputs (or carries witness data)');
  }
  for (var i = 0; i < inputs; i++) {
    reader.take(32 + 4); // prevout
    reader.take(reader.compactSize()); // scriptSig (empty in a PSBT)
    reader.take(4); // sequence
  }
  final outputs = reader.compactSize();
  for (var i = 0; i < outputs; i++) {
    reader.take(8); // amount
    reader.take(reader.compactSize()); // scriptPubKey
  }
  reader.take(4); // locktime
  if (reader.remaining != 0) {
    throw _err('trailing bytes after the unsigned transaction');
  }
  return (inputs: inputs, outputs: outputs);
}

/// Parse [bytes] as a PSBT v0, refusing anything structurally off.
ParsedPsbt parsePsbt(Uint8List bytes) {
  final reader = _Reader(bytes);
  for (final expected in _magic) {
    if (reader.u8() != expected) throw _err('bad magic');
  }
  final globalMap = _readMap(reader);

  Uint8List? unsignedTx;
  var version = 0;
  for (final entry in globalMap) {
    if (entry.keyType == 0x00 && entry.keyData.isEmpty) {
      unsignedTx = entry.value;
    }
    if (entry.keyType == 0xfb && entry.keyData.isEmpty) {
      if (entry.value.length != 4) throw _err('bad version field');
      version = entry.value[0] |
          (entry.value[1] << 8) |
          (entry.value[2] << 16) |
          (entry.value[3] << 24);
    }
  }
  if (unsignedTx == null) {
    // The device's signer relies on the global UNSIGNED_TX that only PSBT v0
    // carries; its absence means v2 (or not a PSBT at all).
    throw _err('no global unsigned transaction — not a PSBT v0');
  }
  if (version != 0) throw _err('unsupported PSBT version $version');

  final counts = _countTxInputsOutputs(unsignedTx);
  final inputs = <List<PsbtKeyValue>>[];
  for (var i = 0; i < counts.inputs; i++) {
    inputs.add(_readMap(reader));
  }
  final outputs = <List<PsbtKeyValue>>[];
  for (var i = 0; i < counts.outputs; i++) {
    outputs.add(_readMap(reader));
  }
  if (reader.remaining != 0) {
    throw _err('trailing bytes after the output maps');
  }

  return ParsedPsbt(
    unsignedTx: unsignedTx,
    version: version,
    inputs: inputs,
    outputs: outputs,
  );
}

/// The entries of key type [keyType] in input [index] (empty when the index
/// is out of range).
List<PsbtKeyValue> inputEntries(ParsedPsbt psbt, int index, int keyType) {
  if (index < 0 || index >= psbt.inputs.length) return const [];
  return psbt.inputs[index].where((e) => e.keyType == keyType).toList();
}

/// Whether input [index] carries any entry of key type [keyType].
bool inputHas(ParsedPsbt psbt, int index, int keyType) {
  return inputEntries(psbt, index, keyType).isNotEmpty;
}
