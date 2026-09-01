/// Minimal TON Bag-of-Cells reader + cell representation hash — exactly the
/// subset the device's signer implements: generic BoC, ordinary level-0 cells,
/// first root. The transaction digest the device signs IS the root cell's
/// representation hash, so this must agree with the firmware bit for bit.
///
/// Hardened for scanned/untrusted input: size caps, bounds checks, and
/// forward-only references (the standard BoC topological order; a backward
/// reference would make the single-pass hash read an uncomputed child).
library;

import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../crypto/digests.dart';

const int _bocMagic = 0xb5ee9c72;
const int _maxCells = 256;
const int _maxCellDataBytes = 128;
const int _maxRefs = 4;

/// The `Number.isSafeInteger` bound the TypeScript SDK enforces on header
/// integers (2^53 - 1) — kept for cross-SDK parity and web compatibility.
const int _maxSafeInteger = 9007199254740991;

class _Cell {
  _Cell({
    required this.dataBits,
    required this.data,
    required this.refs,
  });

  int dataBits;
  Uint8List data;
  List<int> refs;
  int depth = 0;
  Uint8List hash = Uint8List(0);
}

EraSdkError _err(String message) {
  return EraSdkError('malformed-reply', 'ton boc: $message');
}

/// Representation hash of the ROOT cell of a BoC — the bytes TON signs.
Uint8List bocRootHash(Uint8List boc) {
  if (boc.length < 10) throw _err('too short');
  final magic = (boc[0] << 24) | (boc[1] << 16) | (boc[2] << 8) | boc[3];
  if (magic != _bocMagic) throw _err('not a generic BoC');

  final flags = boc[4];
  final hasIdx = (flags >> 7) & 1;
  final refSize = flags & 0x07;
  final offSize = boc[5];
  if (refSize == 0 || refSize > 4) throw _err('bad ref size');
  if (offSize == 0 || offSize > 8) throw _err('bad offset size');

  var pos = 6;
  int readInt(int byteLen) {
    var value = 0;
    for (var i = 0; i < byteLen; i++) {
      if (pos >= boc.length) throw _err('truncated header');
      value = value * 256 + boc[pos++];
      // Checked per step (the TypeScript SDK checks once after the loop, but
      // the accumulator is monotonic, so the rejection set is identical —
      // and this keeps a native 64-bit int from wrapping first).
      if (value > _maxSafeInteger) throw _err('header value out of range');
    }
    return value;
  }

  final cellCount = readInt(refSize);
  final rootCount = readInt(refSize);
  readInt(refSize); // absent count
  readInt(offSize); // total cell data size
  if (rootCount == 0) throw _err('no roots');
  if (cellCount == 0 || cellCount > _maxCells) {
    throw _err('cell count out of range');
  }

  final rootIndex = readInt(refSize);
  for (var i = 1; i < rootCount; i++) {
    readInt(refSize); // remaining root indices
  }
  if (rootIndex >= cellCount) throw _err('root index out of range');
  if (hasIdx != 0) pos += cellCount * offSize; // skip the offsets index

  final cells = <_Cell>[];
  for (var i = 0; i < cellCount; i++) {
    if (pos + 2 > boc.length) throw _err('truncated cell');
    final d1 = boc[pos++];
    final d2 = boc[pos++];
    final refCount = d1 & 0x07;
    if (refCount > _maxRefs) throw _err('too many references');

    final dataByteLen = (d2 + 1) >> 1;
    final incomplete = (d2 & 1) == 1;
    if (dataByteLen > _maxCellDataBytes) throw _err('cell data too large');
    if (pos + dataByteLen > boc.length) throw _err('truncated cell data');
    final data = boc.sublist(pos, pos + dataByteLen);
    pos += dataByteLen;

    // Bit length from the completion tag (last set bit marks the end).
    int dataBits;
    if (incomplete && dataByteLen > 0) {
      final last = data[dataByteLen - 1];
      if (last == 0) {
        dataBits = (dataByteLen - 1) * 8;
      } else {
        var trailingZeros = 0;
        for (var b = 0; b < 8; b++) {
          if (last & (1 << b) != 0) break;
          trailingZeros++;
        }
        dataBits = dataByteLen * 8 - 1 - trailingZeros;
      }
    } else {
      dataBits = dataByteLen * 8;
    }

    final refs = <int>[];
    for (var r = 0; r < refCount; r++) {
      final ref = readInt(refSize);
      if (ref >= cellCount) throw _err('reference out of range');
      if (ref <= i) throw _err('non-topological cell reference');
      refs.add(ref);
    }
    cells.add(_Cell(dataBits: dataBits, data: data, refs: refs));
  }

  // Bottom-up (children first — guaranteed by the forward-only reference
  // check).
  for (var i = cellCount - 1; i >= 0; i--) {
    final cell = cells[i];
    var maxChildDepth = -1;
    for (final r in cell.refs) {
      if (cells[r].depth > maxChildDepth) maxChildDepth = cells[r].depth;
    }
    cell.depth = cell.refs.isEmpty ? 0 : maxChildDepth + 1;

    final dataBytes = (cell.dataBits + 7) >> 3;
    final incomplete = cell.dataBits % 8 != 0;
    final repr = <int>[cell.refs.length, dataBytes * 2 - (incomplete ? 1 : 0)];
    for (var b = 0; b < dataBytes; b++) {
      repr.add(b < cell.data.length ? cell.data[b] : 0);
    }
    if (incomplete && dataBytes > 0) {
      final shift = 7 - (cell.dataBits % 8);
      final last = repr.length - 1;
      repr[last] = (repr[last] | (1 << shift)) & (0xff << shift) & 0xff;
    }
    for (final r in cell.refs) {
      repr
        ..add((cells[r].depth >> 8) & 0xff)
        ..add(cells[r].depth & 0xff);
    }
    var bytes = Uint8List.fromList(repr);
    for (final r in cell.refs) {
      bytes = concatBytes([bytes, cells[r].hash]);
    }
    cell.hash = sha256(bytes);
  }

  return cells[rootIndex].hash;
}
