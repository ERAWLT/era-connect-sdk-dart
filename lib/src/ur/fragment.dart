import 'dart:typed_data';

import '../cbor/decode.dart';
import '../cbor/encode.dart';
import '../cbor/model.dart';
import 'limits.dart';
import 'sampler.dart';

/// A validated multi-part UR fragment.
class Fragment {
  const Fragment({
    required this.type,
    required this.seqNum,
    required this.seqLength,
    required this.messageLength,
    required this.checksum,
    required this.part,
    required this.indexes,
  });

  /// The UR registry type this fragment claims to belong to.
  final String type;

  /// The 1-based fountain sequence number.
  final int seqNum;

  /// The declared number of source fragments.
  final int seqLength;

  /// The declared reassembled message length, in bytes.
  final int messageLength;

  /// The declared CRC32 of the whole message.
  final int checksum;

  /// The fragment bytes (a source fragment, or an XOR of several).
  final Uint8List part;

  /// Which source fragments [part] covers. Treated as immutable.
  final List<int> indexes;
}

/// Whether the fragment covers exactly one source fragment.
bool isSimple(Fragment fragment) => fragment.indexes.length == 1;

/// Fragment CBOR: the definite 5-array `[seqNum, seqLen, msgLen, checksum, bytes]`.
Uint8List fragmentCbor(
  int seqNum,
  int seqLength,
  int messageLength,
  int checksum,
  Uint8List part,
) {
  return cborEncode(
    cbArray([
      cbUint(seqNum),
      cbUint(seqLength),
      cbUint(messageLength),
      cbUint(checksum),
      cbBytes(part),
    ]),
  );
}

/// Parse and validate a fragment payload, or return null.
///
/// Every field here is chosen by whoever printed the QR, and three of them size
/// allocations or loops downstream — so the bounds are checked as a set BEFORE
/// the (quadratic) fountain index derivation pays for anything.
Fragment? tryParseFragment(String type, Uint8List payload) {
  final CborValue decoded;
  try {
    decoded = cborDecode(payload);
  } catch (_) {
    return null;
  }
  if (decoded is! CborArray || decoded.items.length != 5) return null;

  final seqNum = _uintInRange(decoded.items[0]);
  final seqLength = _uintInRange(decoded.items[1]);
  final messageLength = _uintInRange(decoded.items[2]);
  final checksum = _uintInRange(decoded.items[3]);
  final partValue = decoded.items[4];
  if (seqNum == null ||
      seqLength == null ||
      messageLength == null ||
      checksum == null ||
      partValue is! CborBytes) {
    return null;
  }
  final part = partValue.value;
  if (!headerIsConsistent(
    seqNum: seqNum,
    seqLength: seqLength,
    messageLength: messageLength,
    checksum: checksum,
    fragmentLength: part.length,
  )) {
    return null;
  }
  return Fragment(
    type: type,
    seqNum: seqNum,
    seqLength: seqLength,
    messageLength: messageLength,
    checksum: checksum,
    part: part,
    indexes: chooseFragmentIndexes(seqNum, seqLength, checksum),
  );
}

/// A CBOR uint in [0, 2^32), or null for anything else.
int? _uintInRange(CborValue value) {
  if (value is! CborUint) return null;
  final big = value.value;
  if (big < BigInt.zero || big > BigInt.from(UrLimits.maxUint32)) return null;
  return big.toInt();
}
