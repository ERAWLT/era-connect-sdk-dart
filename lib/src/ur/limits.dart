/// Bounds every field a scanned UR fragment can dictate, BEFORE that field is
/// allowed to size an allocation or a loop.
///
/// A QR in the camera frame is attacker-controlled input: a sticker on the
/// device, a second screen, a poster. Without these bounds the fragment
/// header's `seqLength` goes straight into array allocation and into a
/// quadratic index shuffle, so ~60 characters of QR can ask the host for
/// gigabytes or minutes of work — no gzip, no multi-frame assembly, one frame.
///
/// The numbers are generous headroom over real device traffic, NOT tight
/// protocol bounds: a cap that refuses a genuine reply is worse than the
/// denial of service it prevents.
abstract final class UrLimits {
  /// Largest reassembled UR payload, in bytes.
  static const int maxMessageBytes = 64 * 1024;

  /// Largest number of source fragments a multi-part UR may declare.
  static const int maxFragmentCount = 2048;

  /// Largest single fragment payload, in bytes (QR v40 tops out at 2953).
  static const int maxFragmentBytes = 4096;

  /// Largest value for any u32 header field (`seqNum`, `checksum`).
  static const int maxUint32 = 0xffffffff;
}

/// Whether a fragment header describes a UR that could exist.
///
/// The two inequalities are the BC-UR relation
/// `seqLength == ceil(messageLength / fragmentLength)` written without
/// division — exactly what both fountain encoders produce. They stop a header
/// from claiming thousands of fragments for a twenty-byte message.
///
/// `seqLength >= 2`, not 1: a "multi-part" UR with a single source fragment is
/// something neither encoder can produce (both short-circuit to a single-part
/// UR), and it would defeat the two-fragment stream-binding rule with two
/// static images (`1-1` and `2-1` differ only in seqNum and both resolve to
/// fragment 0).
bool headerIsConsistent({
  required int seqNum,
  required int seqLength,
  required int messageLength,
  required int checksum,
  required int fragmentLength,
}) {
  if (seqNum < 1 || seqNum > UrLimits.maxUint32) return false;
  if (checksum < 0 || checksum > UrLimits.maxUint32) return false;
  if (seqLength < 2 || seqLength > UrLimits.maxFragmentCount) return false;
  if (fragmentLength < 1 || fragmentLength > UrLimits.maxFragmentBytes) {
    return false;
  }
  if (messageLength < 1 || messageLength > UrLimits.maxMessageBytes) {
    return false;
  }
  if (messageLength > seqLength * fragmentLength) return false;
  if (messageLength <= (seqLength - 1) * fragmentLength) return false;
  return true;
}
