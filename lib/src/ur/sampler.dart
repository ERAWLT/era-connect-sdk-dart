import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

import '../core/bytes.dart';
import 'limits.dart';
import 'xoshiro.dart';

/// Which source fragments the fountain frame `seqNum` of `seqLength` covers.
///
/// For `seqNum <= seqLength` the frame is the source fragment itself. Above
/// that, the BC-UR fountain sampler runs: seed = sha256(seqNum || checksum)
/// (both big-endian u32), Xoshiro256** drives an alias-method degree chooser
/// over `1/(i+1)` weights, then a full draw-without-replacement permutation of
/// which the first `degree` indexes are taken.
///
/// Every draw below happens in the exact order of the reference
/// implementation. The draw order IS the wire protocol — a different (even
/// "equivalent") shuffle makes the device's fountain frames undecodable.
List<int> chooseFragmentIndexes(int seqNum, int seqLength, int checksum) {
  if (seqLength < 1 || seqLength > UrLimits.maxFragmentCount) {
    throw RangeError(
      'seqLength $seqLength outside 1..${UrLimits.maxFragmentCount}; '
      'cannot build fountain indexes for a UR this large',
    );
  }
  if (seqNum <= seqLength) return [seqNum - 1];

  final digest = Uint8List.fromList(
    sha256.convert(concatBytes([u32be(seqNum), u32be(checksum)])).bytes,
  );
  final rng = Xoshiro256ss(digest);

  // Alias-method table over degree weights 1/(i+1).
  final scaled = List<double>.filled(seqLength, 0);
  var sum = 0.0;
  for (var i = 0; i < seqLength; i++) {
    sum += 1 / (i + 1);
  }
  for (var i = 0; i < seqLength; i++) {
    scaled[i] = ((1 / (i + 1)) * seqLength) / sum;
  }

  final prob = List<double>.filled(seqLength, 0);
  final alias = List<int>.filled(seqLength, 0);
  final small = <int>[];
  final large = <int>[];
  for (var i = seqLength - 1; i >= 0; i--) {
    (scaled[i] < 1 ? small : large).add(i);
  }
  while (small.isNotEmpty && large.isNotEmpty) {
    final less = small.removeLast();
    final more = large.removeLast();
    prob[less] = scaled[less];
    alias[less] = more;
    scaled[more] = scaled[more] + scaled[less] - 1;
    (scaled[more] < 1 ? small : large).add(more);
  }
  while (large.isNotEmpty) {
    prob[large.removeLast()] = 1;
  }
  while (small.isNotEmpty) {
    prob[small.removeLast()] = 1;
  }

  final c = (rng.nextDouble() * prob.length).floor();
  final sample = rng.nextDouble() < prob[c] ? c : alias[c];
  final degree = sample + 1;

  // Full permutation by draw-without-replacement; take the first `degree`.
  final remaining = <int>[];
  for (var i = 0; i < seqLength; i++) {
    remaining.add(i);
  }
  final permutation = <int>[];
  while (remaining.isNotEmpty) {
    final index = (rng.nextDouble() * remaining.length).floor();
    permutation.add(remaining.removeAt(index));
  }
  return permutation.sublist(0, degree);
}
