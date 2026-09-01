import 'dart:typed_data';

import '../chains/ton.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../crypto/digests.dart';
import '../crypto/ed25519.dart';
import 'result.dart';
import 'ton_boc.dart';

/// Arguments for [verifyTonSignature].
class VerifyTonSignatureArgs {
  const VerifyTonSignatureArgs({
    required this.signData,
    required this.dataType,
    required this.signature,
    required this.publicKey,
  });

  /// The exact bytes the request carried in `signData`.
  final Uint8List signData;

  /// The request's [TonDataType].
  final int dataType;

  /// 64-byte Ed25519 signature from the reply.
  final Uint8List signature;

  /// The 32-byte signer public key from linking (`accounts.ton()`).
  final Uint8List publicKey;
}

/// Recompute the exact digest the device signs — the BoC ROOT CELL's
/// representation hash for a transaction, or the TON Connect proof digest
/// `sha256(0xFFFF || "ton-connect" || sha256(payload))` — and verify the
/// Ed25519 signature against the linked key.
VerifyResult verifyTonSignature(VerifyTonSignatureArgs args) {
  if (args.signature.length != 64) return failed('signature must be 64 bytes');
  if (args.publicKey.length != 32) return failed('public key must be 32 bytes');

  Uint8List digest;
  if (args.dataType == TonDataType.tonProof) {
    digest = sha256(concatBytes([
      Uint8List.fromList([0xff, 0xff]),
      utf8Encode('ton-connect'),
      sha256(args.signData),
    ]));
  } else if (args.dataType == TonDataType.transaction) {
    try {
      digest = bocRootHash(args.signData);
    } on EraSdkError catch (e) {
      return failed('signData is not a readable BoC: ${e.message}');
    }
  } else {
    return failed('unknown dataType ${args.dataType}');
  }

  final ok = ed25519Verify(args.publicKey, digest, args.signature);
  return ok
      ? verified
      : failed('the signature does not belong to this account');
}
