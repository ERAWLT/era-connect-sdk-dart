import 'dart:typed_data';

import '../core/bytes.dart';
import '../crypto/digests.dart';
import '../crypto/secp256k1.dart';
import 'result.dart';

/// Digest family for [verifyCosmosSignature]: vanilla Cosmos zones hash with
/// sha256; Ethermint chains (Injective, Evmos, Dymension) with keccak256.
enum CosmosDigest { sha256, keccak256 }

/// Args for [verifyCosmosSignature].
class VerifyCosmosSignatureArgs {
  const VerifyCosmosSignatureArgs({
    required this.signData,
    required this.digest,
    required this.signature,
    required this.publicKey,
    this.expectedPublicKey,
  });

  /// The exact SignDoc bytes the request carried.
  final Uint8List signData;

  /// Digest family: vanilla Cosmos zones hash with sha256; Ethermint chains
  /// (Injective, Evmos, Dymension) with keccak256.
  final CosmosDigest digest;

  /// 64-byte compact signature from the reply.
  final Uint8List signature;

  /// 33-byte compressed public key (from the reply, or derived from your
  /// linked xpub).
  final Uint8List publicKey;

  /// Optional binding: the key you EXPECT (derived from the linked account).
  final Uint8List? expectedPublicKey;
}

/// Verify a Cosmos/Ethermint reply signature against the SignDoc bytes.
VerifyResult verifyCosmosSignature(VerifyCosmosSignatureArgs args) {
  if (args.signature.length != 64) {
    return failed('signature must be 64 bytes (compact r||s)');
  }
  if (args.publicKey.length != 33) {
    return failed('publicKey must be 33 bytes (compressed)');
  }
  final expectedPublicKey = args.expectedPublicKey;
  if (expectedPublicKey != null &&
      !equalBytes(args.publicKey, expectedPublicKey)) {
    return failed('the reply public key is not the linked account key');
  }
  final digest = args.digest == CosmosDigest.keccak256
      ? keccak256(args.signData)
      : sha256(args.signData);
  bool ok;
  try {
    ok = Secp256k1.verify(args.signature, digest, args.publicKey);
  } catch (e) {
    return failed('Cosmos signature could not be checked: $e');
  }
  return ok
      ? verified
      : failed('the signature does not belong to this account');
}
