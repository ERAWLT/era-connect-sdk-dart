import 'dart:typed_data';

import '../chains/sui.dart';
import '../core/bytes.dart';
import '../crypto/ed25519.dart';
import 'result.dart';

/// Inputs for [verifySuiSignature].
class VerifySuiSignatureArgs {
  const VerifySuiSignatureArgs({
    this.intentMessage,
    this.messageHash,
    required this.signature,
    required this.publicKey,
    this.expectedPublicKey,
  });

  /// The intent message the request carried (or pass [messageHash] for the
  /// hash variant).
  final Uint8List? intentMessage;

  final Uint8List? messageHash;

  /// 64-byte Ed25519 signature from the reply.
  final Uint8List signature;

  /// The signer key the reply carried.
  final Uint8List publicKey;

  /// The linked account's key (`accounts.sui()[i].publicKey`) — binds the
  /// reply to YOUR wallet.
  final Uint8List? expectedPublicKey;
}

/// BLAKE2b-256 of the intent message (or the given hash) + Ed25519
/// verification.
VerifyResult verifySuiSignature(VerifySuiSignatureArgs args) {
  Uint8List digest;
  final messageHash = args.messageHash;
  final intentMessage = args.intentMessage;
  if (messageHash != null) {
    if (messageHash.length != 32) return failed('messageHash must be 32 bytes');
    digest = messageHash;
  } else if (intentMessage != null) {
    digest = suiIntentDigest(intentMessage);
  } else {
    return failed('provide intentMessage or messageHash');
  }
  final expectedPublicKey = args.expectedPublicKey;
  if (expectedPublicKey != null &&
      !equalBytes(args.publicKey, expectedPublicKey)) {
    return failed('the reply public key is not the linked account key');
  }
  bool ok;
  try {
    ok = ed25519Verify(args.publicKey, digest, args.signature);
  } on Object catch (e) {
    return failed('Sui signature could not be checked: $e');
  }
  return ok
      ? verified
      : failed('the signature does not belong to this account');
}
