import 'dart:typed_data';

import '../core/bytes.dart';
import '../crypto/ed25519.dart';
import 'result.dart';

/// Inputs for [verifySolanaSignature].
class VerifySolanaSignatureArgs {
  const VerifySolanaSignatureArgs({
    required this.signData,
    required this.signature,
    required this.publicKey,
    this.broadcastMessageBytes,
  });

  /// The exact bytes the request carried in `signData` (the compiled message).
  final Uint8List signData;

  /// 64-byte Ed25519 signature from the reply.
  final Uint8List signature;

  /// The 32-byte signer public key the request was built for.
  final Uint8List publicKey;

  /// Optional: the message bytes you are ABOUT TO BROADCAST. Matters most on
  /// Solana — a blockhash refresh between build and send makes "what was
  /// signed" and "what will be sent" two different objects that must agree.
  final Uint8List? broadcastMessageBytes;
}

/// Check a `sol-signature` against the request it answers.
VerifyResult verifySolanaSignature(VerifySolanaSignatureArgs args) {
  final broadcast = args.broadcastMessageBytes;
  if (broadcast != null && !equalBytes(broadcast, args.signData)) {
    return failed('the message to broadcast is not the one the device signed');
  }
  bool ok;
  try {
    ok = ed25519Verify(args.publicKey, args.signData, args.signature);
  } on Object catch (e) {
    return failed('Solana signature could not be checked: $e');
  }
  return ok
      ? verified
      : failed('the signature does not belong to this account');
}
