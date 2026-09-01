import 'dart:typed_data';

import '../chains/evm.dart';
import '../core/bytes.dart';
import '../crypto/digests.dart';
import '../crypto/secp256k1.dart';
import 'result.dart';

/// Arguments for [verifyEvmSignature].
class VerifyEvmSignatureArgs {
  const VerifyEvmSignatureArgs({
    required this.signData,
    required this.dataType,
    required this.signature,
    required this.address,
    this.reEncodedSignData,
  });

  /// The exact bytes the request carried in `signData`.
  final Uint8List signData;

  /// One of the [EvmDataType] values the request was built with.
  final int dataType;

  /// Raw `r || s || v` from the reply (65+ bytes; multi-byte legacy `v`
  /// handled).
  final Uint8List signature;

  /// The signer address the request was built for: 20 bytes ([Uint8List]) or
  /// a `0x` hex [String].
  final Object address;

  /// Optional: the signing payload re-derived from the transaction you are
  /// ABOUT TO BROADCAST. Recovering against [signData] alone proves the device
  /// signed something you asked for — this closes the second half: that it is
  /// the transaction still in your hands (payloads can legitimately change
  /// between build and send, e.g. a blockhash refresh in your own state).
  final Uint8List? reEncodedSignData;
}

/// EIP-191: 0x19 || "Ethereum Signed Message:\n" || len(message).
Uint8List _personalSignDigest(Uint8List message) {
  final prefix = utf8Encode('Ethereum Signed Message:\n${message.length}');
  return keccak256(concatBytes([
    Uint8List.fromList([0x19]),
    prefix,
    message
  ]));
}

/// "Did the device sign exactly what I sent, with the key I expected?"
/// keccak digest + public-key recovery; the recovered address must equal the
/// request's. Run it before broadcasting.
VerifyResult verifyEvmSignature(VerifyEvmSignatureArgs args) {
  if (args.signature.length < 65) {
    return failed('signature is shorter than 65 bytes');
  }
  final reEncoded = args.reEncodedSignData;
  if (reEncoded != null && !equalBytes(reEncoded, args.signData)) {
    return failed(
        'the transaction to broadcast is not the one the device signed');
  }

  final Uint8List digest;
  switch (args.dataType) {
    case EvmDataType.transaction:
    case EvmDataType.typedTransaction:
      digest = keccak256(args.signData);
    case EvmDataType.personalMessage:
      digest = _personalSignDigest(args.signData);
    case EvmDataType.typedData:
      return unverifiable(
        'EIP-712: the digest is the hash of the structure, computed only on the device',
      );
    default:
      return failed('unknown dataType ${args.dataType}');
  }

  var vBig = BigInt.zero;
  for (final b in args.signature.sublist(64)) {
    vBig = (vBig << 8) | BigInt.from(b);
  }
  final recoveryId = foldRecoveryId(vBig);
  if (recoveryId != 0 && recoveryId != 1) {
    return failed('implausible recovery value');
  }

  Uint8List recovered;
  try {
    final compressed =
        Secp256k1.recover(args.signature.sublist(0, 64), digest, recoveryId);
    final point = Secp256k1.parsePublicKey(compressed);
    final uncompressed = Uint8List.fromList(point.getEncoded(false));
    recovered = keccak256(uncompressed.sublist(1)).sublist(12);
  } on ArgumentError catch (e) {
    return failed('signature could not be checked: ${e.message}');
  }

  final expected = args.address is Uint8List
      ? args.address as Uint8List
      : hexToBytes(args.address as String);
  if (expected.length != 20) {
    return failed('expected address must be 20 bytes, got ${expected.length}');
  }
  if (!equalBytes(recovered, expected)) {
    return failed(
      'the signature does not belong to this account (recovered 0x${bytesToHex(recovered)})',
    );
  }
  return verified;
}
