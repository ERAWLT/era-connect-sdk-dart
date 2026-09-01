import 'dart:typed_data';

import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../crypto/digests.dart';
import '../registry/keypath.dart';
import '../ur/ur.dart';
import 'shared.dart';

/// Props for [SuiChain.generateSignRequest].
class SuiSignRequestProps {
  const SuiSignRequestProps({
    this.requestId,
    required this.intentMessage,
    required this.path,
    required this.xfp,
    this.address,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  /// The COMPLETE BCS intent message (intent prefix + transaction bytes) as
  /// your Sui tooling produces it — the device signs BLAKE2b-256 of exactly
  /// these bytes.
  final Uint8List intentMessage;

  /// Fully hardened SLIP-10 path, e.g. `m/44'/784'/0'/0'/0'`.
  final String path;

  /// Master fingerprint: u32 [int] or 8-hex [String].
  final Object xfp;

  /// 32-byte Sui address (raw [Uint8List] or `0x` hex [String]) — device
  /// display.
  final Object? address;

  final String? origin;
}

/// Props for [SuiChain.generateSignHashRequest].
class SuiSignHashRequestProps {
  const SuiSignHashRequestProps({
    this.requestId,
    required this.messageHash,
    required this.path,
    required this.xfp,
    this.address,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  /// The 32-byte digest to sign directly (the hash-request variant).
  final Uint8List messageHash;

  /// Fully hardened SLIP-10 path, e.g. `m/44'/784'/0'/0'/0'`.
  final String path;

  /// Master fingerprint: u32 [int] or 8-hex [String].
  final Object xfp;

  /// 32-byte Sui address (raw [Uint8List] or `0x` hex [String]) — device
  /// display.
  final Object? address;

  final String? origin;
}

/// A parsed `sui-signature` reply.
class SuiSignatureResult {
  const SuiSignatureResult({
    required this.requestId,
    required this.signature,
    required this.publicKey,
  });

  final Uint8List requestId;

  /// 64-byte Ed25519 signature.
  final Uint8List signature;

  /// The 32-byte signer public key the device answered with.
  final Uint8List publicKey;
}

const List<String> _replyTypes = ['sui-signature'];

/// Sui signing over the ERA UR protocol.
class SuiChain {
  SuiChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Build a `sui-sign-request` (7101). Reply: `sui-signature` (7102).
  SignRequest<SuiSignatureResult> generateSignRequest(
      SuiSignRequestProps props) {
    if (props.intentMessage.isEmpty) {
      throw EraSdkError('invalid-props', 'intentMessage must not be empty');
    }
    return _build(
      urType: 'sui-sign-request',
      signData: cbBytes(props.intentMessage),
      requestId: props.requestId,
      path: props.path,
      xfp: props.xfp,
      address: props.address,
      origin: props.origin,
    );
  }

  /// Build a `sui-sign-hash-request` (7103) — signs the given 32-byte digest
  /// directly.
  SignRequest<SuiSignatureResult> generateSignHashRequest(
      SuiSignHashRequestProps props) {
    if (props.messageHash.length != 32) {
      throw EraSdkError('invalid-props', 'messageHash must be 32 bytes');
    }
    // The hash travels as a HEX STRING on this variant (device contract).
    return _build(
      urType: 'sui-sign-hash-request',
      signData: cbText(bytesToHex(props.messageHash)),
      requestId: props.requestId,
      path: props.path,
      xfp: props.xfp,
      address: props.address,
      origin: props.origin,
    );
  }

  SignRequest<SuiSignatureResult> _build({
    required String urType,
    required CborValue signData,
    required Object? requestId,
    required String path,
    required Object xfp,
    required Object? address,
    required String? origin,
  }) {
    final id = resolveRequestId(_context, requestId);
    final levels = parsePath(path);
    if (!levels.every((level) => level.hardened)) {
      throw EraSdkError(
        'invalid-props',
        'Sui signing paths are fully hardened (SLIP-10 Ed25519), got $path',
      );
    }
    final normalizedXfp = normalizeXfp(xfp);

    final entries = <(int, CborValue)>[
      (1, cbTag(37, cbBytes(id))),
      (2, signData),
      (3, cbArray([keypath304(levels, normalizedXfp)])),
    ];
    if (address != null) {
      final Uint8List addressBytes = switch (address) {
        final Uint8List bytes => bytes,
        final String hex => hexToBytes(hex),
        _ => throw EraSdkError(
            'invalid-props', 'Sui address must be raw bytes or a hex string'),
      };
      if (addressBytes.length != 32) {
        throw EraSdkError('invalid-props', 'Sui address must be 32 bytes');
      }
      entries.add((4, cbArray([cbBytes(addressBytes)])));
    }
    entries.add((5, cbText(origin ?? _context.origin)));

    final ur = Ur(urType, cborEncode(cbMap(entries)));
    return makeSignRequest<SuiSignatureResult>(
      ur: ur,
      requestId: id,
      replyTypes: _replyTypes,
      context: _context,
      parse: (reply) => _parseSuiSignature(reply, id),
    );
  }

  /// Parse a `sui-signature` standalone. Prefer `SignRequest.scanner().parse()`.
  SuiSignatureResult parseSignature(Object input, [ExpectedReply? expect]) {
    return _parseSuiSignature(
      toUr(input),
      expect?.requestId == null ? null : normalizeRequestId(expect!.requestId!),
    );
  }
}

/// BLAKE2b-256 of the intent message — the digest the device signs for
/// `sui-sign-request`.
Uint8List suiIntentDigest(Uint8List intentMessage) {
  return blake2b256(intentMessage);
}

SuiSignatureResult _parseSuiSignature(Ur ur, Uint8List? expectedRequestId) {
  requireUrType(ur, _replyTypes, 'sui-signature');
  final map = requireReplyMap(ur, 'sui-signature');
  final requestId =
      requireRequestIdEcho(map, 1, expectedRequestId, 'sui-signature');
  final signature = asBytes(mapGet(map, 2));
  if (signature == null || signature.length != 64) {
    throw EraSdkError(
      'malformed-reply',
      'sui-signature signature is ${signature?.length ?? 0} bytes, expected 64',
    );
  }
  final publicKey = asBytes(mapGet(map, 3));
  if (publicKey == null || publicKey.length != 32) {
    throw EraSdkError(
      'malformed-reply',
      'sui-signature is missing the 32-byte public key (key 3)',
    );
  }
  return SuiSignatureResult(
    requestId: requestId,
    signature: signature,
    publicKey: publicKey,
  );
}
