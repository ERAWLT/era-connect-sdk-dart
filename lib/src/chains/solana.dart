import 'dart:typed_data';

import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../crypto/codecs.dart';
import '../registry/keypath.dart';
import '../ur/ur.dart';
import 'shared.dart';

/// `sol-sign-request` signType (CBOR key 7).
abstract final class SolSignType {
  /// Key 7 is OMITTED on the wire for a transaction (the device's default).
  static const int transaction = 1;

  /// Off-chain message: key 7 = 2. The device signs the bytes VERBATIM (no
  /// prefix).
  static const int message = 2;
}

/// Inputs for [SolanaChain.generateSignRequest].
class SolSignRequestProps {
  const SolSignRequestProps({
    this.requestId,
    required this.signData,
    this.signType,
    required this.path,
    required this.xfp,
    this.publicKey,
    this.address,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  /// Compiled transaction MESSAGE bytes (legacy or versioned), or raw message
  /// bytes.
  final Uint8List signData;

  /// A [SolSignType] value. Defaults to `transaction`.
  final int? signType;

  /// The signer's derivation path, fully hardened, 2 to 4 levels — the
  /// exported account IS the signer (Ed25519 has no public child derivation).
  ///
  /// The device exports THREE Solana derivations, told apart by depth alone:
  /// `m/44'/501'` ("Single Account Path", what the device's own Receive screen
  /// shows by default), `m/44'/501'/idx'` ("Account-based Path") and
  /// `m/44'/501'/idx'/0'` ("Sub-account Path"). See `EraAccounts.solana` /
  /// [SolanaScheme].
  ///
  /// The firmware signs with the key at the FULL path it is given
  /// (`SolanaDispatcher.cpp:354-372` — `wallet.getKey(coin, *derivationPath)`),
  /// and its only gate is that the request's source fingerprint matches the
  /// master or the parent (`SolanaDispatcher.cpp:149-173`). So all three depths
  /// sign; this used to refuse two of them and made the device's own default
  /// address unspendable through the SDK.
  final String path;

  /// The master fingerprint: a u32 [int] or an 8-hex [String].
  final Object xfp;

  /// 32-byte Ed25519 public key, or its base58 [address] form. One of the two
  /// is required.
  final Uint8List? publicKey;

  /// The base58 address form of [publicKey].
  final String? address;

  final String? origin;
}

/// A parsed `sol-signature` reply.
class SolSignatureResult {
  const SolSignatureResult({required this.requestId, required this.signature});

  final Uint8List requestId;

  /// 64-byte Ed25519 signature.
  final Uint8List signature;
}

const List<String> _replyTypes = ['sol-signature'];

/// The Solana chain module: `sol-sign-request` out, `sol-signature` back.
class SolanaChain {
  SolanaChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Build a `sol-sign-request` (1101). Reply: `sol-signature` (1102).
  SignRequest<SolSignatureResult> generateSignRequest(
    SolSignRequestProps props,
  ) {
    final requestId = resolveRequestId(_context, props.requestId);
    final path = parsePath(props.path);
    // 2..4 fully hardened levels: the three derivations the device exports.
    // The coin type is deliberately NOT checked — the guard never checked it,
    // and adding that in a minor would refuse paths that sign today.
    if (path.length < 2 || path.length > 4 || !path.every((l) => l.hardened)) {
      throw EraSdkError(
        'invalid-props',
        'Solana signing path must be fully hardened and 2 to 4 levels '
            "(m/44'/501', m/44'/501'/idx', m/44'/501'/idx'/0'), "
            'got ${props.path}',
      );
    }
    final xfp = normalizeXfp(props.xfp);
    final publicKey = _resolvePublicKey(props);

    final entries = <(int, CborValue)>[
      (1, cbBytes(requestId)),
      (2, cbBytes(props.signData)),
      (3, keypath304(path, xfp)),
      (4, cbBytes(publicKey)),
      (5, cbText(props.origin ?? _context.origin)),
      (6, cbUint(1)), // version
    ];
    if ((props.signType ?? SolSignType.transaction) == SolSignType.message) {
      entries.add((7, cbUint(SolSignType.message)));
    }
    final ur = Ur('sol-sign-request', cborEncode(cbMap(entries)));

    return makeSignRequest(
      ur: ur,
      requestId: requestId,
      replyTypes: _replyTypes,
      context: _context,
      parse: (reply) => _parseSolSignature(reply, requestId),
    );
  }

  /// Parse a `sol-signature` standalone. Prefer `SignRequest.scanner().parse()`.
  SolSignatureResult parseSignature(Object input, [ExpectedReply? expect]) {
    return _parseSolSignature(
      toUr(input),
      expect?.requestId == null ? null : normalizeRequestId(expect!.requestId!),
    );
  }
}

Uint8List _resolvePublicKey(SolSignRequestProps props) {
  final publicKey = props.publicKey;
  if (publicKey != null) {
    if (publicKey.length != 32) {
      throw EraSdkError('invalid-props', 'Solana public key must be 32 bytes');
    }
    return publicKey;
  }
  final address = props.address;
  if (address != null) {
    Uint8List decoded;
    try {
      decoded = base58Decode(address);
    } on Object {
      throw EraSdkError('invalid-props', 'Solana address is not base58');
    }
    if (decoded.length != 32) {
      throw EraSdkError(
          'invalid-props', 'Solana address does not decode to 32 bytes');
    }
    return decoded;
  }
  throw EraSdkError('invalid-props', 'provide publicKey or address');
}

SolSignatureResult _parseSolSignature(Ur ur, Uint8List? expectedRequestId) {
  requireUrType(ur, _replyTypes, 'sol-signature');
  final map = requireReplyMap(ur, 'sol-signature');
  final requestId =
      requireRequestIdEcho(map, 1, expectedRequestId, 'sol-signature');

  final raw = mapGet(map, 2);
  final value = raw == null ? null : stripTags(raw);
  // The firmware encodes the signature as CBOR bytes; a hex text string is
  // accepted too (older firmware sent that shape).
  Uint8List signature;
  if (value is CborBytes) {
    signature = value.value;
  } else if (value is CborText) {
    try {
      signature = hexToBytes(value.value);
    } on Object {
      throw EraSdkError(
          'malformed-reply', 'sol-signature signature is not hex');
    }
  } else {
    throw EraSdkError(
        'malformed-reply', 'sol-signature is missing the signature (key 2)');
  }
  if (signature.length != 64) {
    throw EraSdkError(
      'malformed-reply',
      'sol-signature signature is ${signature.length} bytes, expected 64',
    );
  }
  return SolSignatureResult(requestId: requestId, signature: signature);
}
