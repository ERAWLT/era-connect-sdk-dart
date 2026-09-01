import 'dart:typed_data';

import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../registry/keypath.dart';
import '../ur/ur.dart';
import 'shared.dart';

/// `eth-sign-request` dataType (CBOR key 3).
abstract final class EvmDataType {
  /// RLP-encoded transaction (the device sniffs EIP-1559/2930/legacy from the
  /// leading byte).
  static const int transaction = 1;

  /// EIP-712 typed data JSON (UTF-8 bytes).
  static const int typedData = 2;

  /// personal_sign / raw message bytes (EIP-191 prefix applied by the device).
  static const int personalMessage = 3;

  /// Typed (EIP-2718) transaction bytes — treated identically to
  /// [transaction].
  static const int typedTransaction = 4;
}

/// Properties of an EVM sign request.
class EvmSignRequestProps {
  const EvmSignRequestProps({
    this.requestId,
    required this.signData,
    required this.dataType,
    required this.path,
    required this.xfp,
    this.chainId,
    this.address,
    this.origin,
  });

  /// 16 bytes ([Uint8List]) or a UUID [String]; minted if omitted.
  final Object? requestId;

  /// RLP tx bytes, typed-data JSON UTF-8, or raw message bytes.
  final Uint8List signData;

  /// One of the [EvmDataType] values.
  final int dataType;

  /// Full signing path, e.g. `m/44'/60'/0'/0/0`.
  final String path;

  /// The account's source fingerprint from the linked wallet
  /// (`EraAccounts.xfpFor(...)`): a u32 [int] or an 8-hex [String].
  final Object xfp;

  /// Required for transactions (it derives the legal reply width). The device
  /// reads it as an unsigned 32-bit value — larger chain ids are refused
  /// here, because a silently truncated id would sign for a different chain.
  final int? chainId;

  /// 20-byte signer address ([Uint8List]) or a `0x` hex [String];
  /// recommended (enables verification helpers).
  final Object? address;

  /// Overrides the SDK-level origin label for this request.
  final String? origin;
}

/// A parsed `eth-signature` reply.
class EvmSignatureResult {
  const EvmSignatureResult({
    required this.requestId,
    required this.signature,
    required this.r,
    required this.s,
    required this.v,
    required this.recoveryId,
  });

  /// The echoed request id.
  final Uint8List requestId;

  /// Raw `r || s || v` exactly as the device sent it (may exceed 65 bytes for
  /// legacy EIP-155).
  final Uint8List signature;

  /// The 32-byte `r` scalar.
  final Uint8List r;

  /// The 32-byte `s` scalar.
  final Uint8List s;

  /// The recovery value AS SENT: parity (0/1) for typed transactions, 27/28
  /// for messages, already-EIP-155-encoded (`parity + chainId*2 + 35`) for
  /// legacy transactions. Do NOT re-apply the EIP-155 formula.
  final BigInt v;

  /// [v] folded to a plain 0/1 recovery id, whichever of the three forms it
  /// arrived in.
  final int recoveryId;
}

/// Over this size the device skips transaction decoding and falls back to
/// blind signing.
const int _blindSignThreshold = 32 * 1024;

const List<String> _replyTypes = ['eth-signature', 'evm-signature'];

/// The `Number.isSafeInteger` bound (2^53 - 1) the TypeScript SDK enforces.
const int _maxSafeInteger = 9007199254740991;

/// The EVM chain module: `eth-sign-request` out, `eth-signature` back.
class EvmChain {
  EvmChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Build an `eth-sign-request` (401). Reply: `eth-signature` (402).
  SignRequest<EvmSignatureResult> generateSignRequest(
      EvmSignRequestProps props) {
    final requestId = resolveRequestId(_context, props.requestId);
    final path = parsePath(props.path);
    final xfp = normalizeXfp(props.xfp);
    final isTransaction = props.dataType == EvmDataType.transaction ||
        props.dataType == EvmDataType.typedTransaction;

    final chainId = props.chainId;
    if (isTransaction && chainId == null) {
      throw EraSdkError(
          'invalid-props', 'chainId is required for transaction sign requests');
    }
    if (chainId != null) {
      if (chainId < 0 || chainId > _maxSafeInteger) {
        throw EraSdkError(
            'invalid-props', 'chainId must be a non-negative integer');
      }
      if (chainId > 0xffffffff) {
        throw EraSdkError(
          'invalid-props',
          "chainId $chainId exceeds the device's unsigned 32-bit range; "
              'a truncated id would produce a signature for a different chain',
        );
      }
    }

    final entries = <(int, CborValue)>[
      (1, cbBytes(requestId)),
      (2, cbBytes(props.signData)),
      (3, cbUint(props.dataType)),
    ];
    if (chainId != null) entries.add((4, cbUint(chainId)));
    entries.add((5, keypath304(path, xfp)));
    final address = props.address;
    if (address != null) entries.add((6, cbBytes(_normalizeAddress(address))));
    entries.add((7, cbText(props.origin ?? _context.origin)));

    final ur = Ur('eth-sign-request', cborEncode(cbMap(entries)));
    final warnings = <String>[];
    if (props.signData.length > _blindSignThreshold) {
      warnings.add('blind-sign-threshold');
    }

    final maxSigLength = 64 + _maxVBytes(props.dataType, chainId);
    return makeSignRequest(
      ur: ur,
      requestId: requestId,
      replyTypes: _replyTypes,
      warnings: warnings,
      context: _context,
      parse: (reply) => _parseEvmSignature(reply, requestId, maxSigLength),
    );
  }

  /// Parse an `eth-signature` standalone. Without `expect.requestId` the echo
  /// is returned but not validated — prefer `SignRequest.scanner().parse()`.
  EvmSignatureResult parseSignature(Object input, [ExpectedReply? expect]) {
    final expectedId = expect?.requestId;
    final expected = expectedId == null ? null : normalizeRequestId(expectedId);
    return _parseEvmSignature(toUr(input), expected, 64 + 8);
  }
}

Uint8List _normalizeAddress(Object address) {
  final Uint8List bytes;
  if (address is Uint8List) {
    bytes = address;
  } else if (address is String) {
    bytes = hexToBytes(address);
  } else {
    throw EraSdkError(
        'invalid-props', 'EVM address must be 20 bytes or a hex string');
  }
  if (bytes.length != 20) {
    throw EraSdkError('invalid-props', 'EVM address must be 20 bytes');
  }
  return bytes;
}

/// Width of the widest `v` the device can legitimately return.
///
/// For a legacy EIP-155 transaction `v = parity + chainId*2 + 35` — 2 bytes
/// past chain id 110, 4 bytes for Aurora. Messages and typed data always
/// answer with one byte (27/28). A flat ceiling either refuses genuine replies
/// on large-id chains or accepts implausibly wide values; the exact bound
/// comes from the request.
int _maxVBytes(int dataType, int? chainId) {
  if (dataType != EvmDataType.transaction &&
      dataType != EvmDataType.typedTransaction) {
    return 1;
  }
  if (chainId == null) return 8;
  var widest = BigInt.from(chainId) * BigInt.two + BigInt.from(36);
  if (widest < BigInt.from(28)) widest = BigInt.from(28);
  var bytes = 0;
  while (widest > BigInt.zero) {
    bytes += 1;
    widest >>= 8;
  }
  return bytes;
}

EvmSignatureResult _parseEvmSignature(
  Ur ur,
  Uint8List? expectedRequestId,
  int maxSigLength,
) {
  requireUrType(ur, _replyTypes, 'eth-signature');
  final map = requireReplyMap(ur, 'eth-signature');
  final requestId =
      requireRequestIdEcho(map, 1, expectedRequestId, 'eth-signature');
  final signature =
      requireSignatureBytes(mapGet(map, 2), 'eth-signature', 65, maxSigLength);

  final r = signature.sublist(0, 32);
  final s = signature.sublist(32, 64);
  final v = bytesToBigint(signature.sublist(64));
  final recoveryId = foldRecoveryId(v);
  if (recoveryId != 0 && recoveryId != 1) {
    throw EraSdkError(
      'malformed-reply',
      'eth-signature carries an implausible recovery value $v',
    );
  }
  return EvmSignatureResult(
    requestId: requestId,
    signature: signature,
    r: r,
    s: s,
    v: v,
    recoveryId: recoveryId,
  );
}

/// Fold parity / 27-28 / EIP-155 forms of `v` to a 0/1 recovery id.
int foldRecoveryId(BigInt v) {
  if (v >= BigInt.from(35)) return ((v - BigInt.from(35)) & BigInt.one).toInt();
  if (v >= BigInt.from(27)) return (v - BigInt.from(27)).toInt();
  return v.toInt();
}
