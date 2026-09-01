import 'dart:typed_data';

import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../registry/keypath.dart';
import '../ur/ur.dart';
import 'shared.dart';

/// `cosmos-sign-request` dataType (CBOR key 3).
abstract final class CosmosDataType {
  /// SIGN_MODE_LEGACY_AMINO_JSON — `signData` is the canonical JSON (UTF-8
  /// bytes).
  static const int amino = 1;

  /// SIGN_MODE_DIRECT — `signData` is the protobuf-encoded SignDoc.
  static const int direct = 2;

  /// SIGN_MODE_TEXTUAL (rare).
  static const int textual = 3;

  /// ADR-036 arbitrary-message signing.
  static const int message = 4;
}

/// Props for [CosmosChain.generateSignRequest].
class CosmosSignRequestProps {
  const CosmosSignRequestProps({
    this.requestId,
    required this.signData,
    required this.dataType,
    required this.path,
    required this.xfp,
    this.address,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  /// SignDoc bytes: canonical Amino JSON (UTF-8) or protobuf SignDoc.
  final Uint8List signData;

  /// One of the [CosmosDataType] values.
  final int dataType;

  /// Full signing path, e.g. `m/44'/118'/0'/0/0`.
  final String path;

  /// Master fingerprint: u32 [int] or 8-hex [String].
  final Object xfp;

  /// Bech32 signer address — device display.
  final String? address;

  /// Per-request origin override.
  final String? origin;
}

/// Ethermint-family chains (Injective, Evmos, Dymension, …) sign with
/// keccak-256 over Ethereum-style keys (`m/44'/60'/...`) and travel as an
/// `evm-sign-request` instead.
class EthermintSignRequestProps {
  const EthermintSignRequestProps({
    this.requestId,
    required this.signData,
    required this.dataType,
    required this.path,
    required this.xfp,
    this.address,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  /// SignDoc bytes: canonical Amino JSON (UTF-8) or protobuf SignDoc.
  final Uint8List signData;

  /// [CosmosDataType.amino] or [CosmosDataType.direct] — the SignDoc
  /// encoding.
  final int dataType;

  /// e.g. `m/44'/60'/0'/0/0`.
  final String path;

  /// Master fingerprint: u32 [int] or 8-hex [String].
  final Object xfp;

  /// The `0x…` signer address string — travels as its ASCII bytes on this
  /// wire.
  final String? address;

  /// Per-request origin override.
  final String? origin;
}

/// A parsed `cosmos-signature`/`evm-signature` reply.
class CosmosSignatureResult {
  const CosmosSignatureResult({
    required this.requestId,
    required this.signature,
    this.publicKey,
  });

  /// The echoed request id.
  final Uint8List requestId;

  /// 64-byte compact secp256k1 signature (r || s).
  final Uint8List signature;

  /// 33-byte compressed public key (absent on the `evm-signature` reply
  /// shape).
  final Uint8List? publicKey;
}

const List<String> _cosmosReplyTypes = ['cosmos-signature'];
const List<String> _ethermintReplyTypes = ['evm-signature'];

/// EvmSignDataType on the wire: 2 = Amino SignDoc, 3 = Direct SignDoc.
const Map<int, int> _ethermintWireType = {1: 2, 2: 3};

/// Cosmos-SDK zones (and their Ethermint cousins) over the ERA wire.
class CosmosChain {
  CosmosChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Build a `cosmos-sign-request` (4101). Reply: `cosmos-signature` (4102).
  SignRequest<CosmosSignatureResult> generateSignRequest(
      CosmosSignRequestProps props) {
    final requestId = resolveRequestId(_context, props.requestId);
    final path = parsePath(props.path);
    final xfp = normalizeXfp(props.xfp);
    if (props.signData.isEmpty) {
      throw EraSdkError('invalid-props', 'signData must not be empty');
    }

    final entries = <(int, CborValue)>[
      (1, cbTag(37, cbBytes(requestId))),
      (2, cbBytes(props.signData)),
      (3, cbUint(props.dataType)),
      (4, cbArray([keypath304(path, xfp)])),
    ];
    final address = props.address;
    if (address != null) entries.add((5, cbArray([cbText(address)])));
    entries.add((6, cbText(props.origin ?? _context.origin)));

    final ur = Ur('cosmos-sign-request', cborEncode(cbMap(entries)));
    return makeSignRequest(
      ur: ur,
      requestId: requestId,
      replyTypes: _cosmosReplyTypes,
      context: _context,
      parse: (reply) =>
          _parseCosmosSignature(reply, requestId, _cosmosReplyTypes),
    );
  }

  /// Build an `evm-sign-request` (4101, the Ethermint shape) for
  /// Injective/Evmos/Dymension-style chains. Reply: `evm-signature` (4102).
  /// The digest on these chains is keccak-256 — see `verifyCosmosSignature`.
  SignRequest<CosmosSignatureResult> generateEthermintSignRequest(
      EthermintSignRequestProps props) {
    final requestId = resolveRequestId(_context, props.requestId);
    final path = parsePath(props.path);
    final xfp = normalizeXfp(props.xfp);
    if (props.signData.isEmpty) {
      throw EraSdkError('invalid-props', 'signData must not be empty');
    }
    final wireType = _ethermintWireType[props.dataType];
    if (wireType == null) {
      throw EraSdkError(
          'invalid-props', 'Ethermint requests are Amino or Direct only');
    }

    final entries = <(int, CborValue)>[
      (1, cbTag(37, cbBytes(requestId))),
      (2, cbBytes(props.signData)),
      (3, cbUint(wireType)),
      // customChainId — 0, the chain resolves from the SignDoc.
      (4, cbUint(0)),
      (5, keypath304(path, xfp)),
    ];
    final address = props.address;
    if (address != null) {
      // ASCII of the 0x string.
      entries.add((6, cbBytes(utf8Encode(address))));
    }
    entries.add((7, cbText(props.origin ?? _context.origin)));

    final ur = Ur('evm-sign-request', cborEncode(cbMap(entries)));
    return makeSignRequest(
      ur: ur,
      requestId: requestId,
      replyTypes: _ethermintReplyTypes,
      context: _context,
      parse: (reply) =>
          _parseCosmosSignature(reply, requestId, _ethermintReplyTypes),
    );
  }

  /// Parse a `cosmos-signature`/`evm-signature` standalone.
  CosmosSignatureResult parseSignature(Object input, [ExpectedReply? expect]) {
    final expectedId = expect?.requestId;
    return _parseCosmosSignature(
      toUr(input),
      expectedId == null ? null : normalizeRequestId(expectedId),
      const ['cosmos-signature', 'evm-signature'],
    );
  }
}

CosmosSignatureResult _parseCosmosSignature(
  Ur ur,
  Uint8List? expectedRequestId,
  List<String> replyTypes,
) {
  requireUrType(ur, replyTypes, 'cosmos-signature');
  final map = requireReplyMap(ur, ur.type);
  final requestId = requireRequestIdEcho(map, 1, expectedRequestId, ur.type);
  final signature = asBytes(mapGet(map, 2));
  if (signature == null || signature.length != 64) {
    throw EraSdkError(
      'malformed-reply',
      '${ur.type} signature is ${signature?.length ?? 0} bytes, '
          'expected 64 (compact r||s)',
    );
  }
  final publicKey = asBytes(mapGet(map, 3));
  if (publicKey != null && publicKey.length != 33) {
    throw EraSdkError(
        'malformed-reply', '${ur.type} public key is not 33 bytes');
  }
  return CosmosSignatureResult(
    requestId: requestId,
    signature: signature,
    publicKey: publicKey,
  );
}
