import 'dart:typed_data';

import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../registry/keypath.dart';
import '../tron_proto/gzip.dart';
import '../tron_proto/messages.dart';
import '../ur/ur.dart';
import 'shared.dart';

export '../tron_proto/messages.dart' show TronLatestBlock;

/// On-device display metadata for a Tron sign request.
class TronSignDisplay {
  const TronSignDisplay({
    this.token,
    this.contractAddress,
    this.from,
    this.to,
    this.value,
    this.memo,
    this.fee,
    this.decimals,
  });

  /// The token symbol shown on the device.
  final String? token;

  /// TRC-20 contract address, when the transfer is a token transfer.
  final String? contractAddress;

  /// Sender address (base58).
  final String? from;

  /// Recipient address (base58).
  final String? to;

  /// Human-readable amount string shown on the device.
  final String? value;

  /// Optional memo shown on the device.
  final String? memo;

  /// Fee in SUN; must fit a positive int32.
  final int? fee;

  /// Token decimals shown on the device. Defaults to 6.
  final int? decimals;
}

/// Inputs for [TronChain.generateSignRequest].
class TronSignRequestProps {
  const TronSignRequestProps({
    this.requestId,
    required this.rawData,
    required this.path,
    required this.xfp,
    required this.latestBlock,
    this.display,
    this.timestamp,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  /// Serialized `Transaction.raw_data` — THE signing source of truth. The
  /// device signs `sha256(rawData) = txID` and returns the transaction with
  /// `raw_data` unmodified.
  final Uint8List rawData;

  /// Full signing path, e.g. `m/44'/195'/0'/0/0`.
  final String path;

  /// The source fingerprint: a u32 [int] or an 8-hex [String].
  final Object xfp;

  /// Reference block context. Source it from a LIVE now-block query and pass
  /// the FULL 64-hex block id.
  final TronLatestBlock latestBlock;

  /// On-device display only; safe to omit for opaque dApp transactions.
  final TronSignDisplay? display;

  /// Request timestamp in Unix milliseconds. Defaults to 0.
  final int? timestamp;

  final String? origin;
}

/// A parsed `keystone-sign-result` reply.
class TronSignatureResult {
  const TronSignatureResult({
    required this.requestId,
    required this.txId,
    required this.rawTx,
    required this.signedTx,
  });

  final Uint8List requestId;

  /// `sha256(raw_data)` hex, as computed by the device.
  final String txId;

  /// Hex of the fully assembled signed transaction — broadcast as-is.
  final String rawTx;

  /// The signed frame split into `raw_data` + signatures (65-byte
  /// r||s||recovery each).
  final SignedTronTx signedTx;
}

/// Ceilings on the gzip blob a `keystone-sign-result` may carry. Tron is the
/// only chain whose reply is compressed, so it is the only one where a few
/// hundred scanned bytes can ask for an arbitrary allocation. Generous
/// multiples of the largest real device reply.
const int _maxCompressedBytes = 8 * 1024;
const int _maxInflatedBytes = 64 * 1024;

const List<String> _replyTypes = ['keystone-sign-result'];

final RegExp _hex64 = RegExp(r'^[0-9a-fA-F]{64}$');

/// Tron signing rides the structured `keystone-sign-request` (6101) envelope —
/// a gzip-compressed protobuf inside CBOR `{1: gzip(protobuf), 2: origin}`.
/// The registry's generic `tron-sign-request` (5101) is NOT accepted by the
/// device and gets no response; do not emit it.
class TronChain {
  TronChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Build a `keystone-sign-request` (6101). Reply: `keystone-sign-result`
  /// (6102).
  SignRequest<TronSignatureResult> generateSignRequest(
    TronSignRequestProps props,
  ) {
    final requestId = resolveRequestId(_context, props.requestId);
    parsePath(props.path); // validate shape; the wire carries the string form
    final xfp = normalizeXfp(props.xfp);
    if (props.rawData.isEmpty) {
      throw EraSdkError('invalid-props', 'rawData must not be empty');
    }
    if (!_hex64.hasMatch(props.latestBlock.hash)) {
      throw EraSdkError(
        'invalid-props',
        'latestBlock.hash must be the FULL 64-hex block id (the device slices ref_block_hash from it)',
      );
    }

    final proto = encodeSignRequestProto(TronSignRequestProto(
      // Zero-padded to eight characters: the firmware parses this string with
      // a hex reader that yields 0 for anything shorter than 4 bytes, and a
      // zero fingerprint fails validation — a wallet whose fingerprint starts
      // with a zero byte (1 in 256) could not sign at all without the pad.
      xfpHex: xfpToHex(xfp),
      signId: uuidStringify(requestId),
      hdPath: props.path,
      timestamp: props.timestamp ?? 0,
      decimals: props.display?.decimals ?? 6,
      token: props.display?.token ?? '',
      contractAddress: props.display?.contractAddress,
      from: props.display?.from,
      to: props.display?.to,
      memo: props.display?.memo,
      value: props.display?.value,
      fee: props.display?.fee,
      latestBlock: props.latestBlock,
      rawData: props.rawData,
    ));

    final ur = Ur(
      'keystone-sign-request',
      cborEncode(cbMap([
        (1, cbBytes(gzipCompress(proto))),
        (2, cbText(props.origin ?? _context.origin)),
      ])),
    );
    return makeSignRequest(
      ur: ur,
      requestId: requestId,
      replyTypes: _replyTypes,
      context: _context,
      parse: (reply) => _parseTronSignature(reply, requestId),
    );
  }

  /// Parse a `keystone-sign-result` standalone. Tron carries the request id
  /// INSIDE the protobuf (`signId`); passing `expect.requestId` is what makes
  /// the echo check possible here — prefer `SignRequest.scanner().parse()`.
  TronSignatureResult parseSignature(Object input, [ExpectedReply? expect]) {
    return _parseTronSignature(
      toUr(input),
      expect?.requestId == null ? null : normalizeRequestId(expect!.requestId!),
    );
  }
}

TronSignatureResult _parseTronSignature(
  Ur ur,
  Uint8List? expectedRequestId,
) {
  requireUrType(ur, _replyTypes, 'keystone-sign-result');
  final map = requireReplyMap(ur, 'keystone-sign-result');
  final compressed = asBytes(mapGet(map, 1));
  if (compressed == null) {
    throw EraSdkError(
      'malformed-reply',
      'keystone-sign-result is missing the payload (key 1)',
    );
  }
  if (compressed.length > _maxCompressedBytes) {
    throw EraSdkError(
      'limit-exceeded',
      'keystone-sign-result payload is ${compressed.length} bytes, over the $_maxCompressedBytes byte ceiling',
    );
  }
  final result =
      decodeSignResultProto(gunzipCapped(compressed, _maxInflatedBytes));

  // The signId echo is the ONLY anti-replay binding on this chain — the
  // device's own bytes are broadcast verbatim, so a stale reply that skipped
  // this check would finalize a payment the user did not approve now.
  if (expectedRequestId != null) {
    final expected = uuidStringify(expectedRequestId).toLowerCase();
    if (result.signId.toLowerCase() != expected) {
      throw EraSdkError(
        'request-id-mismatch',
        result.signId == ''
            ? 'keystone-sign-result does not echo the request id (signId)'
            : 'keystone-sign-result echoes a different request id — it answers another sign request, not this one',
      );
    }
  }
  if (result.rawTx == '') {
    throw EraSdkError(
      'malformed-reply',
      'keystone-sign-result has no signed transaction',
    );
  }
  final signedTx = splitSignedTronTx(result.rawTx);
  final requestId = expectedRequestId ?? _signIdToBytes(result.signId);
  return TronSignatureResult(
    requestId: requestId,
    txId: result.txId,
    rawTx: result.rawTx,
    signedTx: signedTx,
  );
}

Uint8List _signIdToBytes(String signId) {
  try {
    return normalizeRequestId(signId);
  } on Object {
    return Uint8List(16);
  }
}
