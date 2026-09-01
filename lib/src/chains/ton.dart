import 'dart:typed_data';

import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../registry/keypath.dart';
import '../ur/ur.dart';
import 'shared.dart';

/// `ton-sign-request` dataType (CBOR key 3).
abstract final class TonDataType {
  /// `signData` is a Bag-of-Cells; the device signs the ROOT CELL's
  /// representation hash.
  static const int transaction = 1;

  /// TON Connect proof: the device signs
  /// `sha256(0xFFFF || "ton-connect" || sha256(signData))`.
  static const int tonProof = 2;
}

/// Properties for [TonChain.generateSignRequest].
class TonSignRequestProps {
  const TonSignRequestProps({
    this.requestId,
    required this.signData,
    this.dataType,
    required this.path,
    required this.xfp,
    this.address,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  /// BoC bytes (transaction) or the raw proof payload (tonProof).
  final Uint8List signData;

  /// A [TonDataType] value. Defaults to [TonDataType.transaction].
  final int? dataType;

  /// The account path, e.g. `m/44'/607'/0'` (V4R2 and V5R1 share it — the
  /// wallet-contract version affects only the address).
  final String path;

  /// Master fingerprint: u32 [int] or 8-hex [String].
  final Object xfp;

  /// User-friendly bounceable address TEXT (`UQ…`/`EQ…`) — shown on the
  /// device.
  final String? address;

  /// Overrides the config-level origin for this request.
  final String? origin;
}

/// A parsed `ton-signature` reply.
class TonSignatureResult {
  const TonSignatureResult({required this.requestId, required this.signature});

  /// The echoed request id, normalized to 16 bytes.
  final Uint8List requestId;

  /// 64-byte Ed25519 signature over the digest for the request's dataType.
  final Uint8List signature;
}

const List<String> _replyTypes = ['ton-signature'];

/// TON: `ton-sign-request` (7201) / `ton-signature` (7202).
class TonChain {
  TonChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Build a `ton-sign-request` (7201). Reply: `ton-signature` (7202).
  SignRequest<TonSignatureResult> generateSignRequest(
    TonSignRequestProps props,
  ) {
    final requestId = resolveRequestId(_context, props.requestId);
    final path = parsePath(props.path);
    final xfp = normalizeXfp(props.xfp);
    if (props.signData.isEmpty) {
      throw EraSdkError('invalid-props', 'signData must not be empty');
    }

    final entries = <(int, CborValue)>[
      // TON ecosystem quirk: the request id travels as the ASCII BYTES of the
      // hyphenated UUID string, wrapped in tag 37 (that is what Tonkeeper-
      // style integrations emit and what the device echoes back verbatim).
      (1, cbTag(37, cbBytes(utf8Encode(uuidStringify(requestId))))),
      (2, cbBytes(props.signData)),
      (3, cbUint(props.dataType ?? TonDataType.transaction)),
      (4, keypath304(path, xfp)),
    ];
    final address = props.address;
    if (address != null) entries.add((5, cbText(address)));
    entries.add((6, cbText(props.origin ?? _context.origin)));

    final ur = Ur('ton-sign-request', cborEncode(cbMap(entries)));
    return makeSignRequest(
      ur: ur,
      requestId: requestId,
      replyTypes: _replyTypes,
      context: _context,
      parse: (reply) => _parseTonSignature(reply, requestId),
    );
  }

  /// Parse a `ton-signature` standalone. Prefer `SignRequest.scanner().parse()`.
  TonSignatureResult parseSignature(Object input, [ExpectedReply? expect]) {
    final expectedId = expect?.requestId;
    return _parseTonSignature(
      toUr(input),
      expectedId == null ? null : normalizeRequestId(expectedId),
    );
  }
}

TonSignatureResult _parseTonSignature(Ur ur, Uint8List? expectedRequestId) {
  requireUrType(ur, _replyTypes, 'ton-signature');
  final map = requireReplyMap(ur, 'ton-signature');

  // The device echoes the request id BYTES verbatim (tag-37 wrapped). On this
  // chain those bytes are normally the ASCII of the UUID string; a bare
  // 16-byte binary echo is accepted too for forward compatibility.
  final echoedValue = mapGet(map, 1);
  final echoed = echoedValue == null ? null : stripTags(echoedValue);
  if (echoed is! CborBytes) {
    throw EraSdkError(
      'malformed-reply',
      'ton-signature does not echo the request id (key 1)',
    );
  }
  final requestId = _normalizeEchoedId(echoed.value);
  if (expectedRequestId != null) {
    if (requestId == null || !equalBytes(requestId, expectedRequestId)) {
      throw EraSdkError(
        'request-id-mismatch',
        'ton-signature echoes a different request id — it answers another sign request, not this one',
      );
    }
  }

  final sigValue = mapGet(map, 2);
  final sig = sigValue == null ? null : stripTags(sigValue);
  if (sig is! CborBytes) {
    throw EraSdkError(
      'malformed-reply',
      'ton-signature is missing the signature (key 2)',
    );
  }
  if (sig.value.length != 64) {
    throw EraSdkError(
      'malformed-reply',
      'ton-signature signature is ${sig.value.length} bytes, expected 64',
    );
  }
  return TonSignatureResult(
    requestId: requestId ?? Uint8List(16),
    signature: sig.value,
  );
}

/// ASCII-UUID-string bytes (36) or raw binary (16) → 16-byte id; null if
/// neither.
Uint8List? _normalizeEchoedId(Uint8List echoed) {
  if (echoed.length == 16) return echoed;
  if (echoed.length == 36) {
    final text = StringBuffer();
    for (final b in echoed) {
      if (b > 0x7f) return null;
      text.writeCharCode(b);
    }
    try {
      return normalizeRequestId(text.toString());
    } on EraSdkError {
      return null;
    }
  }
  return null;
}
