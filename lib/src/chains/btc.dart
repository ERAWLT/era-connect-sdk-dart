import 'dart:convert' show base64Decode, base64Encode;
import 'dart:typed_data';

import '../cbor/decode.dart';
import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../registry/keypath.dart';
import '../ur/ur.dart';
import 'shared.dart';

/// Bitcoin-family coins the PSBT path signs for (BCH rides its own FORKID
/// envelope: the `bch` module).
enum PsbtCoin { btc, ltc, doge, dash }

/// `crypto-psbt-extend` coin ids (the device's own coin-type table).
const Map<PsbtCoin, int> _psbtExtendCoinId = {
  PsbtCoin.ltc: 2,
  PsbtCoin.doge: 3,
  PsbtCoin.dash: 5,
};

/// CBOR `dataType` values for `btc-sign-request`.
abstract final class BtcDataType {
  static const int message = 1;
}

/// Inputs for [BtcChain.generatePsbtSignRequest].
class BtcPsbtSignRequestProps {
  const BtcPsbtSignRequestProps({required this.psbt, this.coin});

  /// Raw PSBT v0 bytes (BIP-174). The device's signer relies on the global
  /// UNSIGNED_TX.
  final Uint8List psbt;

  /// [PsbtCoin.btc] (default) rides plain `crypto-psbt`; Litecoin/Dogecoin/
  /// Dash ride `crypto-psbt-extend` — the same PSBT plus the coin id,
  /// answered in kind. Build the PSBT with the coin's own derivation paths
  /// (LTC `m/84'/2'/…`, DOGE `m/44'/3'/…`, DASH `m/44'/5'/…`).
  final PsbtCoin? coin;
}

/// A parsed `crypto-psbt` / `crypto-psbt-extend` reply.
class BtcPsbtResult {
  const BtcPsbtResult({required this.psbt});

  /// The signed, NOT finalized PSBT. Finalize + broadcast with your own
  /// stack.
  final Uint8List psbt;
}

/// Inputs for [BtcChain.generateMessageSignRequest].
class BtcMessageSignRequestProps {
  const BtcMessageSignRequestProps({
    this.requestId,
    required this.message,
    required this.path,
    required this.xfp,
    required this.address,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  final Uint8List message;

  /// Full signing path, e.g. `m/84'/0'/0'/0/0`.
  final String path;

  /// The master fingerprint: a u32 [int] or an 8-hex [String].
  final Object xfp;

  /// The signing address. Firmware 2.1.0+ signs for BIP-44/49/84 address
  /// kinds (Taproot is refused — BIP-137 has no header range for it); OLDER
  /// firmware signs legacy P2PKH (`1...`) only and answers a segwit address
  /// with `empty-signature`.
  final String address;

  final String? origin;
}

/// A parsed `btc-signature` reply.
class BtcMessageSignatureResult {
  const BtcMessageSignatureResult({
    required this.requestId,
    required this.signature,
    required this.signatureBase64,
    this.publicKey,
  });

  final Uint8List requestId;

  /// Raw 65-byte BIP-137 signature (header + r + s).
  final Uint8List signature;

  /// The base64 form dApps and verifiers expect.
  final String signatureBase64;

  final Uint8List? publicKey;
}

const List<String> _psbtReplyTypes = ['crypto-psbt'];
const List<String> _psbtExtendReplyTypes = [
  'crypto-psbt-extend',
  'crypto-psbt'
];
const List<String> _messageReplyTypes = ['btc-signature'];

/// The Bitcoin-family chain module: PSBTs and BIP-137 message signing.
class BtcChain {
  BtcChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Build a `crypto-psbt` (310) request: the UR payload is a bare CBOR byte
  /// string of the raw PSBT — no map, no request id, no origin.
  ///
  /// BECAUSE the protocol carries no request id on this path, the reply is
  /// bound to the request only by its content: after parsing, compare the
  /// returned PSBT's unsigned transaction against the one you sent
  /// (`verifySignedPsbt` from the verify library). Skipping that check
  /// re-opens replay of a stale signed PSBT.
  SignRequest<BtcPsbtResult> generatePsbtSignRequest(
    BtcPsbtSignRequestProps props,
  ) {
    if (props.psbt.isEmpty) {
      throw EraSdkError('invalid-props', 'psbt must not be empty');
    }
    final coin = props.coin ?? PsbtCoin.btc;
    final ur = coin == PsbtCoin.btc
        ? Ur('crypto-psbt', cborEncode(cbBytes(props.psbt)))
        : Ur(
            'crypto-psbt-extend',
            cborEncode(
              cbMap([
                (1, cbBytes(props.psbt)),
                (2, cbUint(_psbtExtendCoinId[coin]!)),
              ]),
            ),
          );
    return makeSignRequest(
      ur: ur,
      replyTypes:
          coin == PsbtCoin.btc ? _psbtReplyTypes : _psbtExtendReplyTypes,
      context: _context,
      parse: parsePsbt,
    );
  }

  /// Parse a `crypto-psbt` / `crypto-psbt-extend` reply: the signed (not
  /// finalized) PSBT bytes.
  BtcPsbtResult parsePsbt(Object input) {
    final ur = toUr(input);
    requireUrType(ur, _psbtExtendReplyTypes, 'crypto-psbt');
    CborValue decoded;
    try {
      decoded = cborDecode(ur.cbor);
    } on EraSdkError catch (e) {
      throw EraSdkError('malformed-cbor', 'crypto-psbt reply: ${e.message}');
    } catch (e) {
      throw EraSdkError('malformed-cbor', 'crypto-psbt reply: $e');
    }
    // Plain form: a bare byte string. Extend form: {1: psbt, 2: coinId}.
    final bytes = asBytes(decoded) ?? asBytes(mapGet(decoded, 1));
    if (bytes == null) {
      throw EraSdkError(
          'malformed-reply', 'crypto-psbt reply is not a byte string');
    }
    if (bytes.isEmpty) {
      throw EraSdkError('malformed-reply', 'crypto-psbt reply is empty');
    }
    return BtcPsbtResult(psbt: bytes);
  }

  /// Build a `btc-sign-request` (8101) for message signing. Reply:
  /// `btc-signature` (8102).
  SignRequest<BtcMessageSignatureResult> generateMessageSignRequest(
    BtcMessageSignRequestProps props,
  ) {
    final requestId = resolveRequestId(_context, props.requestId);
    final path = parsePath(props.path);
    final xfp = normalizeXfp(props.xfp);

    final ur = Ur(
      'btc-sign-request',
      cborEncode(
        cbMap([
          // Tag-37-wrapped on this chain (per-chain firmware policy).
          (1, cbTag(37, cbBytes(requestId))),
          (2, cbBytes(props.message)),
          (3, cbUint(BtcDataType.message)),
          (4, cbArray([keypath304(path, xfp)])),
          (5, cbArray([cbText(props.address)])),
          (6, cbText(props.origin ?? _context.origin)),
        ]),
      ),
    );
    return makeSignRequest(
      ur: ur,
      requestId: requestId,
      replyTypes: _messageReplyTypes,
      context: _context,
      parse: (reply) => _parseMessageSignature(reply, requestId),
    );
  }

  /// Parse a `btc-signature` standalone. Prefer `SignRequest.scanner().parse()`.
  BtcMessageSignatureResult parseMessageSignature(
    Object input, [
    ExpectedReply? expect,
  ]) {
    final expectedId = expect?.requestId;
    return _parseMessageSignature(
      toUr(input),
      expectedId == null ? null : normalizeRequestId(expectedId),
    );
  }
}

BtcMessageSignatureResult _parseMessageSignature(
  Ur ur,
  Uint8List? expectedRequestId,
) {
  requireUrType(ur, _messageReplyTypes, 'btc-signature');
  final map = requireReplyMap(ur, 'btc-signature');
  final requestId =
      requireRequestIdEcho(map, 1, expectedRequestId, 'btc-signature');

  final sigValue = asBytes(mapGet(map, 2));
  if (sigValue == null) {
    throw EraSdkError(
        'malformed-reply', 'btc-signature is missing the signature (key 2)');
  }
  // The device answers a message request for an address its signer cannot
  // handle with an EMPTY signature. On firmware 2.1.0+ that is Taproot only;
  // older firmware refuses everything but legacy P2PKH this way.
  if (sigValue.isEmpty) {
    throw EraSdkError(
      'empty-signature',
      'the device returned an empty signature — the address kind is not message-signable '
          'on this firmware (older firmware: legacy P2PKH only; 2.1.0+: everything but Taproot)',
    );
  }

  // Firmware 2.1.0+ sends the raw 65-byte signature; older firmware sends
  // the ASCII of its base64. Accept both: try the double decode first, fall
  // back to the raw bytes.
  Uint8List signature;
  try {
    signature = _base64DecodeStrict(asciiDecode(sigValue));
  } catch (_) {
    signature = sigValue;
  }
  if (signature.length != 65) {
    if (sigValue.length == 65) {
      signature = sigValue;
    } else {
      throw EraSdkError(
        'malformed-reply',
        'btc-signature payload does not decode to a 65-byte BIP-137 signature '
            '(${sigValue.length} bytes on the wire)',
      );
    }
  }
  return BtcMessageSignatureResult(
    requestId: requestId,
    signature: signature,
    signatureBase64: base64Encode(signature),
    publicKey: asBytes(mapGet(map, 3)),
  );
}

final RegExp _base64Grammar = RegExp(r'^[A-Za-z0-9+/]*={0,2}$');

/// Strict standard-alphabet base64 decode. The TypeScript SDK decodes the
/// device quirk with `@scure/base`, which refuses the URL-safe alphabet;
/// `dart:convert` alone accepts BOTH alphabets, so the alphabet is pinned
/// here first (padding placement and non-zero padding bits are already
/// refused by `base64Decode` itself).
Uint8List _base64DecodeStrict(String text) {
  if (text.length % 4 != 0 || !_base64Grammar.hasMatch(text)) {
    throw const FormatException('not canonical base64');
  }
  return base64Decode(text);
}
