import 'dart:convert';
import 'dart:typed_data';

import '../cbor/decode.dart';
import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../ur/ur.dart';
import 'shared.dart';

/// XRP rides the XRP Toolkit convention: an untyped `ur:bytes` whose CBOR
/// payload is the transaction JSON (request) or the canonical signed XRPL
/// binary (reply). There is NO request id and NO chain-specific UR type — the
/// content itself is the only binding, which is why `verifyXrpSignature`
/// (from the verify library) is not optional on this chain.
class XrpSignRequestProps {
  const XrpSignRequestProps({required this.transaction});

  /// The unsigned transaction JSON — a `Map<String, dynamic>` or a JSON
  /// [String]. MUST already carry `SigningPubKey` (the device signs with
  /// `m/44'/144'/0'/0/0` — put THAT key's hex here), `TransactionType`, a
  /// classic `r…` `Account`, `Fee` and `Sequence`.
  final Object transaction;
}

/// A parsed `ur:bytes` reply.
class XrpSignatureResult {
  const XrpSignatureResult({required this.signedTx});

  /// The canonical signed XRPL binary transaction — submit it verbatim.
  final Uint8List signedTx;
}

const List<String> _replyTypes = ['bytes'];

/// XRP signing over the ERA UR protocol.
class XrpChain {
  XrpChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Wrap the tx JSON in the `ur:bytes` request shape. Reply: `ur:bytes` with the signed binary.
  SignRequest<XrpSignatureResult> generateSignRequest(
      XrpSignRequestProps props) {
    final transaction = props.transaction;
    final String text =
        transaction is String ? transaction : jsonEncode(transaction);
    Object? decodedJson;
    try {
      decodedJson = jsonDecode(text);
    } on FormatException {
      throw EraSdkError('invalid-props', 'transaction is not valid JSON');
    }
    final parsed = decodedJson is Map<String, dynamic>
        ? decodedJson
        : const <String, dynamic>{};
    // Mirror the device's own acceptance gate so a refusal happens HERE with
    // a reason, not silently on the hardware.
    if (parsed['TransactionType'] is! String) {
      throw EraSdkError('invalid-props', 'transaction needs a TransactionType');
    }
    final account = parsed['Account'];
    if (account is! String || !account.startsWith('r')) {
      throw EraSdkError(
          'invalid-props', 'transaction needs a classic r… Account');
    }
    final signingPubKey = parsed['SigningPubKey'];
    if (signingPubKey is! String || signingPubKey.isEmpty) {
      throw EraSdkError(
        'invalid-props',
        "transaction needs SigningPubKey — the device signs with m/44'/144'/0'/0/0",
      );
    }
    if (!parsed.containsKey('Fee') || !parsed.containsKey('Sequence')) {
      throw EraSdkError('invalid-props', 'transaction needs Fee and Sequence');
    }

    final ur = Ur('bytes', cborEncode(cbBytes(utf8Encode(text))));
    return makeSignRequest<XrpSignatureResult>(
      ur: ur,
      replyTypes: _replyTypes,
      context: _context,
      parse: (reply) => parseSignature(reply),
    );
  }

  /// Parse the `ur:bytes` reply into the signed binary transaction.
  XrpSignatureResult parseSignature(Object input) {
    final ur = toUr(input);
    requireUrType(ur, _replyTypes, 'xrp reply');
    CborValue decoded;
    try {
      decoded = cborDecode(ur.cbor);
    } on EraSdkError catch (e) {
      throw EraSdkError('malformed-cbor', 'xrp reply: ${e.message}');
    } catch (e) {
      throw EraSdkError('malformed-cbor', 'xrp reply: $e');
    }
    final bytes = asBytes(decoded);
    if (bytes == null || bytes.isEmpty) {
      throw EraSdkError(
          'malformed-reply', 'xrp reply carries no signed transaction bytes');
    }
    return XrpSignatureResult(signedTx: bytes);
  }
}
