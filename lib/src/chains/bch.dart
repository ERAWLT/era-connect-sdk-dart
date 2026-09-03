import 'dart:typed_data';

import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../registry/keypath.dart';
import '../tron_proto/gzip.dart';
import '../tron_proto/messages.dart';
import '../ur/ur.dart';
import 'cashaddr.dart';
import 'shared.dart';

export 'cashaddr.dart'
    show
        CashAddrPayload,
        CashAddrType,
        cashaddrPrefix,
        decodeCashAddr,
        encodeCashAddr;

/// One UTXO the transaction spends. P2PKH only — that is what the device signs.
class BchTxInput {
  const BchTxInput({
    required this.txid,
    required this.index,
    required this.value,
    required this.publicKey,
    required this.path,
  });

  /// Display-order (big-endian) txid of the UTXO, 64 hex chars.
  final String txid;

  /// Output index of the UTXO.
  final int index;

  /// UTXO value in satoshis ([int] or [BigInt]) — part of the BIP-143
  /// sighash, so it MUST be exact.
  final Object value;

  /// The compressed (33-byte) public key that owns the UTXO ([Uint8List] or
  /// hex [String]).
  final Object publicKey;

  /// Full derivation path of that key, e.g. `m/44'/145'/0'/0/0`.
  final String path;
}

/// One output of a BCH sign request.
class BchTxOutput {
  const BchTxOutput({
    required this.address,
    required this.value,
    this.isChange,
    this.changeAddressPath,
  });

  /// CashAddr (P2PKH or P2SH), with or without the `bitcoincash:` prefix.
  final String address;

  /// Output value in satoshis ([int] or [BigInt]).
  final Object value;

  /// Marks the output as change on the device screen. Display only.
  final bool? isChange;

  /// Shown with the change output; the address above is still what is paid.
  final String? changeAddressPath;
}

/// Inputs for [BchChain.generateSignRequest].
class BchSignRequestProps {
  const BchSignRequestProps({
    this.requestId,
    required this.inputs,
    required this.outputs,
    required this.fee,
    this.dustThreshold,
    this.memo,
    required this.xfp,
    this.timestamp,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  /// The UTXOs being spent.
  final List<BchTxInput> inputs;

  /// Every output — change included — carries a real CashAddr.
  final List<BchTxOutput> outputs;

  /// Fee in satoshis ([int] or [BigInt]). Must equal
  /// `sum(inputs) - sum(outputs)` exactly.
  final Object fee;

  /// Dust threshold shown on the device; defaults to 546.
  final int? dustThreshold;

  /// Optional memo shown on the device.
  final String? memo;

  /// The source fingerprint: a u32 [int] or an 8-hex [String].
  final Object xfp;

  /// Milliseconds timestamp shown in the device log; 0 omits it.
  final int? timestamp;

  final String? origin;
}

/// A parsed `keystone-sign-result` reply.
class BchSignatureResult {
  const BchSignatureResult({
    required this.requestId,
    required this.txId,
    required this.rawTx,
  });

  final Uint8List requestId;

  /// Display-order txid of the signed transaction, as computed by the device.
  final String txId;

  /// Hex of the fully signed transaction — broadcast as-is.
  final String rawTx;
}

const int _maxCompressedBytes = 8 * 1024;
const int _maxInflatedBytes = 64 * 1024;

const List<String> _replyTypes = ['keystone-sign-result'];

/// Satoshi amounts must stay exact in a double; anything above is refused.
final BigInt _maxSatoshi = BigInt.from(2100000000000000); // 21M coins

/// The 2^53-1 safe-integer bound web builds impose — kept for
/// web (dart2js) parity, where int precision ends at 2^53 too.
const int _maxSafeInteger = 9007199254740991;

BigInt _toSatoshi(Object value, String label) {
  final BigInt v;
  if (value is BigInt) {
    v = value;
  } else if (value is int) {
    // Refuse amounts past 2^53: a web build cannot represent them exactly,
    // and a satoshi amount that silently loses precision is a wrong payment.
    if (value > _maxSafeInteger || value < -_maxSafeInteger) {
      throw EraSdkError(
        'invalid-props',
        '$label must be an integer satoshi amount',
      );
    }
    v = BigInt.from(value);
  } else {
    throw EraSdkError(
      'invalid-props',
      '$label must be an integer satoshi amount',
    );
  }
  if (v <= BigInt.zero || v > _maxSatoshi) {
    throw EraSdkError(
      'invalid-props',
      '$label must be a positive satoshi amount',
    );
  }
  return v;
}

final RegExp _compressedKeyHex = RegExp(r'^0[23][0-9a-f]{64}$');
final RegExp _txidHex = RegExp(r'^[0-9a-fA-F]{64}$');
final RegExp _anyHex = RegExp(r'^[0-9a-fA-F]+$');

String _toPublicKeyHex(Object publicKey, String label) {
  final String hex;
  if (publicKey is String) {
    hex = publicKey.toLowerCase();
  } else if (publicKey is Uint8List) {
    hex = bytesToHex(publicKey);
  } else {
    throw EraSdkError(
      'invalid-props',
      '$label must be a 33-byte compressed public key',
    );
  }
  if (!_compressedKeyHex.hasMatch(hex)) {
    throw EraSdkError(
      'invalid-props',
      '$label must be a 33-byte compressed public key',
    );
  }
  return hex;
}

/// Bitcoin Cash signing rides the structured `keystone-sign-request` (6101)
/// envelope, NOT the PSBT path: the device's PSBT signer cannot apply the
/// `SIGHASH_FORKID` (0x41) sighash BCH consensus requires, so a dedicated
/// FORKID signer sits behind this envelope instead. The SDK therefore builds
/// the transaction container from structured inputs/outputs here — the one
/// chain where it is more than a transport.
///
/// The device derives each input's signing key from its `path`, computes the
/// BIP-143 sighash with FORKID over version-1/locktime-0/sequence-0xfffffffd
/// legacy serialization, and returns the COMPLETE signed transaction.
class BchChain {
  BchChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Build a `keystone-sign-request` (6101). Reply: `keystone-sign-result` (6102).
  SignRequest<BchSignatureResult> generateSignRequest(
      BchSignRequestProps props) {
    final requestId = resolveRequestId(_context, props.requestId);
    final xfp = normalizeXfp(props.xfp);
    if (props.inputs.isEmpty) {
      throw EraSdkError('invalid-props', 'at least one input is required');
    }
    if (props.outputs.isEmpty) {
      throw EraSdkError('invalid-props', 'at least one output is required');
    }

    var inputSum = BigInt.zero;
    final inputs = <BchProtoInput>[];
    for (var i = 0; i < props.inputs.length; i++) {
      final input = props.inputs[i];
      if (!_txidHex.hasMatch(input.txid)) {
        throw EraSdkError(
            'invalid-props', 'input $i: txid must be 64 hex chars');
      }
      if (input.index < 0) {
        throw EraSdkError(
          'invalid-props',
          'input $i: index must be a non-negative integer',
        );
      }
      parsePath(input.path); // validate shape; the wire carries the string form
      final value = _toSatoshi(input.value, 'input $i value');
      inputSum += value;
      inputs.add(BchProtoInput(
        txidHex: input.txid.toLowerCase(),
        index: input.index,
        value: value,
        publicKeyHex: _toPublicKeyHex(input.publicKey, 'input $i publicKey'),
        ownerKeyPath: input.path,
      ));
    }

    var outputSum = BigInt.zero;
    final outputs = <BchProtoOutput>[];
    for (var i = 0; i < props.outputs.length; i++) {
      final output = props.outputs[i];
      // Decode AND re-encode: the wire must carry the canonical lowercase
      // form. The device's own parser prepends a lowercase prefix before
      // decoding, so the spec's all-uppercase (QR alphanumeric) spelling
      // turns mixed-case there, is rejected — and the rejection FAILS OPEN
      // into a zero pubkey hash, i.e. a signed burn output. Never forward
      // the caller's spelling.
      final decoded = decodeCashAddr(output.address);
      final value = _toSatoshi(output.value, 'output $i value');
      outputSum += value;
      final changeAddressPath = output.changeAddressPath;
      if (changeAddressPath != null) parsePath(changeAddressPath);
      outputs.add(BchProtoOutput(
        address: encodeCashAddr(
          decoded.type,
          decoded.hash,
          withPrefix: output.address.contains(':'),
        ),
        value: value,
        isChange: output.isChange ?? false,
        changeAddressPath: changeAddressPath,
      ));
    }

    // The fee field is what the device SHOWS the user, but the fee the network
    // takes is inputs minus outputs — an inconsistent pair would put a lie on
    // the confirmation screen, so it is refused here.
    final fee = _toSatoshi(props.fee, 'fee');
    if (inputSum != outputSum + fee) {
      throw EraSdkError(
        'invalid-props',
        'fee mismatch: inputs ($inputSum) minus outputs ($outputSum) is '
            '${inputSum - outputSum}, but fee says $fee',
      );
    }

    final dustThreshold = props.dustThreshold ?? 546;
    if (dustThreshold < 0 || dustThreshold > 0x7fffffff) {
      throw EraSdkError(
        'invalid-props',
        'dustThreshold must fit a non-negative int32',
      );
    }

    final proto = encodeBchSignRequestProto(BchSignRequestProto(
      // Zero-padded to eight characters — same firmware hex reader as Tron.
      xfpHex: xfpToHex(xfp),
      signId: uuidStringify(requestId),
      timestamp: props.timestamp ?? 0,
      fee: fee,
      dustThreshold: dustThreshold,
      memo: props.memo,
      inputs: inputs,
      outputs: outputs,
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
      parse: (reply) => _parseBchSignature(reply, requestId),
    );
  }

  /// Parse a `keystone-sign-result` standalone. The request id lives INSIDE
  /// the protobuf (`signId`); pass `expect.requestId` to enable the echo
  /// check — prefer `SignRequest.scanner().parse()`.
  BchSignatureResult parseSignature(Object input, [ExpectedReply? expect]) {
    return _parseBchSignature(
      toUr(input),
      expect?.requestId == null ? null : normalizeRequestId(expect!.requestId!),
    );
  }
}

BchSignatureResult _parseBchSignature(Ur ur, Uint8List? expectedRequestId) {
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

  // The signId echo is the ONLY anti-replay binding on this envelope. After
  // it, ALWAYS run `verifyBchSignedTx` from the verify layer — the reply is
  // a complete broadcastable transaction, and the echo alone does not prove
  // its inputs and outputs are the ones that were requested.
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
  if (!_anyHex.hasMatch(result.rawTx) || result.rawTx.length.isOdd) {
    throw EraSdkError(
      'malformed-reply',
      'keystone-sign-result rawTx is not hex',
    );
  }
  final requestId = expectedRequestId ?? _signIdToBytes(result.signId);
  return BchSignatureResult(
    requestId: requestId,
    txId: result.txId,
    rawTx: result.rawTx,
  );
}

Uint8List _signIdToBytes(String signId) {
  try {
    return normalizeRequestId(signId);
  } on Object {
    return Uint8List(16);
  }
}
