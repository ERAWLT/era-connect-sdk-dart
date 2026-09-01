/// The Tron signing envelope ("QrCode Protocol"):
/// `Base -> Payload -> SignTransaction -> TronTx`, gzip-compressed and wrapped
/// in a `keystone-sign-request` (6101) CBOR map. Schemas are vendored under
/// `proto/tron/`; this codec hand-writes the five messages the wallet side
/// speaks, with reference-exact field emission (explicitly-set defaults ARE
/// written; ascending field order).
library;

import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';
import 'wire.dart';

/// A live now-block anchor for a Tron transaction.
class TronLatestBlock {
  const TronLatestBlock({
    required this.hash,
    required this.number,
    required this.timestamp,
  });

  /// FULL 64-hex block id of a live now-block (the device slices
  /// ref_block_hash from it).
  final String hash;

  /// The block height.
  final int number;

  /// The block timestamp in Unix milliseconds.
  final int timestamp;
}

/// Inputs for [encodeSignRequestProto].
class TronSignRequestProto {
  const TronSignRequestProto({
    required this.xfpHex,
    required this.signId,
    required this.hdPath,
    required this.timestamp,
    required this.decimals,
    required this.token,
    this.contractAddress,
    this.from,
    this.to,
    this.memo,
    this.value,
    this.fee,
    required this.latestBlock,
    required this.rawData,
  });

  /// Lowercase, ZERO-PADDED 8-hex source fingerprint (the wire demands the
  /// string form).
  final String xfpHex;

  /// Hyphenated UUID string; echoed by the device as the only reply binding.
  final String signId;

  /// The BIP-44 derivation path of the signing key.
  final String hdPath;

  /// Request timestamp in Unix milliseconds.
  final int timestamp;

  /// Token decimals shown on the device.
  final int decimals;

  /// The token symbol shown on the device.
  final String token;

  /// TRC-20 contract address, when the transfer is a token transfer.
  final String? contractAddress;

  /// Sender address (base58).
  final String? from;

  /// Recipient address (base58).
  final String? to;

  /// Optional memo shown on the device.
  final String? memo;

  /// Human-readable amount string shown on the device.
  final String? value;

  /// Fee in SUN; must fit a positive int32.
  final int? fee;

  /// The now-block anchor.
  final TronLatestBlock latestBlock;

  /// Serialized `Transaction.raw_data` — the signing source of truth.
  final Uint8List rawData;
}

const int _payloadTypeSignTx = 2;

/// Encode a Tron `keystone-sign-request` Base protobuf.
Uint8List encodeSignRequestProto(TronSignRequestProto req) {
  final fee = req.fee;
  if (fee != null && (fee < 0 || fee > 0x7fffffff)) {
    throw EraSdkError('invalid-props', 'tron fee must fit a positive int32');
  }
  final latestBlock = ProtoWriter()
      .stringField(1, req.latestBlock.hash)
      .varintField(2, BigInt.from(req.latestBlock.number))
      .varintField(3, BigInt.from(req.latestBlock.timestamp))
      .finish();

  final tronTx = ProtoWriter().stringField(1, req.token);
  final contractAddress = req.contractAddress;
  if (contractAddress != null) tronTx.stringField(2, contractAddress);
  final from = req.from;
  if (from != null) tronTx.stringField(3, from);
  final to = req.to;
  if (to != null) tronTx.stringField(4, to);
  final memo = req.memo;
  if (memo != null) tronTx.stringField(5, memo);
  final value = req.value;
  if (value != null) tronTx.stringField(6, value);
  tronTx.messageField(7, latestBlock);
  if (fee != null) tronTx.varintField(9, BigInt.from(fee));
  tronTx.bytesField(10, req.rawData);

  final signTx = ProtoWriter()
      .stringField(1, 'TRON')
      .stringField(2, req.signId)
      .stringField(3, req.hdPath)
      .varintField(4, BigInt.from(req.timestamp))
      .varintField(5, BigInt.from(req.decimals))
      .messageField(8, tronTx.finish())
      .finish();

  final payload = ProtoWriter()
      .varintField(1, BigInt.from(_payloadTypeSignTx))
      .stringField(2, req.xfpHex)
      .messageField(4, signTx)
      .finish();

  return ProtoWriter()
      .varintField(1, BigInt.from(2)) // Base.version
      .stringField(2, 'QrCode Protocol')
      .messageField(3, payload)
      .finish();
}

/// One UTXO spent by a BCH sign request.
class BchProtoInput {
  const BchProtoInput({
    required this.txidHex,
    required this.index,
    required this.value,
    required this.publicKeyHex,
    required this.ownerKeyPath,
  });

  /// Display-order (big-endian) txid, 64 hex chars — a STRING on the wire.
  final String txidHex;

  /// The output index of the UTXO within its transaction.
  final int index;

  /// UTXO value in satoshis.
  final BigInt value;

  /// Compressed public key, 66 hex chars — a STRING on the wire.
  final String publicKeyHex;

  /// Full derivation path of the key that owns the UTXO.
  final String ownerKeyPath;
}

/// One output created by a BCH sign request.
class BchProtoOutput {
  const BchProtoOutput({
    required this.address,
    required this.value,
    required this.isChange,
    this.changeAddressPath,
  });

  /// CashAddr (verbatim; the device accepts both prefixed and bare form).
  final String address;

  /// Output value in satoshis.
  final BigInt value;

  /// Whether the output returns change to the sender.
  final bool isChange;

  /// Derivation path of the change address, when [isChange] is set.
  final String? changeAddressPath;
}

/// Inputs for [encodeBchSignRequestProto].
class BchSignRequestProto {
  const BchSignRequestProto({
    required this.xfpHex,
    required this.signId,
    required this.timestamp,
    required this.fee,
    required this.dustThreshold,
    this.memo,
    required this.inputs,
    required this.outputs,
  });

  /// Lowercase, ZERO-PADDED 8-hex source fingerprint (the wire demands the
  /// string form).
  final String xfpHex;

  /// Hyphenated UUID string; echoed by the device as the only reply binding.
  final String signId;

  /// Request timestamp in Unix milliseconds.
  final int timestamp;

  /// Fee in satoshis — shown on the device; MUST equal inputs minus outputs.
  final BigInt fee;

  /// The dust threshold in satoshis.
  final int dustThreshold;

  /// Optional memo shown on the device.
  final String? memo;

  /// The UTXOs being spent.
  final List<BchProtoInput> inputs;

  /// The outputs being created.
  final List<BchProtoOutput> outputs;
}

/// The BCH leg of the same envelope: `Base -> Payload -> SignTransaction ->
/// BchTx` at oneof tag 10, with FLAT inputs (value/publicKey are direct
/// fields, no nested Utxo sub-message). Unlike the Tron writer, default
/// values are OMITTED here — proto3 emission, which is what the reference
/// wallet capture the firmware fixture pins does. `hdPath` (SignTransaction
/// field 3) is deliberately absent: the reference never sends it and the
/// device reads the per-input `ownerKeyPath` instead.
Uint8List encodeBchSignRequestProto(BchSignRequestProto req) {
  final bchTx = ProtoWriter();
  if (req.fee != BigInt.zero) bchTx.varintField(1, req.fee);
  if (req.dustThreshold != 0) {
    bchTx.varintField(2, BigInt.from(req.dustThreshold));
  }
  final memo = req.memo;
  if (memo != null && memo != '') bchTx.stringField(3, memo);
  for (final input in req.inputs) {
    final w = ProtoWriter().stringField(1, input.txidHex);
    if (input.index != 0) w.varintField(2, BigInt.from(input.index));
    if (input.value != BigInt.zero) w.varintField(3, input.value);
    w.stringField(4, input.publicKeyHex);
    w.stringField(5, input.ownerKeyPath);
    bchTx.messageField(4, w.finish());
  }
  for (final output in req.outputs) {
    final w = ProtoWriter().stringField(1, output.address);
    if (output.value != BigInt.zero) w.varintField(2, output.value);
    if (output.isChange) w.varintField(3, BigInt.one);
    final changeAddressPath = output.changeAddressPath;
    if (changeAddressPath != null && changeAddressPath != '') {
      w.stringField(4, changeAddressPath);
    }
    bchTx.messageField(5, w.finish());
  }

  final signTx = ProtoWriter().stringField(1, 'BCH').stringField(2, req.signId);
  if (req.timestamp != 0) signTx.varintField(4, BigInt.from(req.timestamp));
  signTx.varintField(5, BigInt.from(8)); // decimal: BCH is always 8
  signTx.messageField(10, bchTx.finish());

  final payload = ProtoWriter()
      .varintField(1, BigInt.from(_payloadTypeSignTx))
      .stringField(2, req.xfpHex)
      .messageField(4, signTx.finish())
      .finish();

  return ProtoWriter()
      .varintField(1, BigInt.from(2)) // Base.version
      .stringField(2, 'QrCode Protocol')
      .messageField(3, payload)
      .finish();
}

/// The decoded fields of a `keystone-sign-result` reply.
class TronSignResultProto {
  const TronSignResultProto({
    required this.signId,
    required this.txId,
    required this.rawTx,
  });

  /// The echoed sign request id (empty when the reply omits it).
  final String signId;

  /// The transaction id computed by the device.
  final String txId;

  /// The signed transaction frame as hex.
  final String rawTx;
}

/// Parse a `keystone-sign-result` Base protobuf. Unknown fields are skipped.
TronSignResultProto decodeSignResultProto(Uint8List bytes) {
  final base = readFields(bytes);
  final payloadBytes = firstBytes(base, 3);
  if (payloadBytes == null) {
    throw EraSdkError(
      'malformed-reply',
      'keystone-sign-result carries no payload',
    );
  }
  final payload = readFields(payloadBytes);
  final resultBytes = firstBytes(payload, 7); // Payload.signTxResult
  if (resultBytes == null) {
    return const TronSignResultProto(signId: '', txId: '', rawTx: '');
  }
  final result = readFields(resultBytes);
  return TronSignResultProto(
    signId: _text(firstBytes(result, 1)),
    txId: _text(firstBytes(result, 2)),
    rawTx: _text(firstBytes(result, 3)),
  );
}

String _text(Uint8List? bytes) {
  if (bytes == null) return '';
  try {
    return utf8Decode(bytes);
  } on FormatException {
    throw EraSdkError(
      'malformed-reply',
      'protobuf string field is not valid UTF-8',
    );
  }
}

/// The two halves of a signed Tron network `Transaction` frame.
class SignedTronTx {
  const SignedTronTx({required this.rawData, required this.signatures});

  /// Verbatim `raw_data` slice — the digest is sha256 over the device's own
  /// serialization.
  final Uint8List rawData;

  /// The signature list, in frame order.
  final List<Uint8List> signatures;
}

/// Split a signed Tron network `Transaction` frame (`{1: raw_data, 2: signature*}`)
/// from the reply's `rawTx` hex. Top-level fields must be length-delimited —
/// anything else is not a transaction frame.
SignedTronTx splitSignedTronTx(String rawTxHex) {
  Uint8List frame;
  try {
    frame = hexToBytes(rawTxHex);
  } on FormatException {
    throw EraSdkError('malformed-reply', 'signed Tron transaction is not hex');
  }
  final fields = readFields(frame);
  Uint8List? rawData;
  final signatures = <Uint8List>[];
  for (final f in fields) {
    if (f.wireType != 2) {
      throw EraSdkError(
        'malformed-reply',
        'unexpected wire type in signed Tron transaction',
      );
    }
    if (f.field == 1 && rawData == null) rawData = f.bytes;
    if (f.field == 2) signatures.add(f.bytes);
  }
  if (rawData == null) {
    throw EraSdkError(
      'malformed-reply',
      'signed Tron transaction carries no raw_data',
    );
  }
  return SignedTronTx(rawData: rawData, signatures: signatures);
}
