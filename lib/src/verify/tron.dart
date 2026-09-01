import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../crypto/codecs.dart';
import '../crypto/digests.dart';
import '../crypto/secp256k1.dart';
import '../tron_proto/messages.dart';
import '../tron_proto/wire.dart';
import 'result.dart';

/// Inputs for [verifyTronSignature].
class VerifyTronSignatureArgs {
  const VerifyTronSignatureArgs({
    required this.rawData,
    required this.from,
    this.latestBlock,
    required this.signedTx,
  });

  /// The `raw_data` bytes the request carried.
  final Uint8List rawData;

  /// The base58 owner address the transaction spends from.
  final String from;

  /// The reference block the request carried (enables the rebuild-path window
  /// check).
  final TronLatestBlock? latestBlock;

  /// The reply: either the split frame from `TronSignatureResult.signedTx`
  /// (a [SignedTronTx]), or the raw hex (a [String]).
  final Object signedTx;
}

/// The Tron reply is a fully signed transaction broadcast VERBATIM, so it is
/// checked on both counts: every signature must recover to the owner address,
/// and the transaction must move what the user approved.
///
/// Byte equality with the request's `rawData` is the strong form. When the
/// bytes differ (a firmware that rebuilds `raw_data` from the semantic
/// fields), the fallback compares the fields that decide where the money goes,
/// plus the validity window against the reference block.
VerifyResult verifyTronSignature(VerifyTronSignatureArgs args) {
  SignedTronTx signedTx;
  final input = args.signedTx;
  if (input is SignedTronTx) {
    signedTx = input;
  } else if (input is String) {
    try {
      signedTx = splitSignedTronTx(input);
    } on EraSdkError catch (e) {
      return failed(
          'the returned Tron transaction is not readable: ${e.message}');
    }
  } else {
    return failed(
        'the returned Tron transaction is not readable: not a SignedTronTx or hex string');
  }
  if (signedTx.signatures.isEmpty) {
    return failed('the returned Tron transaction carries no signature');
  }
  if (args.from.isEmpty) {
    return failed('no owner address to check the signature against');
  }

  final digest = sha256(signedTx.rawData);
  for (final signature in signedTx.signatures) {
    final recovered = _recoverTronAddress(digest, signature);
    if (recovered == null) return failed('signature could not be checked');
    if (recovered != args.from) {
      return failed('the signature does not belong to this account');
    }
  }

  if (equalBytes(signedTx.rawData, args.rawData)) return verified;

  // Rebuild path: the firmware built its own raw_data from the semantic
  // fields. Compare the operation, then the validity window.
  final contractResult = _compareContracts(args.rawData, signedTx.rawData);
  if (contractResult != null) return contractResult;
  final latestBlock = args.latestBlock;
  if (latestBlock == null) {
    return failed(
      'the returned raw_data differs from the request and no latestBlock was provided to check the validity window',
    );
  }
  return _compareWindow(signedTx.rawData, latestBlock);
}

String? _recoverTronAddress(Uint8List digest, Uint8List signature) {
  if (signature.length < 65) return null;
  final recovery = signature[64];
  final recoveryId = recovery >= 27 ? (recovery - 27) & 1 : recovery & 1;
  try {
    final compressed = Secp256k1.recover(
      Uint8List.sublistView(signature, 0, 64),
      digest,
      recoveryId,
    );
    final uncompressed = Uint8List.fromList(
      Secp256k1.parsePublicKey(compressed).getEncoded(false),
    );
    final hash = keccak256(Uint8List.sublistView(uncompressed, 1));
    return base58CheckEncode(concatBytes([
      Uint8List.fromList([0x41]),
      Uint8List.sublistView(hash, 12),
    ]));
  } on Object {
    return null;
  }
}

// --- raw_data structural comparison ---------------------------------------

class _TronContract {
  const _TronContract({
    required this.typeUrl,
    required this.type,
    required this.parameter,
  });

  final String typeUrl;
  final BigInt type;
  final Uint8List parameter;
}

class _TronRawData {
  const _TronRawData({
    required this.contracts,
    required this.expiration,
    required this.timestamp,
  });

  final List<_TronContract> contracts;
  final BigInt expiration;
  final BigInt timestamp;
}

_TronRawData? _parseRawData(Uint8List bytes) {
  try {
    final fields = readFields(bytes);
    final contracts = <_TronContract>[];
    for (final f in fields) {
      if (f.field == 11 && f.wireType == 2) {
        final c = readFields(f.bytes);
        final anyBytes = firstBytes(c, 2);
        final any =
            anyBytes == null ? const <ProtoField>[] : readFields(anyBytes);
        final typeUrlBytes = anyBytes == null ? null : firstBytes(any, 1);
        final parameter = anyBytes == null ? null : firstBytes(any, 2);
        contracts.add(_TronContract(
          typeUrl: typeUrlBytes == null ? '' : utf8Decode(typeUrlBytes),
          type: firstVarint(c, 1) ?? BigInt.zero,
          parameter: parameter ?? Uint8List(0),
        ));
      }
    }
    return _TronRawData(
      contracts: contracts,
      expiration: firstVarint(fields, 8) ?? BigInt.zero,
      timestamp: firstVarint(fields, 14) ?? BigInt.zero,
    );
  } on Object {
    return null;
  }
}

/// null = contracts match (continue to the window check); a result = verdict.
VerifyResult? _compareContracts(Uint8List askedBytes, Uint8List repliedBytes) {
  final asked = _parseRawData(askedBytes);
  final replied = _parseRawData(repliedBytes);
  if (asked == null) {
    return failed('the Tron transaction built by the app could not be read');
  }
  if (replied == null) {
    return failed('the Tron transaction built by the device could not be read');
  }
  if (asked.contracts.length != 1 || replied.contracts.length != 1) {
    return failed('the Tron transaction does not carry exactly one contract');
  }
  final a = asked.contracts[0];
  final b = replied.contracts[0];
  final kindA = _contractKind(a);
  final kindB = _contractKind(b);
  if (kindA != kindB) {
    return failed(
        'the returned Tron transaction is a different kind of operation');
  }

  final pa = _readFieldsSafe(a.parameter);
  final pb = _readFieldsSafe(b.parameter);
  if (pa == null || pb == null) {
    return failed('the Tron contract parameters could not be read');
  }

  switch (kindA) {
    case _ContractKind.transfer:
      // TransferContract {1: owner, 2: to, 3: amount}
      if (_sameBytesField(pa, pb, 1) &&
          _sameBytesField(pa, pb, 2) &&
          (firstVarint(pa, 3) ?? BigInt.zero) ==
              (firstVarint(pb, 3) ?? BigInt.zero)) {
        return null;
      }
    case _ContractKind.transferAsset:
      // TransferAssetContract {1: asset, 2: owner, 3: to, 4: amount}
      if (_sameBytesField(pa, pb, 1) &&
          _sameBytesField(pa, pb, 2) &&
          _sameBytesField(pa, pb, 3) &&
          (firstVarint(pa, 4) ?? BigInt.zero) ==
              (firstVarint(pb, 4) ?? BigInt.zero)) {
        return null;
      }
    case _ContractKind.triggerSmartContract:
      // TriggerSmartContract {1: owner, 2: contract, 3: call_value, 4: data}.
      // call_value: zero and absent are the same thing — the two sides are
      // serialized by different protobuf writers that disagree on whether a
      // zero scalar is written, and every TRC-20 transfer carries call_value 0.
      if (_sameBytesField(pa, pb, 1) &&
          _sameBytesField(pa, pb, 2) &&
          (firstVarint(pa, 3) ?? BigInt.zero) ==
              (firstVarint(pb, 3) ?? BigInt.zero) &&
          _sameBytesField(pa, pb, 4)) {
        return null;
      }
    case _ContractKind.other:
      // An operation this gate cannot compare field by field is not waved
      // through: without byte equality there is nothing left to bind it to
      // what the user approved.
      return failed(
          'the returned Tron transaction carries an operation this check cannot compare');
  }
  return failed(
      'the returned Tron transaction does not match the one approved');
}

enum _ContractKind { transfer, transferAsset, triggerSmartContract, other }

_ContractKind _contractKind(_TronContract contract) {
  if (contract.typeUrl.endsWith('.TransferContract') ||
      contract.type == BigInt.one) {
    return _ContractKind.transfer;
  }
  if (contract.typeUrl.endsWith('.TransferAssetContract') ||
      contract.type == BigInt.two) {
    return _ContractKind.transferAsset;
  }
  if (contract.typeUrl.endsWith('.TriggerSmartContract') ||
      contract.type == BigInt.from(31)) {
    return _ContractKind.triggerSmartContract;
  }
  return _ContractKind.other;
}

List<ProtoField>? _readFieldsSafe(Uint8List bytes) {
  try {
    return readFields(bytes);
  } on Object {
    return null;
  }
}

final Uint8List _emptyBytes = Uint8List(0);

bool _sameBytesField(List<ProtoField> a, List<ProtoField> b, int field) {
  final x = firstBytes(a, field) ?? _emptyBytes;
  final y = firstBytes(b, field) ?? _emptyBytes;
  return equalBytes(x, y);
}

/// Firmware formulas, not policy: the two device-side transaction builders
/// stamp `timestamp` with the request's reference-block timestamp verbatim and
/// set `expiration` to +10 minutes (one builder) or +10 hours (the other). A
/// range spanning both cannot refuse a reply the live fleet produces.
final BigInt _minExpiryMs = BigInt.from(10 * 60 * 1000);
final BigInt _maxExpiryMs = BigInt.from(10 * 60 * 60 * 1000);

VerifyResult _compareWindow(
  Uint8List repliedBytes,
  TronLatestBlock latestBlock,
) {
  final replied = _parseRawData(repliedBytes);
  if (replied == null) {
    return failed('the Tron transaction built by the device could not be read');
  }
  final block = BigInt.from(latestBlock.timestamp);
  if (replied.timestamp != block) {
    return failed(
      'the returned Tron transaction is stamped against a different reference block than the one we sent',
    );
  }
  final validFor = replied.expiration - block;
  if (validFor < _minExpiryMs || validFor > _maxExpiryMs) {
    return failed(
      "the returned Tron transaction is valid for $validFor ms after the reference block, outside the firmware's $_minExpiryMs-$_maxExpiryMs ms window",
    );
  }
  return verified;
}
