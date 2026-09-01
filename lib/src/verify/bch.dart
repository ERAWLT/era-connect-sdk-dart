/// "The device signed exactly what I sent" for Bitcoin Cash.
///
/// The reply on this chain is a COMPLETE broadcastable transaction, so the
/// binding has to be rebuilt from it: every outpoint, every output script and
/// value, and every input signature are checked against the request. The
/// sighash is BIP-143 with `SIGHASH_FORKID` (0x41) — recomputed here from the
/// request's own input values, which is also what makes a value lie visible:
/// a wrong `value` in the request would fail right here, because the network
/// would reject the same preimage.
library;

import 'dart:typed_data';

import '../chains/cashaddr.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../crypto/digests.dart';
import '../crypto/secp256k1.dart';
import 'result.dart';

/// One request input, as named to the device.
class VerifyBchInput {
  const VerifyBchInput({
    required this.txid,
    required this.index,
    required this.value,
    required this.publicKey,
  });

  /// Display-order txid, 64 hex chars — as sent in the request.
  final String txid;

  final int index;

  /// UTXO value in satoshis ([int] or [BigInt]) — as sent in the request.
  final Object value;

  /// The compressed public key the request named as the UTXO owner
  /// ([Uint8List] or hex [String]).
  final Object publicKey;
}

/// One request output, as named to the device.
class VerifyBchOutput {
  const VerifyBchOutput({required this.address, required this.value});

  /// CashAddr as sent in the request (prefixed or bare).
  final String address;

  /// Output value in satoshis ([int] or [BigInt]).
  final Object value;
}

/// Inputs for [verifyBchSignedTx].
class VerifyBchSignedTxArgs {
  const VerifyBchSignedTxArgs({
    required this.rawTx,
    required this.inputs,
    required this.outputs,
    this.txId,
  });

  /// The reply's `rawTx` hex.
  final String rawTx;

  final List<VerifyBchInput> inputs;

  final List<VerifyBchOutput> outputs;

  /// The reply's `txId`, when you want it checked against the raw bytes too.
  final String? txId;
}

const int _sighashForkidAll = 0x41;
// The device's signer hardcodes these; a reply that deviates was not built
// by it (or a firmware change landed — then update BOTH constants and docs).
const int _bchTxVersion = 1;
const int _bchTxLocktime = 0;
const int _bchTxSequence = 0xfffffffd;

/// One decoded input of a legacy-serialized transaction.
class DecodedBchInput {
  const DecodedBchInput({
    required this.txidLE,
    required this.index,
    required this.scriptSig,
    required this.sequence,
  });

  /// The outpoint txid in wire (little-endian) order.
  final Uint8List txidLE;

  final int index;

  final Uint8List scriptSig;

  final int sequence;
}

/// One decoded output of a legacy-serialized transaction.
class DecodedBchOutput {
  const DecodedBchOutput({required this.value, required this.script});

  final BigInt value;

  final Uint8List script;
}

/// A decoded legacy-serialized Bitcoin Cash transaction.
class DecodedBchTx {
  const DecodedBchTx({
    required this.version,
    required this.inputs,
    required this.outputs,
    required this.locktime,
  });

  final int version;

  final List<DecodedBchInput> inputs;

  final List<DecodedBchOutput> outputs;

  final int locktime;
}

/// Hardened reader for the legacy (non-witness) transaction serialization.
DecodedBchTx decodeBchRawTx(String rawTxHex) {
  Uint8List bytes;
  try {
    bytes = hexToBytes(rawTxHex);
  } on Object {
    throw EraSdkError('malformed-reply', 'signed transaction is not hex');
  }
  var offset = 0;
  void need(int n) {
    if (offset + n > bytes.length) {
      throw EraSdkError('malformed-reply', 'signed transaction is truncated');
    }
  }

  int readU32() {
    need(4);
    final v = bytes[offset] |
        (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) |
        (bytes[offset + 3] << 24);
    offset += 4;
    return v;
  }

  BigInt readU64() {
    need(8);
    var v = BigInt.zero;
    for (var i = 7; i >= 0; i--) {
      v = (v << 8) | BigInt.from(bytes[offset + i]);
    }
    offset += 8;
    return v;
  }

  int readVarint() {
    need(1);
    final first = bytes[offset++];
    if (first < 0xfd) return first;
    if (first == 0xfd) {
      need(2);
      final v = bytes[offset] | (bytes[offset + 1] << 8);
      offset += 2;
      return v;
    }
    // 4- and 8-byte counts cannot occur in a transaction the device can build.
    throw EraSdkError(
      'malformed-reply',
      'unreasonable varint in signed transaction',
    );
  }

  Uint8List readSlice(int n) {
    need(n);
    final s = Uint8List.sublistView(bytes, offset, offset + n);
    offset += n;
    return s;
  }

  final version = readU32();
  final inputCount = readVarint();
  if (inputCount == 0 || inputCount > 1000) {
    throw EraSdkError(
      'malformed-reply',
      'unreasonable input count in signed transaction',
    );
  }
  final inputs = <DecodedBchInput>[];
  for (var i = 0; i < inputCount; i++) {
    final txidLE = readSlice(32);
    final index = readU32();
    final scriptSig = readSlice(readVarint());
    final sequence = readU32();
    inputs.add(DecodedBchInput(
      txidLE: txidLE,
      index: index,
      scriptSig: scriptSig,
      sequence: sequence,
    ));
  }
  final outputCount = readVarint();
  if (outputCount == 0 || outputCount > 1000) {
    throw EraSdkError(
      'malformed-reply',
      'unreasonable output count in signed transaction',
    );
  }
  final outputs = <DecodedBchOutput>[];
  for (var i = 0; i < outputCount; i++) {
    final value = readU64();
    final script = readSlice(readVarint());
    outputs.add(DecodedBchOutput(value: value, script: script));
  }
  final locktime = readU32();
  if (offset != bytes.length) {
    throw EraSdkError(
      'malformed-reply',
      'trailing bytes after signed transaction',
    );
  }
  return DecodedBchTx(
    version: version,
    inputs: inputs,
    outputs: outputs,
    locktime: locktime,
  );
}

Uint8List _p2pkhScript(Uint8List pubkeyHash) {
  return concatBytes([
    Uint8List.fromList([0x76, 0xa9, 0x14]),
    pubkeyHash,
    Uint8List.fromList([0x88, 0xac]),
  ]);
}

Uint8List _p2shScript(Uint8List scriptHash) {
  return concatBytes([
    Uint8List.fromList([0xa9, 0x14]),
    scriptHash,
    Uint8List.fromList([0x87]),
  ]);
}

Uint8List _scriptForAddress(String address) {
  final decoded = decodeCashAddr(address);
  return decoded.type == CashAddrType.p2pkh
      ? _p2pkhScript(decoded.hash)
      : _p2shScript(decoded.hash);
}

Uint8List _le32(int value) {
  return Uint8List.fromList([
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
  ]);
}

Uint8List _le64(BigInt value) {
  final out = Uint8List(8);
  final mask = BigInt.from(0xff);
  var v = value;
  for (var i = 0; i < 8; i++) {
    out[i] = (v & mask).toInt();
    v >>= 8;
  }
  return out;
}

Uint8List _varintBytes(int value) {
  if (value < 0xfd) return Uint8List.fromList([value]);
  return Uint8List.fromList([0xfd, value & 0xff, (value >> 8) & 0xff]);
}

/// BIP-143 sighash preimage with FORKID, exactly as consensus defines it:
/// `version ‖ hashPrevouts ‖ hashSequence ‖ outpoint ‖ scriptCode ‖ value ‖
/// sequence ‖ hashOutputs ‖ locktime ‖ hashType(LE)`, double-SHA256d.
Uint8List computeBchSighash({
  required DecodedBchTx tx,
  required int inputIndex,
  required Uint8List scriptCode,
  required BigInt value,
  int? hashType,
}) {
  final type = hashType ?? _sighashForkidAll;
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw EraSdkError('invalid-props', 'sighash input index out of range');
  }
  final input = tx.inputs[inputIndex];
  final hashPrevouts = sha256d(concatBytes([
    for (final i in tx.inputs) concatBytes([i.txidLE, _le32(i.index)]),
  ]));
  final hashSequence = sha256d(concatBytes([
    for (final i in tx.inputs) _le32(i.sequence),
  ]));
  final hashOutputs = sha256d(concatBytes([
    for (final o in tx.outputs)
      concatBytes([_le64(o.value), _varintBytes(o.script.length), o.script]),
  ]));
  final preimage = concatBytes([
    _le32(tx.version),
    hashPrevouts,
    hashSequence,
    input.txidLE,
    _le32(input.index),
    _varintBytes(scriptCode.length),
    scriptCode,
    _le64(value),
    _le32(input.sequence),
    hashOutputs,
    _le32(tx.locktime),
    _le32(type),
  ]);
  return sha256d(preimage);
}

BigInt _toBigintValue(Object value, String label) {
  final BigInt v;
  if (value is BigInt) {
    v = value;
  } else if (value is int) {
    v = BigInt.from(value);
  } else {
    throw EraSdkError('invalid-props', '$label must be positive');
  }
  if (v <= BigInt.zero) {
    throw EraSdkError('invalid-props', '$label must be positive');
  }
  return v;
}

Uint8List _toPublicKeyBytes(Object publicKey) {
  if (publicKey is String) return hexToBytes(publicKey);
  if (publicKey is Uint8List) return publicKey;
  throw EraSdkError(
    'invalid-props',
    'publicKey must be bytes or a hex string',
  );
}

/// Strict DER `SEQUENCE(INTEGER r, INTEGER s)` to a compact 64-byte `r ‖ s`
/// (what [Secp256k1.verify] consumes). Throws on anything a canonical DER
/// encoder cannot have produced.
Uint8List _derToCompact(Uint8List der) {
  EraSdkError bad(String why) =>
      EraSdkError('malformed-reply', 'signature DER is malformed: $why');
  if (der.length < 8 || der[0] != 0x30) throw bad('not a DER sequence');
  if (der[1] != der.length - 2) throw bad('sequence length mismatch');
  var offset = 2;
  Uint8List readInt() {
    if (offset + 2 > der.length || der[offset] != 0x02) {
      throw bad('missing integer tag');
    }
    final len = der[offset + 1];
    offset += 2;
    if (len == 0 || offset + len > der.length) throw bad('bad integer length');
    final value = Uint8List.sublistView(der, offset, offset + len);
    offset += len;
    if (value[0] & 0x80 != 0) throw bad('negative integer');
    if (len > 1 && value[0] == 0x00 && value[1] & 0x80 == 0) {
      throw bad('unnecessary leading zero');
    }
    final start = value[0] == 0x00 ? 1 : 0;
    if (value.length - start > 32) throw bad('integer wider than 32 bytes');
    return Uint8List.sublistView(value, start);
  }

  final r = readInt();
  final s = readInt();
  if (offset != der.length) throw bad('trailing bytes');
  final out = Uint8List(64);
  out.setAll(32 - r.length, r);
  out.setAll(64 - s.length, s);
  return out;
}

/// Verify a signed BCH transaction against the request that asked for it.
VerifyResult verifyBchSignedTx(VerifyBchSignedTxArgs args) {
  try {
    final tx = decodeBchRawTx(args.rawTx);

    // Everything the verifier does not read is unchecked (the sighash is
    // recomputed FROM the decoded tx, so it is self-consistent with any
    // version/locktime/sequence). Pin the parameters the signer fixes.
    if (tx.version != _bchTxVersion || tx.locktime != _bchTxLocktime) {
      return failed(
        'transaction parameters (version ${tx.version}, locktime ${tx.locktime}) '
        "are not the device signer's (1, 0)",
      );
    }
    for (var i = 0; i < tx.inputs.length; i++) {
      if (tx.inputs[i].sequence != _bchTxSequence) {
        return failed(
            "input $i sequence is not the device signer's 0xfffffffd");
      }
    }

    if (tx.inputs.length != args.inputs.length) {
      return failed(
        'signed transaction has ${tx.inputs.length} inputs, the request had ${args.inputs.length}',
      );
    }
    if (tx.outputs.length != args.outputs.length) {
      return failed(
        'signed transaction has ${tx.outputs.length} outputs, the request had ${args.outputs.length}',
      );
    }

    for (var i = 0; i < args.outputs.length; i++) {
      final requested = args.outputs[i];
      final actual = tx.outputs[i];
      if (actual.value != _toBigintValue(requested.value, 'output $i value')) {
        return failed('output $i value differs from the request');
      }
      if (!equalBytes(actual.script, _scriptForAddress(requested.address))) {
        return failed('output $i does not pay the requested address');
      }
    }

    for (var i = 0; i < args.inputs.length; i++) {
      final requested = args.inputs[i];
      final actual = tx.inputs[i];
      final txidLE =
          Uint8List.fromList(hexToBytes(requested.txid).reversed.toList());
      if (!equalBytes(actual.txidLE, txidLE) ||
          actual.index != requested.index) {
        return failed(
            'input $i spends a different outpoint than the request named');
      }

      // scriptSig must be exactly push(sig‖0x41) push(pubkey33).
      final script = actual.scriptSig;
      if (script.length < 2) return failed('input $i has no signature');
      final sigLen = script[0];
      if (sigLen < 9 || 1 + sigLen + 1 > script.length) {
        return failed('input $i scriptSig is not a signature push');
      }
      final sigWithType = Uint8List.sublistView(script, 1, 1 + sigLen);
      final pubLen = script[1 + sigLen];
      if (pubLen != 33 || 1 + sigLen + 1 + pubLen != script.length) {
        return failed(
          'input $i scriptSig does not end with a compressed public key push',
        );
      }
      final pubkey = Uint8List.sublistView(script, 1 + sigLen + 1);
      if (!equalBytes(pubkey, _toPublicKeyBytes(requested.publicKey))) {
        return failed(
          'input $i was signed with a different public key than the request named — '
          'the transaction cannot spend the requested UTXO',
        );
      }
      final hashType = sigWithType[sigWithType.length - 1];
      if (hashType != _sighashForkidAll) {
        return failed(
          'input $i uses sighash 0x${hashType.toRadixString(16)}, expected SIGHASH_ALL|FORKID (0x41)',
        );
      }
      final sighash = computeBchSighash(
        tx: tx,
        inputIndex: i,
        scriptCode: _p2pkhScript(hash160(pubkey)),
        value: _toBigintValue(requested.value, 'input $i value'),
      );
      final signature = _derToCompact(
        Uint8List.sublistView(sigWithType, 0, sigWithType.length - 1),
      );
      if (!Secp256k1.verify(signature, sighash, pubkey)) {
        return failed(
          'input $i signature does not verify against the BIP-143 FORKID sighash',
        );
      }
    }

    final txId = args.txId;
    if (txId != null) {
      final computed = bytesToHex(Uint8List.fromList(
        sha256d(hexToBytes(args.rawTx)).reversed.toList(),
      ));
      if (computed != txId.toLowerCase()) {
        return failed(
            'reply txId does not match the hash of the signed transaction');
      }
    }
    return verified;
  } on EraSdkError catch (e) {
    return failed(e.message);
  } on Object catch (e) {
    return failed(e is FormatException ? e.message : e.toString());
  }
}
