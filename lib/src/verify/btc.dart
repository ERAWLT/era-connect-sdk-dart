import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/errors.dart';
import 'psbt_reader.dart';
import 'result.dart';

/// Inputs for [verifySignedPsbt].
class VerifySignedPsbtArgs {
  const VerifySignedPsbtArgs({
    required this.sentPsbt,
    required this.signedPsbt,
    this.requireEveryInputSigned = true,
  });

  /// The PSBT you sent to the device.
  final Uint8List sentPsbt;

  /// The PSBT the device returned.
  final Uint8List signedPsbt;

  /// true (default) on flows where every input is yours (a plain send): a
  /// reply that signed only part of the transaction is refused here with a
  /// reason instead of failing later inside a finalizer. Set false for dApp
  /// `signPsbt` hand-backs, where a PSBT legitimately carries inputs you
  /// cannot sign.
  final bool requireEveryInputSigned;
}

/// The `crypto-psbt` reply carries NO request id — this comparison IS the
/// anti-replay binding for Bitcoin. It is not optional.
///
/// The unsigned transaction is compared byte for byte, which pins the input
/// set and order, the outputs, their amounts, the version and the locktime in
/// one shot — and therefore the txid. The device only ADDS per-input
/// signature fields, so a legitimate reply always matches.
VerifyResult verifySignedPsbt(VerifySignedPsbtArgs args) {
  ParsedPsbt sent;
  ParsedPsbt signed;
  try {
    sent = parsePsbt(args.sentPsbt);
  } catch (e) {
    return failed('the PSBT we sent is not readable: ${_message(e)}');
  }
  try {
    signed = parsePsbt(args.signedPsbt);
  } catch (e) {
    return failed(
        'the PSBT the device returned is not readable: ${_message(e)}');
  }

  if (!equalBytes(sent.unsignedTx, signed.unsignedTx)) {
    return failed(
        'the returned PSBT is a different transaction from the one approved');
  }

  // A finalized field carries the COMPLETE scriptSig/witness that will be
  // broadcast, and the unsigned-tx comparison above does not cover it (it
  // lives per input, the unsigned tx in the global map). An input that comes
  // back finalized must have been SENT that way, with byte-identical
  // values — the device echoes these fields, it never authors them.
  const finalizedTypes = [
    PsbtInputType.finalScriptSig,
    PsbtInputType.finalScriptWitness,
  ];
  for (var i = 0; i < signed.inputs.length; i++) {
    for (final type in finalizedTypes) {
      if (!inputHas(signed, i, type)) continue;
      if (!inputHas(sent, i, type)) {
        return failed(
          'input $i came back finalized (type 0x${type.toRadixString(16)}) '
          'and was not sent that way — the script it would broadcast is not ours',
        );
      }
      final a = inputEntries(sent, i, type);
      final b = inputEntries(signed, i, type);
      var same = a.length == b.length;
      if (same) {
        for (var k = 0; k < a.length; k++) {
          if (!equalBytes(a[k].value, b[k].value)) {
            same = false;
            break;
          }
        }
      }
      if (!same) {
        return failed(
          'input $i came back with a different finalized script than the one we sent',
        );
      }
    }
  }

  bool isSigned(int i) =>
      inputHas(signed, i, PsbtInputType.partialSig) ||
      inputHas(signed, i, PsbtInputType.taprootKeySpendSignature) ||
      inputHas(signed, i, PsbtInputType.taprootScriptSpendSignature);

  final indexes = List<int>.generate(signed.inputs.length, (i) => i);
  if (args.requireEveryInputSigned) {
    if (!indexes.every(isSigned)) {
      return failed('the device signed only part of the transaction');
    }
  } else if (!indexes.any(isSigned)) {
    return failed('the returned PSBT carries no signature');
  }
  return verified;
}

/// Inputs for [verifyBtcMessageHeader].
class VerifyBtcMessageHeaderArgs {
  const VerifyBtcMessageHeaderArgs({
    required this.address,
    required this.signature,
  });

  /// The address the request asked the device to sign with.
  final String address;

  /// The raw 65-byte BIP-137 signature.
  final Uint8List signature;
}

/// BIP-137: the recovery header names the address type a verifier derives
/// before comparing. A header of the wrong range produces a signature that
/// LOOKS fine (65 bytes, valid base64) but fails every verifier downstream —
/// this check is the only place that difference is visible.
VerifyResult verifyBtcMessageHeader(VerifyBtcMessageHeaderArgs args) {
  if (args.signature.isEmpty) {
    return failed('empty signature');
  }
  final header = args.signature[0];
  final range = _headerRangeFor(args.address);
  if (range == null) {
    return unverifiable(
        'address kind has no BIP-137 header range to check against');
  }
  if (header >= range.low && header <= range.high) return verified;
  return failed(
    'recovery header $header does not match a ${range.label} address '
    '(BIP-137 expects ${range.low}..${range.high}); this signature would not '
    'verify against the address it was asked to sign for',
  );
}

class _HeaderRange {
  const _HeaderRange({
    required this.low,
    required this.high,
    required this.label,
  });

  final int low;
  final int high;
  final String label;
}

_HeaderRange? _headerRangeFor(String address) {
  final a = address.toLowerCase();
  if (a.startsWith('bc1q') || a.startsWith('tb1q') || a.startsWith('bcrt1q')) {
    return const _HeaderRange(
        low: 39, high: 42, label: 'native segwit (P2WPKH)');
  }
  if (a.startsWith('bc1p') || a.startsWith('tb1p') || a.startsWith('bcrt1p')) {
    return null; // Taproot: BIP-137 does not cover it (BIP-322 is the scheme).
  }
  // Base58 kinds matched on SHAPE, not first character alone — a guard that
  // invents a range for a string it does not understand is worse than one
  // that declines to judge.
  if (_looksBase58(address)) {
    if (address.startsWith('3') || address.startsWith('2')) {
      return const _HeaderRange(
          low: 35, high: 38, label: 'P2SH (nested segwit)');
    }
    if (address.startsWith('1') ||
        address.startsWith('m') ||
        address.startsWith('n')) {
      // Both the uncompressed and compressed P2PKH ranges — which one is
      // right depends on the key the device used, which we do not know.
      return const _HeaderRange(low: 27, high: 34, label: 'legacy P2PKH');
    }
  }
  return null;
}

final RegExp _base58Alphabet = RegExp(r'^[1-9A-HJ-NP-Za-km-z]+$');

bool _looksBase58(String address) {
  return address.length >= 26 &&
      address.length <= 35 &&
      _base58Alphabet.hasMatch(address);
}

String _message(Object e) => e is EraSdkError ? e.message : '$e';
