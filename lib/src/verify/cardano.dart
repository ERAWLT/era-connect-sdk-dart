import 'dart:typed_data';

import '../accounts/derive.dart';
import '../chains/cardano.dart';
import '../core/bytes.dart';
import '../core/errors.dart';
import '../crypto/digests.dart';
import '../crypto/ed25519.dart';
import '../registry/keypath.dart';
import 'result.dart';

/// The linked account's key material, from `accounts.cardano()`: the account
/// xpub halves and its path.
class VerifyCardanoAccount {
  const VerifyCardanoAccount({
    required this.publicKey,
    required this.chainCode,
    required this.accountPath,
  });

  final Uint8List publicKey;
  final Uint8List chainCode;
  final String accountPath;
}

/// Inputs for [verifyCardanoSignature].
class VerifyCardanoSignatureArgs {
  const VerifyCardanoSignatureArgs({
    required this.signData,
    this.witnessSet,
    this.witnesses,
    this.account,
    this.signerPaths,
  });

  /// The exact bytes the request carried in `signData` (the full tx CBOR
  /// array).
  final Uint8List signData;

  /// The reply's witness set (or already-parsed [witnesses]).
  final Uint8List? witnessSet;

  final List<CardanoWitness>? witnesses;

  /// Optional but STRONGLY recommended — binds the witnesses to YOUR wallet:
  /// the linked account's key material plus the signing paths your request
  /// carried. Without it the check only proves internal consistency of the
  /// reply (any key could have produced a matching pair).
  final VerifyCardanoAccount? account;

  /// The unique signing paths of the request (utxos + certKeys), e.g.
  /// `m/1852'/1815'/0'/0/0`.
  final List<String>? signerPaths;
}

/// Recompute the digest the device signs — BLAKE2b-256 of the ENCODED FIRST
/// ELEMENT of the transaction CBOR array (the tx body) — and verify every
/// `[vkey, signature]` pair against it. With `account` + `signerPaths`, the
/// vkeys are additionally required to be exactly the soft-derived children of
/// YOUR linked account at the request's own paths.
VerifyResult verifyCardanoSignature(VerifyCardanoSignatureArgs args) {
  List<CardanoWitness> witnesses;
  try {
    witnesses = args.witnesses ??
        (args.witnessSet != null
            ? parseWitnessSet(args.witnessSet!)
            : <CardanoWitness>[]);
  } on EraSdkError catch (e) {
    return failed('witness set is not readable: ${e.message}');
  }
  if (witnesses.isEmpty) return failed('no witnesses to verify');

  Uint8List digest;
  try {
    digest = blake2b256(firstArrayItemBytes(args.signData));
  } on FormatException catch (e) {
    return failed('signData is not a readable transaction array: ${e.message}');
  }

  for (final witness in witnesses) {
    bool ok;
    try {
      ok = ed25519Verify(witness.vkey, digest, witness.signature);
    } on Object catch (e) {
      return failed('Cardano signature could not be checked: $e');
    }
    if (!ok) {
      return failed('a witness signature does not verify against its own vkey');
    }
  }

  final account = args.account;
  final signerPaths = args.signerPaths;
  if (account != null && signerPaths != null && signerPaths.isNotEmpty) {
    final accountLevels = parsePath(account.accountPath);
    final expected = <String, String>{}; // vkey hex -> path
    for (final path in <String>{...signerPaths}) {
      final levels = parsePath(path);
      var extendsAccount = levels.length == accountLevels.length + 2;
      if (extendsAccount) {
        for (var i = 0; i < accountLevels.length; i++) {
          if (levels[i].index != accountLevels[i].index ||
              levels[i].hardened != accountLevels[i].hardened) {
            extendsAccount = false;
            break;
          }
        }
      }
      final tail = levels.sublist(accountLevels.length);
      if (!extendsAccount || tail.any((l) => l.hardened)) {
        return failed(
          'signer path $path does not extend the account path with two soft components',
        );
      }
      final vkey = cardanoSoftDerivePath(
        account.publicKey,
        account.chainCode,
        tail.map((l) => l.index).toList(),
      );
      expected[bytesToHex(vkey)] = path;
    }
    // Every requested path must have produced a witness…
    for (final entry in expected.entries) {
      if (!witnesses.any((w) => bytesToHex(w.vkey) == entry.key)) {
        return failed(
            'no witness for the requested signer path ${entry.value}');
      }
    }
    // …and every witness must belong to a requested path (no foreign keys).
    for (final witness in witnesses) {
      if (!expected.containsKey(bytesToHex(witness.vkey))) {
        return failed(
            'the witness set carries a key your request did not ask for');
      }
    }
  }
  return verified;
}

// ---------------------------------------------------------------------------
// CBOR item walker: the encoded extent of the first element of a CBOR array.
// Supports definite AND indefinite lengths (wallet-produced tx CBOR may use
// either), with depth/size hardening.
// ---------------------------------------------------------------------------

/// The encoded extent of the first element of the CBOR array in [bytes] (the
/// tx body of a full Cardano transaction). Throws [FormatException] on
/// anything that is not an array with at least one element.
Uint8List firstArrayItemBytes(Uint8List bytes) {
  if (bytes.isEmpty) throw const FormatException('empty input');
  final top = bytes[0];
  final major = top >> 5;
  if (major != 4) throw const FormatException('not a CBOR array');
  int start;
  if ((top & 0x1f) == 31) {
    start = 1; // indefinite array
  } else {
    final head = _readHead(bytes, 0);
    if (head.value == BigInt.zero) {
      throw const FormatException('transaction array is empty');
    }
    start = head.next;
  }
  final end = _skipItem(bytes, start, 0);
  return bytes.sublist(start, end);
}

/// The indefinite-length marker (additional info 31) as a head value.
final BigInt _indefinite = BigInt.from(-1);

final BigInt _maxContainerEntries = BigInt.from(1000000);

class _Head {
  const _Head(this.value, this.next);

  final BigInt value;
  final int next;
}

_Head _readHead(Uint8List bytes, int offset) {
  if (offset >= bytes.length) throw const FormatException('truncated');
  final initial = bytes[offset];
  final info = initial & 0x1f;
  if (info < 24) return _Head(BigInt.from(info), offset + 1);
  if (info == 31) return _Head(_indefinite, offset + 1); // indefinite marker
  int width;
  if (info == 24) {
    width = 1;
  } else if (info == 25) {
    width = 2;
  } else if (info == 26) {
    width = 4;
  } else if (info == 27) {
    width = 8;
  } else {
    throw const FormatException('reserved length encoding');
  }
  var value = BigInt.zero;
  for (var i = 0; i < width; i++) {
    if (offset + 1 + i >= bytes.length) {
      throw const FormatException('truncated');
    }
    value = (value << 8) | BigInt.from(bytes[offset + 1 + i]);
  }
  return _Head(value, offset + 1 + width);
}

/// Returns the offset just past the item starting at [offset].
int _skipItem(Uint8List bytes, int offset, int depth) {
  if (depth > 32) throw const FormatException('nesting too deep');
  if (offset >= bytes.length) throw const FormatException('truncated');
  final initial = bytes[offset];
  final major = initial >> 5;
  final head = _readHead(bytes, offset);

  switch (major) {
    case 0:
    case 1:
      if (head.value == _indefinite) {
        throw const FormatException('malformed integer');
      }
      return head.next;
    case 2:
    case 3:
      if (head.value == _indefinite) {
        // Indefinite string: chunks until 0xFF.
        var pos = head.next;
        while (pos >= bytes.length || bytes[pos] != 0xff) {
          final chunk = _readHead(bytes, pos);
          if (chunk.value < BigInt.zero) {
            throw const FormatException('malformed chunk');
          }
          if (chunk.value > BigInt.from(bytes.length)) {
            throw const FormatException('truncated string');
          }
          pos = chunk.next + chunk.value.toInt();
          if (pos > bytes.length) {
            throw const FormatException('truncated string');
          }
        }
        return pos + 1;
      }
      if (head.value > BigInt.from(bytes.length)) {
        throw const FormatException('truncated string');
      }
      final end = head.next + head.value.toInt();
      if (end > bytes.length) throw const FormatException('truncated string');
      return end;
    case 4:
    case 5:
      final perEntry = major == 5 ? 2 : 1;
      if (head.value == _indefinite) {
        var pos = head.next;
        while (pos >= bytes.length || bytes[pos] != 0xff) {
          for (var i = 0; i < perEntry; i++) {
            pos = _skipItem(bytes, pos, depth + 1);
          }
        }
        return pos + 1;
      }
      final count = head.value * BigInt.from(perEntry);
      if (count > _maxContainerEntries) {
        throw const FormatException('container too large');
      }
      var pos = head.next;
      final n = count.toInt();
      for (var i = 0; i < n; i++) {
        pos = _skipItem(bytes, pos, depth + 1);
      }
      return pos;
    case 6:
      if (head.value == _indefinite) {
        throw const FormatException('malformed tag');
      }
      return _skipItem(bytes, head.next, depth + 1);
    case 7:
      if ((initial & 0x1f) == 31) {
        throw const FormatException('unexpected break');
      }
      if ((initial & 0x1f) == 25) return offset + 3;
      if ((initial & 0x1f) == 26) return offset + 5;
      if ((initial & 0x1f) == 27) return offset + 9;
      return head.next;
    default:
      throw const FormatException('unreachable');
  }
}
