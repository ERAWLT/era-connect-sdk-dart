import 'dart:typed_data';

import '../cbor/decode.dart';
import '../cbor/model.dart';
import '../core/errors.dart';
import '../ur/ur.dart';
import 'keypath.dart';

/// Raw account entry parsed from a `crypto-multi-accounts` (1103) export.
///
/// [xfp] is the entry's ORIGIN source fingerprint (`crypto-keypath` key 2) —
/// the value a `*-sign-request` keypath must carry. It is NOT the top-level
/// master fingerprint, although the two often coincide.
class RawAccountEntry {
  const RawAccountEntry({
    required this.path,
    required this.xfp,
    required this.publicKey,
    required this.chainCode,
    required this.parentFingerprint,
    required this.name,
    required this.note,
  });

  /// The account-level derivation path.
  final List<PathLevel> path;

  /// The origin's source fingerprint, when the export carries one. Cardano
  /// entries deliberately ship a path-only origin — resolve against the
  /// wrapper's master fingerprint in that case.
  final int? xfp;

  /// Nullable and length-unconstrained, as in the reference implementation:
  /// an entry without a usable key still resolves its xfp for signing — only
  /// the address-derivation views require the 33/32-byte forms.
  final Uint8List? publicKey;

  /// The BIP-32 chain code, when the export carries one.
  final Uint8List? chainCode;

  /// The parent key's fingerprint (`crypto-hdkey` key 8), when present.
  final int? parentFingerprint;

  /// A display name for the account, when present.
  final String? name;

  /// A label string (`account.standard`, ...) — NEVER chain metadata.
  final String? note;
}

/// The decoded wallet export: master fingerprint, device metadata and the
/// account entries.
class RawMultiAccounts {
  const RawMultiAccounts({
    required this.masterFingerprint,
    required this.deviceName,
    required this.deviceId,
    required this.deviceVersion,
    required this.entries,
  });

  /// The wrapper's master fingerprint (u32).
  final int masterFingerprint;

  /// The device name (key 3), when present.
  final String? deviceName;

  /// The device id (key 4), when present.
  final String? deviceId;

  /// The device firmware version (key 5), when present.
  final String? deviceVersion;

  /// The parsed account entries.
  final List<RawAccountEntry> entries;
}

/// UR types a device links a watch-only wallet with.
const Set<String> walletUrTypes = {
  'crypto-multi-accounts',
  'crypto-account',
  'crypto-hdkey',
};

/// Parse a wallet-export UR ([Ur] or a single-part `ur:` [String]).
///
/// Of the three admitted link types only the `crypto-multi-accounts` shape
/// yields derivable accounts; an export that yields none is refused rather
/// than stored as an unusable wallet. Malformed entries are skipped
/// individually so one foreign item does not abort the rest.
RawMultiAccounts parseMultiAccountsUr(Object input) {
  String type;
  Uint8List cbor;
  if (input is String) {
    final parsed = parseUrString(input);
    if (parsed.seq != null) {
      throw EraSdkError(
        'invalid-props',
        'multi-part UR string: assemble it with a UrScanner first',
      );
    }
    type = parsed.type;
    cbor = parsed.payload;
  } else if (input is Ur) {
    type = input.type;
    cbor = input.cbor;
  } else {
    throw EraSdkError(
        'invalid-props', 'wallet export must be a Ur or a ur: string');
  }

  if (!walletUrTypes.contains(type)) {
    // The type is attacker-sized (the UR grammar allows an unbounded letter
    // run) — truncate before it reaches a message or error data.
    final shown = type.length > 32 ? '${type.substring(0, 32)}…' : type;
    throw EraSdkError(
      'wrong-ur-type',
      '"$shown" is not a wallet export; expected one of ${walletUrTypes.join(', ')}',
    );
  }

  CborValue decoded;
  try {
    decoded = cborDecode(cbor);
  } on EraSdkError catch (e) {
    throw EraSdkError(
        'malformed-cbor', 'cannot decode wallet UR: ${e.message}');
  } catch (e) {
    throw EraSdkError('malformed-cbor', 'cannot decode wallet UR: $e');
  }
  final root = asMap(decoded);
  if (root == null) {
    throw EraSdkError('malformed-cbor', 'wallet UR is not a CBOR map');
  }

  // A standalone `crypto-hdkey` export (the single-account link some wallet
  // profiles use — e.g. the TON one: `{3: key, 6: keypath, 10: name}`) IS the
  // entry map itself: no master-fingerprint/list wrapper. The entry's origin
  // fingerprint doubles as the master fingerprint.
  if (type == 'crypto-hdkey') {
    final entry = _tryParseEntry(decoded);
    if (entry == null) {
      throw EraSdkError(
        'malformed-reply',
        'crypto-hdkey export carries no derivable account (missing origin keypath)',
      );
    }
    return RawMultiAccounts(
      masterFingerprint: entry.xfp ?? 0,
      deviceName: null,
      deviceId: null,
      deviceVersion: null,
      entries: [entry],
    );
  }

  final master = asUint(mapGet(root, 1));
  final list = asArray(mapGet(root, 2));
  if (master == null || list == null) {
    throw EraSdkError(
      'malformed-reply',
      'wallet UR missing master fingerprint (key 1) or accounts (key 2)',
    );
  }

  final entries = <RawAccountEntry>[];
  for (final item in list) {
    final entry = _tryParseEntry(item);
    if (entry != null) entries.add(entry);
  }
  if (entries.isEmpty) {
    throw EraSdkError(
      'malformed-reply',
      'wallet UR carries no account this SDK can derive an address from',
    );
  }

  return RawMultiAccounts(
    masterFingerprint: (master & BigInt.from(0xffffffff)).toInt(),
    deviceName: asText(mapGet(root, 3)),
    deviceId: asText(mapGet(root, 4)),
    deviceVersion: asText(mapGet(root, 5)),
    entries: entries,
  );
}

final BigInt _maxU32 = BigInt.from(0xffffffff);

RawAccountEntry? _tryParseEntry(CborValue item) {
  final map = asMap(item);
  if (map == null) return null;
  final origin = asMap(mapGet(map, 6));
  if (origin == null) return null;

  final path = parsePathComponents(mapGet(origin, 1));
  if (path == null || path.isEmpty) return null;
  final xfpValue = asUint(mapGet(origin, 2));
  final xfp = xfpValue != null && xfpValue <= _maxU32 ? xfpValue.toInt() : null;

  final parentFp = asUint(mapGet(map, 8));
  return RawAccountEntry(
    path: path,
    xfp: xfp,
    publicKey: asBytes(mapGet(map, 3)),
    chainCode: asBytes(mapGet(map, 4)),
    parentFingerprint:
        parentFp != null && parentFp <= _maxU32 ? parentFp.toInt() : null,
    name: asText(mapGet(map, 9)),
    note: asText(mapGet(map, 10)),
  );
}
