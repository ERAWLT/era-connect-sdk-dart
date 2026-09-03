import 'dart:typed_data';

import '../cbor/decode.dart';
import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../core/errors.dart';
import '../core/rand.dart';
import '../registry/keypath.dart';
import '../ur/ur.dart';
import 'shared.dart';

/// One transaction input the device must sign for.
class CardanoUtxoRef {
  const CardanoUtxoRef({
    required this.transactionHash,
    required this.index,
    required this.path,
    required this.xfp,
    this.amount,
    this.address,
  });

  /// 32-byte hash of the transaction that created the UTXO.
  final Uint8List transactionHash;

  final int index;

  /// Full signing path for this input, e.g. `m/1852'/1815'/0'/0/0`.
  final String path;

  /// The master fingerprint: a u32 [int] or an 8-hex [String].
  final Object xfp;

  /// Lovelace amount as a decimal string — device display.
  final String? amount;

  /// Bech32 address of the UTXO — device display.
  final String? address;
}

/// A certificate/withdrawal key the transaction additionally needs a witness
/// from.
class CardanoCertKeyRef {
  const CardanoCertKeyRef({
    required this.path,
    required this.xfp,
    this.keyHash,
  });

  /// Full signing path, e.g. the stake key `m/1852'/1815'/0'/2/0`.
  final String path;

  /// The master fingerprint: a u32 [int] or an 8-hex [String].
  final Object xfp;

  /// 28-byte key hash — device display/matching.
  final Uint8List? keyHash;
}

/// Inputs for [CardanoChain.generateSignRequest].
class CardanoSignRequestProps {
  const CardanoSignRequestProps({
    this.requestId,
    required this.signData,
    required this.utxos,
    this.certKeys,
    this.origin,
  });

  /// 16 raw bytes ([Uint8List]) or a UUID [String]; minted when absent.
  final Object? requestId;

  /// The FULL transaction CBOR (`[body, witness_set, is_valid, aux_data]`) as
  /// your Cardano tooling serializes it. The device extracts the body (first
  /// array element) and signs its BLAKE2b-256 hash.
  final Uint8List signData;

  /// At least one; the device signs once per UNIQUE path across utxos +
  /// certKeys.
  final List<CardanoUtxoRef> utxos;

  final List<CardanoCertKeyRef>? certKeys;

  final String? origin;
}

/// One `[vkey, signature]` pair from the reply's witness set.
class CardanoWitness {
  const CardanoWitness({required this.vkey, required this.signature});

  /// 32-byte verification key.
  final Uint8List vkey;

  /// 64-byte Ed25519 signature over the tx-body BLAKE2b-256 hash.
  final Uint8List signature;
}

/// A parsed `cardano-signature` reply.
class CardanoSignatureResult {
  const CardanoSignatureResult({
    required this.requestId,
    required this.witnessSet,
    required this.witnesses,
  });

  final Uint8List requestId;

  /// The witness-set CBOR verbatim (`{0: #6.258([[vkey, sig]…])}`) — merge it
  /// into your tx.
  final Uint8List witnessSet;

  /// The `[vkey, signature]` pairs parsed out of the witness set.
  final List<CardanoWitness> witnesses;
}

const List<String> _replyTypes = ['cardano-signature'];
const int _utxoTag = 2201;
const int _certKeyTag = 2204;

/// The 2^53-1 safe-integer bound on a utxo index.
const int _maxSafeInteger = 9007199254740991;

/// The Cardano chain module: `cardano-sign-request` out, `cardano-signature`
/// back.
class CardanoChain {
  CardanoChain([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;

  /// Build a `cardano-sign-request` (2202). Reply: `cardano-signature` (2203).
  SignRequest<CardanoSignatureResult> generateSignRequest(
    CardanoSignRequestProps props,
  ) {
    final requestId = resolveRequestId(_context, props.requestId);
    if (props.signData.isEmpty) {
      throw EraSdkError('invalid-props', 'signData must not be empty');
    }
    if (props.utxos.isEmpty) {
      throw EraSdkError('invalid-props', 'at least one utxo is required');
    }

    final utxos = props.utxos.map((utxo) {
      if (utxo.transactionHash.length != 32) {
        throw EraSdkError(
            'invalid-props', 'utxo transactionHash must be 32 bytes');
      }
      if (utxo.index < 0 || utxo.index > _maxSafeInteger) {
        throw EraSdkError(
            'invalid-props', 'utxo index must be a non-negative integer');
      }
      final entries = <(int, CborValue)>[
        (1, cbBytes(utxo.transactionHash)),
        (2, cbUint(utxo.index)),
      ];
      final amount = utxo.amount;
      if (amount != null) entries.add((3, cbText(amount)));
      entries
          .add((4, keypath304(parsePath(utxo.path), normalizeXfp(utxo.xfp))));
      final address = utxo.address;
      if (address != null) entries.add((5, cbText(address)));
      return cbTag(_utxoTag, cbMap(entries));
    }).toList();

    final certKeys =
        (props.certKeys ?? const <CardanoCertKeyRef>[]).map((certKey) {
      final entries = <(int, CborValue)>[];
      final keyHash = certKey.keyHash;
      if (keyHash != null) entries.add((1, cbBytes(keyHash)));
      entries.add(
          (2, keypath304(parsePath(certKey.path), normalizeXfp(certKey.xfp))));
      return cbTag(_certKeyTag, cbMap(entries));
    }).toList();

    final entries = <(int, CborValue)>[
      (1, cbTag(37, cbBytes(requestId))),
      (2, cbBytes(props.signData)),
      (3, cbArray(utxos)),
    ];
    if (certKeys.isNotEmpty) entries.add((4, cbArray(certKeys)));
    entries.add((5, cbText(props.origin ?? _context.origin)));

    final ur = Ur('cardano-sign-request', cborEncode(cbMap(entries)));
    return makeSignRequest(
      ur: ur,
      requestId: requestId,
      replyTypes: _replyTypes,
      context: _context,
      parse: (reply) => _parseCardanoSignature(reply, requestId),
    );
  }

  /// Parse a `cardano-signature` standalone. Prefer
  /// `SignRequest.scanner().parse()`.
  CardanoSignatureResult parseSignature(Object input, [ExpectedReply? expect]) {
    return _parseCardanoSignature(
      toUr(input),
      expect?.requestId == null ? null : normalizeRequestId(expect!.requestId!),
    );
  }
}

CardanoSignatureResult _parseCardanoSignature(
  Ur ur,
  Uint8List? expectedRequestId,
) {
  requireUrType(ur, _replyTypes, 'cardano-signature');
  final map = requireReplyMap(ur, 'cardano-signature');
  final requestId =
      requireRequestIdEcho(map, 1, expectedRequestId, 'cardano-signature');

  final witnessSet = asBytes(mapGet(map, 2));
  if (witnessSet == null || witnessSet.isEmpty) {
    throw EraSdkError(
      'malformed-reply',
      'cardano-signature is missing the witness set (key 2)',
    );
  }
  return CardanoSignatureResult(
    requestId: requestId,
    witnessSet: witnessSet,
    witnesses: parseWitnessSet(witnessSet),
  );
}

/// `[vkey, signature]` pairs from a witness-set CBOR `{0: #6.258([...])}`
/// (the set tag is optional).
List<CardanoWitness> parseWitnessSet(Uint8List witnessSet) {
  CborValue decoded;
  try {
    decoded = cborDecode(witnessSet);
  } on EraSdkError catch (e) {
    throw EraSdkError(
      'malformed-reply',
      'witness set is not readable CBOR: ${e.message}',
    );
  } catch (e) {
    throw EraSdkError(
        'malformed-reply', 'witness set is not readable CBOR: $e');
  }
  final root = stripTags(decoded);
  if (root is! CborMap) {
    throw EraSdkError('malformed-reply', 'witness set is not a CBOR map');
  }
  final vkeyWitnesses = mapGet(root, 0);
  final list = vkeyWitnesses == null ? null : stripTags(vkeyWitnesses);
  if (list is! CborArray) {
    throw EraSdkError(
        'malformed-reply', 'witness set carries no vkey witnesses (key 0)');
  }
  final witnesses = <CardanoWitness>[];
  for (final item in list.items) {
    final pair = stripTags(item);
    if (pair is! CborArray || pair.items.length < 2) {
      throw EraSdkError('malformed-reply', 'malformed vkey witness');
    }
    final vkey = asBytes(pair.items[0]);
    final signature = asBytes(pair.items[1]);
    if (vkey == null ||
        vkey.length != 32 ||
        signature == null ||
        signature.length != 64) {
      throw EraSdkError(
        'malformed-reply',
        'vkey witness is not [32-byte key, 64-byte signature]',
      );
    }
    witnesses.add(CardanoWitness(vkey: vkey, signature: signature));
  }
  if (witnesses.isEmpty) {
    throw EraSdkError('malformed-reply', 'witness set is empty');
  }
  return witnesses;
}
