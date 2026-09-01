import '../accounts/accounts.dart';
import '../cbor/encode.dart';
import '../cbor/model.dart';
import '../chains/shared.dart';
import '../core/errors.dart';
import '../qr/animated_ur.dart';
import '../registry/keypath.dart';
import '../registry/multi_accounts.dart';
import '../scan/ur_scanner.dart';
import '../ur/ur.dart';

/// The curve a derivation schema requests.
enum DerivationCurve {
  /// secp256k1 (the default).
  secp256k1,

  /// Ed25519.
  ed25519,
}

/// The derivation algorithm a schema requests.
enum DerivationAlgorithm {
  /// SLIP-10 (the default).
  slip10,

  /// BIP32-Ed25519 (the Cardano Icarus scheme).
  bip32ed25519,
}

/// One derivation path the wallet asks the device to export.
class KeyDerivationSchema {
  const KeyDerivationSchema({
    required this.path,
    this.curve,
    this.algo,
    this.chainType,
  });

  /// The derivation path to request, e.g. `m/44'/60'/0'`.
  final String path;

  /// Defaults to [DerivationCurve.secp256k1].
  final DerivationCurve? curve;

  /// Defaults to [DerivationAlgorithm.slip10].
  final DerivationAlgorithm? algo;

  /// Optional chain hint shown by the device.
  final String? chainType;
}

/// Properties of a key-derivation hardware call.
class KeyDerivationCallProps {
  const KeyDerivationCallProps({required this.schemas, this.origin});

  /// The derivation schemas to request (at least one).
  final List<KeyDerivationSchema> schemas;

  /// Overrides the SDK-level origin label for this call.
  final String? origin;
}

/// The pull-model linking request: display it, then scan the device's account export back.
class HardwareCallRequest {
  HardwareCallRequest._(this.ur, this.replyTypes, this._context);

  /// The UR to display.
  final Ur ur;

  /// UR types that can answer this call.
  final List<String> replyTypes;

  final ChainContext _context;

  /// Fragment + animate for display.
  AnimatedUr toAnimated([AnimatedUrOptions? options]) {
    return AnimatedUr(
      ur,
      AnimatedUrOptions(
        maxFragmentLength:
            options?.maxFragmentLength ?? _context.maxFragmentLength,
      ),
    );
  }

  /// A scanner pre-pinned to the wallet-export reply types; its `parse()`
  /// yields the linked [EraAccounts].
  TypedUrScanner<EraAccounts> scanner() {
    return TypedUrScanner<EraAccounts>(
      UrScannerOptions(expectedTypes: replyTypes),
      (reply) => EraAccounts.fromUr(reply),
    );
  }
}

const Map<DerivationCurve, int> _curves = {
  DerivationCurve.secp256k1: 0,
  DerivationCurve.ed25519: 1,
};

const Map<DerivationAlgorithm, int> _algos = {
  DerivationAlgorithm.slip10: 0,
  DerivationAlgorithm.bip32ed25519: 1,
};

/// Build a `qr-hardware-call` (1201) wrapping a `key-derivation-call` (1301):
/// the WALLET asks the device for specific derivation paths, curves and
/// algorithms instead of accepting whatever the device's sync screen
/// volunteers. The device answers with a `crypto-multi-accounts` export,
/// which closes the loop through `EraAccounts.fromUr`.
///
/// Registry shape (Keystone-standard):
/// `1201({1: type=0, 2: 1301({1: [1302({1: 304(keypath), 2: curve, 3: algo, 4?: chainType})...]}), 3?: origin})`.
HardwareCallRequest generateKeyDerivationCall(
  ChainContext context,
  KeyDerivationCallProps props,
) {
  if (props.schemas.isEmpty) {
    throw EraSdkError(
        'invalid-props', 'at least one derivation schema is required');
  }
  final schemas = props.schemas.map((schema) {
    final levels = parsePath(schema.path);
    final entries = <(int, CborValue)>[
      (1, keypath304(levels)),
      (2, cbUint(_curves[schema.curve ?? DerivationCurve.secp256k1]!)),
      (3, cbUint(_algos[schema.algo ?? DerivationAlgorithm.slip10]!)),
    ];
    final chainType = schema.chainType;
    if (chainType != null) entries.add((4, cbText(chainType)));
    return cbTag(1302, cbMap(entries));
  }).toList();

  final call = cbTag(1301, cbMap([(1, cbArray(schemas))]));
  final root = cbMap([
    (1, cbUint(0)), // type: KeyDerivation
    (2, call),
    (3, cbText(props.origin ?? context.origin)),
  ]);

  final ur = Ur('qr-hardware-call', cborEncode(root));
  final replyTypes = [...walletUrTypes];
  return HardwareCallRequest._(ur, replyTypes, context);
}
