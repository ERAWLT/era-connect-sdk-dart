/// Air-gapped ERA hardware wallet SDK: account linking and transaction
/// signing over animated QR codes (BC-UR / Keystone-compatible registry).
///
/// The root library carries the [EraConnect] facade, the linking layer and
/// the QR transport. Per-chain modules are also importable on their own
/// (`package:era_connect/evm.dart`, `.../bch.dart`, ...), and the
/// verification helpers live in `package:era_connect/verify.dart` so their
/// curve arithmetic is only linked by apps that use it (do).
library;

import 'src/accounts/accounts.dart';
import 'src/chains/bch.dart';
import 'src/chains/btc.dart';
import 'src/chains/cardano.dart';
import 'src/chains/cosmos.dart';
import 'src/chains/evm.dart';
import 'src/chains/shared.dart';
import 'src/chains/solana.dart';
import 'src/chains/sui.dart';
import 'src/chains/ton.dart';
import 'src/chains/tron.dart';
import 'src/chains/xrp.dart';
import 'src/hardware_call/key_derivation.dart' as kd;
import 'src/hardware_call/key_derivation.dart'
    show HardwareCallRequest, KeyDerivationCallProps;
import 'src/raw.dart';
import 'src/scan/ur_scanner.dart';

export 'src/accounts/accounts.dart';
export 'src/accounts/derive.dart'
    show
        bchAddressFromPublicKey,
        btcNestedSegwitAddressFromPublicKey,
        btcP2pkhAddressFromPublicKey,
        btcP2wpkhAddressFromPublicKey,
        evmAddressFromPublicKey,
        solanaAddressFromPublicKey,
        suiAddressFromPublicKey,
        tronAddressFromPublicKey;
export 'src/chains/bch.dart';
export 'src/chains/btc.dart';
export 'src/chains/cardano.dart';
export 'src/chains/cosmos.dart';
export 'src/chains/evm.dart';
export 'src/chains/shared.dart'
    show
        ChainContext,
        EraConnectConfig,
        ExpectedReply,
        SignRequest,
        resolveContext;
export 'src/chains/solana.dart';
export 'src/chains/sui.dart';
export 'src/chains/ton.dart';
export 'src/chains/tron.dart';
export 'src/chains/xrp.dart';
export 'src/core/errors.dart';
export 'src/core/rand.dart' show RandomBytesFn;
export 'src/hardware_call/key_derivation.dart'
    show HardwareCallRequest, KeyDerivationCallProps, KeyDerivationSchema;
export 'src/qr/animated_ur.dart';
export 'src/raw.dart';
export 'src/registry/keypath.dart' show PathLevel, formatPath, parsePath;
export 'src/registry/multi_accounts.dart'
    show RawAccountEntry, RawMultiAccounts;
export 'src/scan/ur_scanner.dart';
export 'src/device_profile.dart';
export 'src/ur/limits.dart' show UrLimits;
export 'src/ur/ur.dart' show Ur;

/// The SDK facade: one instance per app, chain modules as lazy getters.
///
/// ```dart
/// final era = EraConnect(EraConnectConfig(origin: 'MyWallet'));
/// final accounts = era.parseAccounts(scannedUr); // link once
/// final request = era.evm.generateSignRequest(...); // sign anytime
/// ```
class EraConnect {
  EraConnect([EraConnectConfig? config]) : _context = resolveContext(config);

  final ChainContext _context;
  EvmChain? _evm;
  BtcChain? _btc;
  SolanaChain? _solana;
  TronChain? _tron;
  BchChain? _bch;
  TonChain? _ton;
  CardanoChain? _cardano;
  SuiChain? _sui;
  CosmosChain? _cosmos;
  XrpChain? _xrp;
  RawModule? _raw;

  EvmChain get evm => _evm ??= EvmChain(_context);

  BtcChain get btc => _btc ??= BtcChain(_context);

  SolanaChain get solana => _solana ??= SolanaChain(_context);

  TronChain get tron => _tron ??= TronChain(_context);

  /// Bitcoin Cash — the structured keystone envelope (see the bch library).
  BchChain get bch => _bch ??= BchChain(_context);

  TonChain get ton => _ton ??= TonChain(_context);

  CardanoChain get cardano => _cardano ??= CardanoChain(_context);

  SuiChain get sui => _sui ??= SuiChain(_context);

  CosmosChain get cosmos => _cosmos ??= CosmosChain(_context);

  XrpChain get xrp => _xrp ??= XrpChain(_context);

  /// Escape hatch: build/parse arbitrary URs with the hardened transport.
  RawModule get raw => _raw ??= RawModule(_context);

  /// Linking: parse the device's `crypto-multi-accounts` export (a [Ur] from
  /// a scanner, or a single-part `ur:` string).
  EraAccounts parseAccounts(Object input) => EraAccounts.fromUr(input);

  /// Pull-model linking: ask the device for SPECIFIC derivations
  /// (`qr-hardware-call` 1201). The device answers with a
  /// `crypto-multi-accounts` export.
  HardwareCallRequest generateKeyDerivationCall(KeyDerivationCallProps props) =>
      kd.generateKeyDerivationCall(_context, props);

  /// A type-agnostic hardened scanner (linking flows, raw flows).
  UrScanner scanner([UrScannerOptions? options]) => UrScanner(options);
}
