import 'dart:typed_data';

import '../core/errors.dart';
import '../registry/keypath.dart';
import '../registry/multi_accounts.dart';
import '../ur/ur.dart';
import 'derive.dart' as derive;

/// Chain family of an exported account, matched by its derivation path — never by the note label.
enum AccountChain {
  /// `m/44'/60'` — every EVM network.
  evm,

  /// `m/84'|49'|44'|86'/0'` — Bitcoin MAINNET, all script types.
  ///
  /// Coin type 1' is deliberately NOT classified as Bitcoin, and widening
  /// this would be a mistake: SLIP-44 assigns coin type 1 to "Testnet (all
  /// coins)", so `m/84'/1'/0'` is as much a Litecoin or Dogecoin testnet
  /// account as a Bitcoin one — this SDK's own `PsbtCoin` admits those
  /// chains. Classification reads the path ALONE, with no caller intent to
  /// disambiguate it, so a coin-type-1' entry stays [unknown].
  /// `EraAccounts.btc(testnet: true)` may resolve the very same entry only
  /// because the caller named the chain.
  btc,

  /// `m/44'/145'` — Bitcoin Cash.
  bch,

  /// `m/84'|49'|44'/2'` — Litecoin. Unlike coin type 1', coin type 2' is
  /// unambiguous, so attribution needs no caller intent.
  litecoin,

  /// `m/44'/3'` — Dogecoin.
  dogecoin,

  /// `m/44'/5'` — Dash.
  dash,

  /// `m/44'/501'` — Solana.
  solana,

  /// `m/44'/195'` — Tron.
  tron,

  /// `m/44'/607'` — TON.
  ton,

  /// `m/1852'/1815'` — Cardano (CIP-1852).
  cardano,

  /// `m/44'/784'` — Sui.
  sui,

  /// `m/44'/118'` — Cosmos.
  cosmos,

  /// `m/44'/144'` — XRP.
  xrp,

  /// A path this SDK does not map to a chain family.
  unknown,
}

/// One exported account key, as the wallet list surfaces it.
class AccountKey {
  const AccountKey({
    required this.chain,
    required this.path,
    required this.xfp,
    required this.publicKey,
    required this.chainCode,
    required this.name,
    required this.note,
  });

  /// The chain family, classified from [path].
  final AccountChain chain;

  /// Account-level derivation path, e.g. `m/44'/60'/0'`.
  final String path;

  /// The source fingerprint a `*-sign-request` keypath must carry for this
  /// account (lowercase 8-hex). NOT necessarily the master fingerprint.
  final String xfp;

  /// 33-byte compressed secp256k1, or 32-byte Ed25519 (Solana); absent when the export omitted it.
  final Uint8List? publicKey;

  /// The BIP-32 chain code, when the export carries one.
  final Uint8List? chainCode;

  /// A display name for the account, when present.
  final String? name;

  /// Derivation-scheme label (`account.standard`, ...) — display only.
  final String? note;
}

/// Device metadata carried by the wallet export.
class DeviceInfo {
  const DeviceInfo({
    required this.name,
    required this.id,
    required this.firmwareVersion,
  });

  /// The device name, when present.
  final String? name;

  /// The device id, when present.
  final String? id;

  /// The device firmware version, when present.
  final String? firmwareVersion;
}

AccountChain _classify(List<PathLevel> path) {
  if (path.length < 2) return AccountChain.unknown;
  final p0 = path[0];
  final p1 = path[1];
  if (!p0.hardened || !p1.hardened) return AccountChain.unknown;
  if (p0.index == 44 && p1.index == 60) return AccountChain.evm;
  if (p1.index == 0 &&
      (p0.index == 84 || p0.index == 49 || p0.index == 44 || p0.index == 86)) {
    return AccountChain.btc;
  }
  if (p0.index == 44 && p1.index == 145) return AccountChain.bch;
  if (p1.index == 2 &&
      (p0.index == 84 || p0.index == 49 || p0.index == 44)) {
    return AccountChain.litecoin;
  }
  if (p0.index == 44 && p1.index == 3) return AccountChain.dogecoin;
  if (p0.index == 44 && p1.index == 5) return AccountChain.dash;
  if (p0.index == 44 && p1.index == 501) return AccountChain.solana;
  if (p0.index == 44 && p1.index == 195) return AccountChain.tron;
  if (p0.index == 44 && p1.index == 607) return AccountChain.ton;
  if (p0.index == 1852 && p1.index == 1815) return AccountChain.cardano;
  if (p0.index == 44 && p1.index == 784) return AccountChain.sui;
  // The non-118 Cosmos zones, each on its own SLIP-44 coin type. The
  // Ethermint zones are deliberately absent: they sit on `m/44'/60'` and stay
  // classified as [AccountChain.evm], because that is what their key is —
  // `cosmos('injective')` reaches them through the EVM account.
  if (p0.index == 44 && _cosmosSlip44.contains(p1.index)) {
    return AccountChain.cosmos;
  }
  if (p0.index == 44 && p1.index == 144) return AccountChain.xrp;
  return AccountChain.unknown;
}

Uint8List _withChainCode(RawAccountEntry entry) {
  final chainCode = entry.chainCode;
  if (chainCode == null) {
    throw EraSdkError(
      'account-not-found',
      'account ${formatPath(entry.path)} carries no chain code; cannot derive children',
    );
  }
  return chainCode;
}

/// The entry's key at the required length, or a typed refusal (derivation only).
Uint8List _requireKey(RawAccountEntry entry, int length) {
  final publicKey = entry.publicKey;
  if (publicKey == null || publicKey.length != length) {
    throw EraSdkError(
      'invalid-props',
      'account ${formatPath(entry.path)} carries no $length-byte public key; '
          'xfp lookup still works, address derivation does not',
    );
  }
  return publicKey;
}

/// EVM view over the linked wallet: one account xpub, addresses derived at `0/index`.
class EvmAccountView {
  EvmAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The account-level derivation path.
  String get accountPath => formatPath(_entry.path);

  /// Signing path for address `index`: `<account>/0/<index>`.
  String pathFor(int index) => '$accountPath/0/$index';

  /// EIP-55 checksummed address at `0/index`.
  String deriveAddress(int index) {
    return derive.evmAddressFromPublicKey(
      derive.derivePublicKey(
          _requireKey(_entry, 33), _withChainCode(_entry), 0, index),
    );
  }

  /// The account-level BIP-32 extended public key.
  String xpub() => _extendedKeyOf(_entry);
}

/// The BIP purpose values a Bitcoin export may carry (44, 49, 84 or 86).
///
/// Dart has no closed integer type, so this alias names the intent while
/// [_btcPurposes] is what actually bounds it: [EraAccounts.btc] selects an
/// account for these four values and returns null for anything else.
typedef BtcPurpose = int;

/// The only purposes [EraAccounts.btc] will resolve an account for. A purpose
/// outside this set has no script type, no address encoding and no SLIP-132
/// form, so there is nothing a view over it could honestly answer.
const Set<BtcPurpose> _btcPurposes = {44, 49, 84, 86};

/// Whether [entry] is a TESTNET account, read off its coin type. SLIP-44
/// gives coin type 1 to "Testnet (all coins)"; every other coin type a
/// Bitcoin view can wrap is a mainnet account.
bool _isTestnetAccount(RawAccountEntry entry) =>
    entry.path.length >= 2 &&
    entry.path[1].hardened &&
    entry.path[1].index == 1;

/// Bitcoin view over one exported account. The default is the BIP-84
/// native-segwit account; pass `purpose` to reach the other script types the
/// device exports (44 = legacy P2PKH, 49 = nested segwit, 84 = native
/// segwit, 86 = taproot). Which of those can sign MESSAGES depends on the
/// firmware: 2.1.0+ signs 44/49/84 and refuses Taproot, older firmware signs
/// legacy P2PKH alone.
class BtcAccountView {
  /// Wraps one selected account. The NETWORK is not a parameter: it is read
  /// off [entry]'s own coin type, so a mainnet entry can never be dressed as
  /// a testnet account — which is precisely the confident wrong answer this
  /// view used to be able to produce.
  BtcAccountView(RawAccountEntry entry, this.purpose, this._resolvedXfp)
      : _entry = entry,
        _testnet = _isTestnetAccount(entry);

  final RawAccountEntry _entry;
  final bool _testnet;

  /// The BIP purpose of this account (44, 49, 84 or 86).
  final BtcPurpose purpose;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The account-level derivation path.
  String get accountPath => formatPath(_entry.path);

  /// Signing path for receive address `index`: `<account>/0/<index>`.
  String receivePath(int index) => '$accountPath/0/$index';

  /// Signing path for change address `index`: `<account>/1/<index>`.
  String changePath(int index) => '$accountPath/1/$index';

  /// The address at receive (or `change:`) `index`, in this purpose's format.
  String deriveAddress(int index, {bool change = false}) {
    final child = derive.derivePublicKey(
      _requireKey(_entry, 33),
      _withChainCode(_entry),
      change ? 1 : 0,
      index,
    );
    switch (purpose) {
      case 84:
        return derive.btcP2wpkhAddressFromPublicKey(
            child, _testnet ? 'tb' : 'bc');
      case 44:
        return derive.btcP2pkhAddressFromPublicKey(child, _testnet);
      case 49:
        return derive.btcNestedSegwitAddressFromPublicKey(child, _testnet);
      case 86:
        return derive.btcTaprootAddressFromPublicKey(
            child, _testnet ? 'tb' : 'bc');
      default:
        throw EraSdkError('invalid-props', 'unsupported BIP purpose $purpose');
    }
  }

  /// The account-level BIP-32 extended public key: `xpub…` on mainnet,
  /// `tpub…` on testnet — the version bytes follow the account this view
  /// actually selected, never the caller's expectation.
  String xpub() => _extendedKeyOf(
      _entry, _testnet ? derive.tpubVersion : derive.xpubVersion);

  /// SLIP-132 zpub form of the BIP-84 key, for tools that require it. On
  /// testnet this returns the `vpub…` form, which is SLIP-132's BIP-84
  /// testnet key — same purpose, same account, testnet version bytes.
  /// Refuses any purpose other than 84 on both networks.
  String zpub() {
    if (purpose != 84) {
      throw EraSdkError(
        'invalid-props',
        'zpub is the SLIP-132 form of the BIP-84 account only',
      );
    }
    return _extendedKeyOf(
        _entry, _testnet ? derive.vpubVersion : derive.zpubVersion);
  }
}

/// Tron view: addresses derived at `0/index`.
class TronAccountView {
  TronAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The account-level derivation path.
  String get accountPath => formatPath(_entry.path);

  /// Signing path for address `index`: `<account>/0/<index>`.
  String pathFor(int index) => '$accountPath/0/$index';

  /// Tron base58check address at `0/index`.
  String deriveAddress(int index) {
    return derive.tronAddressFromPublicKey(
      derive.derivePublicKey(
          _requireKey(_entry, 33), _withChainCode(_entry), 0, index),
    );
  }
}

/// Bitcoin Cash view: `m/44'/145'/0'`, CashAddr P2PKH addresses.
/// The Bitcoin-like altcoins, which differ only in constants.
enum UtxoChain { litecoin, dogecoin, dash }

class _UtxoChainParams {
  const _UtxoChainParams({
    required this.p2pkh,
    required this.p2sh,
    required this.purposes,
    this.hrp,
  });

  /// base58check version byte for P2PKH — Litecoin 48 ("L"), Doge 30 ("D"),
  /// Dash 76 ("X").
  final int p2pkh;

  /// base58check version byte for P2SH — Litecoin 50 ("M"), Doge 22, Dash 16.
  final int p2sh;

  /// Segwit HRP, where the chain has segwit at all.
  final String? hrp;

  /// BIP purposes the chain's derivation vector declares, best first.
  final List<int> purposes;
}

/// Taken from each coin's `CoinInfo` in the firmware, not from a registry:
/// these version bytes are the only thing separating one chain's addresses
/// from another's, so they are pinned to the device that produces the keys.
const Map<UtxoChain, _UtxoChainParams> _utxoChains = {
  UtxoChain.litecoin: _UtxoChainParams(
      p2pkh: 48, p2sh: 50, hrp: 'ltc', purposes: [84, 49, 44]),
  UtxoChain.dogecoin: _UtxoChainParams(p2pkh: 30, p2sh: 22, purposes: [44]),
  UtxoChain.dash: _UtxoChainParams(p2pkh: 76, p2sh: 16, purposes: [44]),
};

AccountChain _chainOf(UtxoChain chain) => switch (chain) {
      UtxoChain.litecoin => AccountChain.litecoin,
      UtxoChain.dogecoin => AccountChain.dogecoin,
      UtxoChain.dash => AccountChain.dash,
    };

/// A Litecoin, Dogecoin or Dash account.
///
/// The SDK signed PSBTs for these three long before it could name an address
/// for them: [_classify] returned [AccountChain.unknown] and there was no
/// view, so a caller holding a perfectly good Litecoin account had no way to
/// ask this SDK where to receive. The encoding is the same machinery Bitcoin
/// already uses, under different version bytes.
class UtxoAccountView {
  UtxoAccountView(this._entry, this._resolvedXfp, this.chain);

  final RawAccountEntry _entry;
  final int _resolvedXfp;
  final UtxoChain chain;

  _UtxoChainParams get _params => _utxoChains[chain]!;

  /// The BIP purpose this account was exported under — 84, 49 or 44.
  int get purpose => _entry.path[0].index;

  String get xfp => xfpToHex(_resolvedXfp);

  String get accountPath => formatPath(_entry.path);

  String receivePath(int index) => '$accountPath/0/$index';

  String changePath(int index) => '$accountPath/1/$index';

  Uint8List derivePublicKey(int index, {bool change = false}) =>
      derive.derivePublicKey(
        _requireKey(_entry, 33),
        _withChainCode(_entry),
        change ? 1 : 0,
        index,
      );

  /// The address at receive (or [change]) [index], in this account's script
  /// type.
  String deriveAddress(int index, {bool change = false}) {
    final child = derivePublicKey(index, change: change);
    final params = _params;
    final hrp = params.hrp;
    if (purpose == 84 && hrp != null) {
      return derive.btcP2wpkhAddressFromPublicKey(child, hrp);
    }
    if (purpose == 49) {
      return derive.nestedSegwitAddressFromPublicKey(child, params.p2sh);
    }
    if (purpose == 44) {
      return derive.p2pkhAddressFromPublicKey(child, params.p2pkh);
    }
    throw EraSdkError('invalid-props',
        '${chain.name} has no address encoding for BIP purpose $purpose');
  }

  String xpub() => _extendedKeyOf(_entry);
}

class BchAccountView {
  BchAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The account-level derivation path.
  String get accountPath => formatPath(_entry.path);

  /// Signing path for receive address `index`: `<account>/0/<index>`.
  String receivePath(int index) => '$accountPath/0/$index';

  /// Signing path for change address `index`: `<account>/1/<index>`.
  String changePath(int index) => '$accountPath/1/$index';

  /// The compressed public key at receive/change `index` — what a sign request's input names.
  Uint8List derivePublicKey(int index, {bool change = false}) {
    return derive.derivePublicKey(
      _requireKey(_entry, 33),
      _withChainCode(_entry),
      change ? 1 : 0,
      index,
    );
  }

  /// Bare CashAddr by default; `withPrefix: true` for `bitcoincash:...`.
  String deriveAddress(int index, {bool change = false, bool? withPrefix}) {
    return derive.bchAddressFromPublicKey(
      derivePublicKey(index, change: change),
      withPrefix: withPrefix ?? false,
    );
  }
}

/// TON view: one Ed25519 key per account (`m/44'/607'/0'`), shared by the
/// V4R2 and V5R1 wallet contracts — the contract version affects only the
/// ADDRESS, which this SDK leaves to TON tooling (derive it from [publicKey]
/// with your TON library).
class TonAccountView {
  TonAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The account-level derivation path.
  String get accountPath => formatPath(_entry.path);

  /// 32-byte Ed25519 public key — the signer for both wallet-contract versions.
  Uint8List get publicKey => _requireKey(_entry, 32);

  /// The account label (`name`, falling back to `note`), when present.
  String? get name => _entry.name ?? _entry.note;
}

/// Cardano view (CIP-1852): the exported account key supports SOFT public
/// derivation (BIP32-Ed25519), so payment (`0/i`), change (`1/i`) and stake
/// (`2/0`) verification keys derive locally. Bech32 ADDRESS assembly is left
/// to Cardano tooling — [deriveKey] hands you the raw vkeys it needs.
class CardanoAccountView {
  CardanoAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The account-level derivation path.
  String get accountPath => formatPath(_entry.path);

  /// The account-level extended public key material.
  Uint8List get publicKey => _requireKey(_entry, 32);

  /// The account-level chain code.
  Uint8List get chainCode => _withChainCode(_entry);

  /// Signing path for `role/index`, e.g. `pathFor(0, 0)` → `.../0/0`.
  String pathFor(int role, int index) => '$accountPath/$role/$index';

  /// Soft-derived 32-byte verification key at `role/index` (0 payment, 1 change, 2 stake).
  Uint8List deriveKey(int role, int index) {
    return derive.cardanoSoftDerivePath(
      _requireKey(_entry, 32),
      _withChainCode(_entry),
      [role, index],
    );
  }
}

/// Sui view: like Solana, each fully-hardened exported entry IS a signer.
class SuiAccountView {
  SuiAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The signer's full derivation path.
  String get path => formatPath(_entry.path);

  /// The 32-byte Ed25519 public key.
  Uint8List get publicKey => _requireKey(_entry, 32);

  /// `0x` Sui address: BLAKE2b-256 of `0x00 || publicKey`.
  String get address => derive.suiAddressFromPublicKey(_requireKey(_entry, 32));
}

/// Solana view: Ed25519 has no public child derivation, so the device
/// pre-derives hardened accounts (`m/44'/501'/idx'`) and each entry IS a
/// signer. The public key, base58, IS the address.
/// The three Solana derivation schemes, told apart by path depth:
/// `single` = `m/44'/501'`, `account` = `m/44'/501'/<n>'`,
/// `subAccount` = `m/44'/501'/<n>'/0'`.
enum SolanaScheme { single, account, subAccount }

class SolanaAccountView {
  SolanaAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The signer's full derivation path.
  String get path => formatPath(_entry.path);

  /// Which of the three Solana derivation schemes this entry belongs to.
  ///
  /// The firmware declares all three under the same `Derivation::Solana` and
  /// distinguishes them by PATH DEPTH alone — "Single Account Path"
  /// `m/44'/501'`, "Account-based Path" `m/44'/501'/<n>'`, and "Sub-account
  /// Path" `m/44'/501'/<n>'/0'`. Without this, three entries all report index
  /// 0 with three different addresses, and two entries report each of 1..4.
  SolanaScheme get scheme => switch (_entry.path.length) {
        2 => SolanaScheme.single,
        3 => SolanaScheme.account,
        _ => SolanaScheme.subAccount,
      };

  /// The hardened account index (third path level), 0 for the single-account
  /// path which has no such level. Unique only WITHIN a scheme — read it
  /// together with [scheme].
  int get index => _entry.path.length > 2 ? _entry.path[2].index : 0;

  /// The 32-byte Ed25519 public key.
  Uint8List get publicKey => _requireKey(_entry, 32);

  /// The base58 address (the public key itself).
  String get address =>
      derive.solanaAddressFromPublicKey(_requireKey(_entry, 32));
}

/// Cosmos view (`m/44'/118'/0'`): one secp256k1 account key, addresses
/// derived at `0/index`. The bech32 PREFIX is the caller's — every zone
/// spends the same key under its own HRP (`cosmos`, `osmo`, `celestia`, ...),
/// so there is no correct default and [deriveAddress] requires one.
///
/// Ethermint zones (Injective, Evmos, Dymension, ...) are the exception: they
/// sign with `m/44'/60'` keys, so they come back as the EVM account, not this
/// one.
/// One Cosmos SDK zone, as the firmware's `CosmosCoinInfo` table declares it.
class CosmosChainInfo {
  const CosmosChainInfo(this.id, this.hrp, this.slip44, {this.ethermint = false});

  /// Stable lowercase id, e.g. `osmosis`, `terra-classic`.
  final String id;

  /// bech32 human-readable part, e.g. `osmo`.
  final String hrp;

  /// SLIP-44 coin type the zone's account is derived under.
  final int slip44;

  /// True for Injective, Evmos and Dymension: EVM keys wearing a Cosmos coat.
  /// Their account sits at `m/44'/60'` and the bech32 payload is the ETHEREUM
  /// address, not the `sha256+ripemd160` hash every other zone uses.
  final bool ethermint;
}

/// Every Cosmos zone the device can export a key for, transcribed from
/// `CosmosCoinInfo.cpp`. Twenty-four of them share SLIP-44 118, so the export
/// carries ONE key for all of them and the HRP is what separates the
/// addresses — enumerate this table, never the export's entries, or a caller
/// sees two dozen identical rows.
const List<CosmosChainInfo> cosmosChains = [
  CosmosChainInfo('cosmos', 'cosmos', 118),
  CosmosChainInfo('osmosis', 'osmo', 118),
  CosmosChainInfo('celestia', 'celestia', 118),
  CosmosChainInfo('juno', 'juno', 118),
  CosmosChainInfo('akash', 'akash', 118),
  CosmosChainInfo('stride', 'stride', 118),
  CosmosChainInfo('axelar', 'axelar', 118),
  CosmosChainInfo('neutron', 'neutron', 118),
  CosmosChainInfo('dydx', 'dydx', 118),
  CosmosChainInfo('noble', 'noble', 118),
  CosmosChainInfo('sei', 'sei', 118),
  CosmosChainInfo('kujira', 'kujira', 118),
  CosmosChainInfo('stargaze', 'stars', 118),
  CosmosChainInfo('agoric', 'agoric', 118),
  CosmosChainInfo('secret', 'secret', 529),
  CosmosChainInfo('cronos', 'cro', 394),
  CosmosChainInfo('kava', 'kava', 459),
  CosmosChainInfo('terra', 'terra', 330),
  CosmosChainInfo('thorchain', 'thor', 931),
  CosmosChainInfo('injective', 'inj', 60, ethermint: true),
  CosmosChainInfo('evmos', 'evmos', 60, ethermint: true),
  CosmosChainInfo('dymension', 'dym', 60, ethermint: true),
  CosmosChainInfo('babylon', 'bbn', 118),
  CosmosChainInfo('neutaro', 'neutaro', 118),
  CosmosChainInfo('terra-classic', 'terra', 330),
  CosmosChainInfo('shentu', 'shentu', 118),
  CosmosChainInfo('persistence', 'persistence', 118),
  CosmosChainInfo('sommelier', 'somm', 118),
  CosmosChainInfo('irisnet', 'iaa', 118),
  CosmosChainInfo('regen', 'regen', 118),
  CosmosChainInfo('umee', 'umee', 118),
  CosmosChainInfo('quicksilver', 'quick', 118),
  CosmosChainInfo('gravity-bridge', 'gravity', 118),
];

final Map<String, CosmosChainInfo> _cosmosById = {
  for (final c in cosmosChains) c.id: c,
};

/// Coin types that mean "a Cosmos account", Ethermint's 60 excluded.
final Set<int> _cosmosSlip44 = {
  for (final c in cosmosChains)
    if (!c.ethermint) c.slip44,
};

/// Look up a zone by id, or throw with the id that was not found.
CosmosChainInfo cosmosChain(String id) {
  final found = _cosmosById[id];
  if (found == null) {
    throw EraSdkError('invalid-props', 'unknown Cosmos chain "$id"');
  }
  return found;
}

class CosmosAccountView {
  CosmosAccountView(this._entry, this._resolvedXfp, [this.chain]);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The zone this view was resolved for, when it was asked for by id.
  final CosmosChainInfo? chain;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The account-level derivation path.
  String get accountPath => formatPath(_entry.path);

  /// Signing path for address `index`: `<account>/0/<index>`.
  String pathFor(int index) => '$accountPath/0/$index';

  /// The compressed secp256k1 key at `0/index` — what a sign request's path names.
  Uint8List derivePublicKey(int index) {
    return derive.derivePublicKey(
        _requireKey(_entry, 33), _withChainCode(_entry), 0, index);
  }

  /// Bech32 address for this account.
  ///
  /// Pass `chain: 'osmosis'` to name a zone from the registry — that also
  /// picks the right hashing, which matters for Injective, Evmos and
  /// Dymension whose payload is the Ethereum address rather than `hash160`.
  /// Pass [prefix] for a zone the registry does not carry; that always uses
  /// the classic recipe. A view resolved through `cosmos('osmosis')` already
  /// knows its zone and needs neither.
  String deriveAddress(int index, {String? prefix, String? chain}) {
    final zone = chain != null ? cosmosChain(chain) : this.chain;
    final hrp = prefix ?? zone?.hrp;
    if (hrp == null) {
      throw EraSdkError('invalid-props',
          'name a Cosmos zone: deriveAddress(i, chain: ...) or prefix: ...');
    }
    final key = derivePublicKey(index);
    return prefix == null && (zone?.ethermint ?? false)
        ? derive.ethermintAddressFromPublicKey(key, hrp)
        : derive.cosmosAddressFromPublicKey(key, hrp);
  }
}

/// XRP view (`m/44'/144'/0'`). The device signs with ONE key — the address at
/// `0/0` — so [signingPath] names it, and the hex of `derivePublicKey(0)` is
/// what an unsigned transaction's `SigningPubKey` must carry. [pathFor] is
/// there for wallets that scan further addresses of the same account.
class XrpAccountView {
  XrpAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The account-level derivation path.
  String get accountPath => formatPath(_entry.path);

  /// The only path the device signs with: `<account>/0/0`.
  String get signingPath => '$accountPath/0/0';

  /// Signing path for address `index`: `<account>/0/<index>`.
  String pathFor(int index) => '$accountPath/0/$index';

  /// The compressed secp256k1 key at `0/index`.
  Uint8List derivePublicKey(int index) {
    return derive.derivePublicKey(
        _requireKey(_entry, 33), _withChainCode(_entry), 0, index);
  }

  /// Classic `r...` address of the key at `0/index`.
  String deriveAddress(int index) {
    return derive.xrpAddressFromPublicKey(derivePublicKey(index));
  }
}

String _extendedKeyOf(RawAccountEntry entry, [int? version]) {
  final chainCode = _withChainCode(entry);
  final publicKey = _requireKey(entry, 33);
  final last = entry.path[entry.path.length - 1];
  return derive.serializeExtendedPublicKey(
    version: version ?? derive.xpubVersion,
    depth: entry.path.length,
    parentFingerprint: entry.parentFingerprint ?? 0,
    childNumber: last.hardened ? last.index + 0x80000000 : last.index,
    chainCode: chainCode,
    publicKey: publicKey,
  );
}

/// The linked wallet: everything a software wallet extracts from the device's
/// `crypto-multi-accounts` QR. Parse once, store the source UR string, derive
/// addresses locally — the device is not needed again until signing.
class EraAccounts {
  EraAccounts._(this._raw, this.sourceUr);

  final RawMultiAccounts _raw;

  /// The single-part `ur:` string this wallet was parsed from, when it was
  /// linked from a string.
  final String? sourceUr;

  /// Parse a wallet-export UR ([Ur] or a single-part `ur:` [String]).
  static EraAccounts fromUr(Object input) {
    final raw = parseMultiAccountsUr(input);
    return EraAccounts._(
        raw, input is String ? input : (input as Ur).toString());
  }

  /// Master fingerprint, lowercase 8-hex.
  String get masterFingerprint => xfpToHex(_raw.masterFingerprint);

  /// Device metadata carried by the export.
  DeviceInfo get device => DeviceInfo(
        name: _raw.deviceName,
        id: _raw.deviceId,
        firmwareVersion: _raw.deviceVersion,
      );

  /// Every exported account key, classified by path.
  List<AccountKey> get keys {
    return _raw.entries
        .map((entry) => AccountKey(
              chain: _classify(entry.path),
              path: formatPath(entry.path),
              xfp: xfpToHex(entry.xfp ?? _raw.masterFingerprint),
              publicKey: entry.publicKey,
              chainCode: entry.chainCode,
              name: entry.name,
              note: entry.note,
            ))
        .toList();
  }

  /// The xfp a sign request must carry for the account whose path exactly
  /// equals [accountPath]. Throws `account-not-found` — never a silent zero.
  String xfpFor(String accountPath) {
    return xfpToHex(_resolveXfp(_entryFor(accountPath)));
  }

  /// Entry xfp, falling back to the wrapper's master fingerprint (Cardano-style path-only origins).
  int _resolveXfp(RawAccountEntry entry) {
    return entry.xfp ?? _raw.masterFingerprint;
  }

  RawAccountEntry? _find(bool Function(RawAccountEntry entry) test) {
    for (final entry in _raw.entries) {
      if (test(entry)) return entry;
    }
    return null;
  }

  /// The EVM account (standard `m/44'/60'/...` scheme), if the export carries one.
  EvmAccountView? evm() {
    final entry = _find((e) =>
            _isEvmAccount(e) &&
            (e.note == null || e.note == 'account.standard')) ??
        _find(_isEvmAccount);
    return entry == null ? null : EvmAccountView(entry, _resolveXfp(entry));
  }

  /// An EVM ACCOUNT, as opposed to anything else that starts `m/44'/60'`.
  ///
  /// [_classify] reads only the first two path levels, and three different
  /// things share those: the standard account `m/44'/60'/<account>'` (depth 3),
  /// the Ledger Live entries `m/44'/60'/<n>'/0/0` (depth 5, fully derived
  /// leaves) and the Ethermint keys that Injective, Evmos and Dymension are
  /// exported under, which sit at `m/44'/60'/0'/0/0` and carry no chain code.
  ///
  /// Without this, [evm] could hand back one of those leaves — and a view over
  /// a leaf reports a leaf path as its account path and derives two levels
  /// BELOW it, producing a real key at a nonsense path. A wrong address that
  /// looks entirely plausible is the worst failure this SDK can have.
  ///
  /// Depth is the whole test. Key material deliberately is NOT: an entry with
  /// no public key and no chain code still resolves its xfp for signing, which
  /// is reference behaviour, and the derivation path already refuses such an
  /// entry with a typed error.
  static bool _isEvmAccount(RawAccountEntry e) =>
      _classify(e.path) == AccountChain.evm && e.path.length == 3;

  /// A Bitcoin account view. Defaults to the BIP-84 native-segwit account;
  /// pass `purpose: 44` for legacy P2PKH, 49 for nested segwit, 86 for
  /// taproot — if the export carries them. See [BtcAccountView] for which
  /// script types can sign messages on which firmware.
  ///
  /// [purpose] is bounded to {44, 49, 84, 86}. Any other value returns null
  /// rather than a view: an arbitrary purpose has no script type and no
  /// address encoding, so a view over it could serve an `xpub()` that looks
  /// plausible and refuse only later, at the first address.
  ///
  /// [testnet] SELECTS the account: it looks for the FIRST entry whose first
  /// two levels are `m/<purpose>'/1'/…` rather than `m/<purpose>'/0'/…`,
  /// and the address encoding, the account path, the xfp and the extended
  /// key all follow that entry. Levels below the coin type are not examined,
  /// so an export whose only BIP-84 testnet entry is `m/84'/1'/2'` answers
  /// with that one. There is no fallback between the two networks — asking
  /// for an account the export does not carry returns null, because
  /// returning the other network's key under a testnet address would be a
  /// confident wrong answer.
  ///
  /// ERA firmware exports Bitcoin accounts at coin type 0' only, so
  /// `btc(testnet: true)` returns null for a current ERA wallet export. The
  /// parameter is here because the export format carries coin-type-1'
  /// accounts and other wallet profiles do export them.
  BtcAccountView? btc({bool testnet = false, BtcPurpose purpose = 84}) {
    if (!_btcPurposes.contains(purpose)) return null;
    final coinType = testnet ? 1 : 0;
    final entry = _find((e) =>
        e.path.length >= 2 &&
        e.path[0].hardened &&
        e.path[1].hardened &&
        e.path[0].index == purpose &&
        e.path[1].index == coinType);
    return entry == null
        ? null
        : BtcAccountView(entry, purpose, _resolveXfp(entry));
  }

  /// The Tron account, if the export carries one.
  TronAccountView? tron() {
    final entry = _find((e) => _classify(e.path) == AccountChain.tron);
    return entry == null ? null : TronAccountView(entry, _resolveXfp(entry));
  }

  /// The Bitcoin Cash account (`m/44'/145'/0'`), if the export carries one.
  BchAccountView? bch() {
    final entry = _find((e) => _classify(e.path) == AccountChain.bch);
    return entry == null ? null : BchAccountView(entry, _resolveXfp(entry));
  }

  /// A Litecoin, Dogecoin or Dash account. [purpose] picks the script type
  /// where the chain has more than one — Litecoin is exported as BIP-84 by
  /// every ERA profile, but a third-party profile may carry 49 or 44 instead,
  /// so the default is "whichever the export actually holds", best first.
  UtxoAccountView? utxo(UtxoChain chain, {int? purpose}) {
    final wanted = _chainOf(chain);
    final purposes = purpose == null ? _utxoChains[chain]!.purposes : [purpose];
    for (final p in purposes) {
      final entry = _find((e) =>
          _classify(e.path) == wanted &&
          e.path.length == 3 &&
          e.path[0].index == p);
      if (entry != null) {
        return UtxoAccountView(entry, _resolveXfp(entry), chain);
      }
    }
    return null;
  }

  /// The Litecoin account — BIP-84 native segwit unless the export says
  /// otherwise.
  UtxoAccountView? litecoin({int? purpose}) =>
      utxo(UtxoChain.litecoin, purpose: purpose);

  /// The Dogecoin account (`m/44'/3'/0'`, legacy P2PKH — no segwit).
  UtxoAccountView? dogecoin() => utxo(UtxoChain.dogecoin);

  /// The Dash account (`m/44'/5'/0'`, legacy P2PKH — no segwit).
  UtxoAccountView? dash() => utxo(UtxoChain.dash);

  /// The TON account (linked via the Tonkeeper-style `crypto-hdkey` export).
  TonAccountView? ton() {
    final entry = _find((e) =>
        _classify(e.path) == AccountChain.ton && e.publicKey?.length == 32);
    return entry == null ? null : TonAccountView(entry, _resolveXfp(entry));
  }

  /// All exported Sui signers (fully hardened SLIP-10 entries).
  List<SuiAccountView> sui() {
    return _raw.entries
        .where((e) =>
            _classify(e.path) == AccountChain.sui && e.publicKey?.length == 32)
        .map((e) => SuiAccountView(e, _resolveXfp(e)))
        .toList();
  }

  /// The Cardano account (CIP-1852 Icarus export), if the export carries one.
  CardanoAccountView? cardano() {
    final entry = _find((e) =>
        _classify(e.path) == AccountChain.cardano && e.publicKey?.length == 32);
    return entry == null ? null : CardanoAccountView(entry, _resolveXfp(entry));
  }

  /// All pre-derived Solana signers (usually `m/44'/501'/0'..9'`).
  /// The Solana accounts an export carries — ALREADY DERIVED by the device,
  /// one entry per key. Ed25519 hardened paths cannot be walked from a parent
  /// public key, so there is nothing to derive here and nothing beyond what
  /// the export shipped.
  ///
  /// Pass [scheme] to take one derivation scheme: the device ships all three,
  /// so an unfiltered list holds several entries reporting the same [
  /// SolanaAccountView.index] with different addresses.
  List<SolanaAccountView> solana({SolanaScheme? scheme}) {
    return _raw.entries
        .where((e) =>
            _classify(e.path) == AccountChain.solana &&
            e.publicKey?.length == 32)
        .map((e) => SolanaAccountView(e, _resolveXfp(e)))
        .where((v) => scheme == null || v.scheme == scheme)
        .toList();
  }

  /// The Cosmos account (`m/44'/118'/0'`), if the export carries one.
  /// A Cosmos account. With no argument this is the shared SLIP-44 118 entry —
  /// the one key that serves Cosmos Hub, Osmosis, Celestia and twenty-one
  /// more. Name a zone (`cosmos('kava')`) to resolve the entry that zone is
  /// actually derived under: the non-118 chains have their own coin types, and
  /// the Ethermint zones are served by the EVM account.
  CosmosAccountView? cosmos([String? chainId]) {
    if (chainId == null) {
      final entry = _find((e) => _classify(e.path) == AccountChain.cosmos);
      return entry == null ? null : CosmosAccountView(entry, _resolveXfp(entry));
    }
    final zone = cosmosChain(chainId);
    final entry = zone.ethermint
        ? _find(_isEvmAccount)
        : _find((e) =>
            e.path.length == 3 &&
            e.path[0].index == 44 &&
            e.path[0].hardened &&
            e.path[1].index == zone.slip44 &&
            e.path[1].hardened);
    return entry == null
        ? null
        : CosmosAccountView(entry, _resolveXfp(entry), zone);
  }

  /// Every Cosmos zone this export can actually serve an address for.
  List<CosmosChainInfo> availableCosmosChains() =>
      [for (final c in cosmosChains) if (cosmos(c.id) != null) c];

  /// The XRP account (`m/44'/144'/0'`), if the export carries one.
  XrpAccountView? xrp() {
    final entry = _find((e) => _classify(e.path) == AccountChain.xrp);
    return entry == null ? null : XrpAccountView(entry, _resolveXfp(entry));
  }

  RawAccountEntry _entryFor(String accountPath) {
    final levels = parsePath(accountPath);
    final entry = _find((e) => pathEquals(e.path, levels));
    if (entry == null) {
      throw EraSdkError(
        'account-not-found',
        'the linked wallet carries no account at $accountPath',
      );
    }
    return entry;
  }
}
