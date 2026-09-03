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

  /// `m/84'|49'|44'|86'/0'` — Bitcoin, all script types.
  btc,

  /// `m/44'/145'` — Bitcoin Cash.
  bch,

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
  if (p0.index == 44 && p1.index == 501) return AccountChain.solana;
  if (p0.index == 44 && p1.index == 195) return AccountChain.tron;
  if (p0.index == 44 && p1.index == 607) return AccountChain.ton;
  if (p0.index == 1852 && p1.index == 1815) return AccountChain.cardano;
  if (p0.index == 44 && p1.index == 784) return AccountChain.sui;
  if (p0.index == 44 && p1.index == 118) return AccountChain.cosmos;
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
typedef BtcPurpose = int;

/// Bitcoin view over one exported account. The default is the BIP-84
/// native-segwit account; pass `purpose` to reach the other script types the
/// device exports (44 = legacy P2PKH, 49 = nested segwit, 84 = native
/// segwit, 86 = taproot). Which of those can sign MESSAGES depends on the
/// firmware: 2.1.0+ signs 44/49/84 and refuses Taproot, older firmware signs
/// legacy P2PKH alone.
class BtcAccountView {
  BtcAccountView(this._entry, this._testnet, this.purpose, this._resolvedXfp);

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
        throw EraSdkError(
          'invalid-props',
          'taproot addresses need the BIP-341 output-key tweak; derive them from xpub() with your Bitcoin library',
        );
      default:
        throw EraSdkError('invalid-props', 'unsupported BIP purpose $purpose');
    }
  }

  /// The account-level BIP-32 extended public key.
  String xpub() => _extendedKeyOf(_entry);

  /// SLIP-132 zpub form of the BIP-84 key, for tools that require it.
  String zpub() {
    if (purpose != 84) {
      throw EraSdkError(
        'invalid-props',
        'zpub is the SLIP-132 form of the BIP-84 account only',
      );
    }
    return _extendedKeyOf(_entry, derive.zpubVersion);
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
class SolanaAccountView {
  SolanaAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

  /// The account's source fingerprint, lowercase 8-hex.
  String get xfp => xfpToHex(_resolvedXfp);

  /// The signer's full derivation path.
  String get path => formatPath(_entry.path);

  /// The hardened account index (third path level).
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
class CosmosAccountView {
  CosmosAccountView(this._entry, this._resolvedXfp);

  final RawAccountEntry _entry;
  final int _resolvedXfp;

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

  /// Bech32 address under the zone's own HRP, e.g. `prefix: 'osmo'`.
  String deriveAddress(int index, {required String prefix}) {
    return derive.cosmosAddressFromPublicKey(derivePublicKey(index), prefix);
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
            _classify(e.path) == AccountChain.evm &&
            (e.note == null || e.note == 'account.standard')) ??
        _find((e) => _classify(e.path) == AccountChain.evm);
    return entry == null ? null : EvmAccountView(entry, _resolveXfp(entry));
  }

  /// A Bitcoin account view. Defaults to the BIP-84 native-segwit account;
  /// pass `purpose: 44` for legacy P2PKH, 49 for nested segwit, 86 for
  /// taproot — if the export carries them. See [BtcAccountView] for which
  /// script types can sign messages on which firmware.
  BtcAccountView? btc({bool testnet = false, BtcPurpose purpose = 84}) {
    final entry = _find((e) =>
        _classify(e.path) == AccountChain.btc &&
        e.path.isNotEmpty &&
        e.path[0].index == purpose);
    return entry == null
        ? null
        : BtcAccountView(entry, testnet, purpose, _resolveXfp(entry));
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
  List<SolanaAccountView> solana() {
    return _raw.entries
        .where((e) =>
            _classify(e.path) == AccountChain.solana &&
            e.publicKey?.length == 32)
        .map((e) => SolanaAccountView(e, _resolveXfp(e)))
        .toList();
  }

  /// The Cosmos account (`m/44'/118'/0'`), if the export carries one.
  CosmosAccountView? cosmos() {
    final entry = _find((e) => _classify(e.path) == AccountChain.cosmos);
    return entry == null ? null : CosmosAccountView(entry, _resolveXfp(entry));
  }

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
