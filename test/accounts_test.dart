import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:era_connect/src/accounts/accounts.dart';
import 'package:era_connect/src/accounts/derive.dart' as derive;
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/crypto/bip32.dart';
import 'package:era_connect/src/crypto/codecs.dart';
import 'package:era_connect/src/crypto/digests.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:test/test.dart';

/// Address derivation against PUBLIC standard vectors: the BIP-84 test seed
/// (the well-known test mnemonic). If any remembered constant here were wrong,
/// the two independent halves (seed-side derivation vs published addresses)
/// could not agree.
final Uint8List testSeed = hexToBytes(
  '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
);

// --- test-only private-side BIP-32 (the SDK itself is watch-only) -----------

final ECDomainParameters _domain = ECCurve_secp256k1();

Uint8List _compressed(BigInt key) =>
    Uint8List.fromList((_domain.G * key)!.getEncoded(true));

Uint8List _ser256(BigInt value) {
  final raw = bigintToBytes(value);
  final out = Uint8List(32);
  out.setAll(32 - raw.length, raw);
  return out;
}

/// A private BIP-32 node: enough of HDKey to build wallet exports in tests.
class TestHdNode {
  TestHdNode._(this._key, this.chainCode, this.parentFingerprint);

  factory TestHdNode.fromMasterSeed(Uint8List seed) {
    final i = hmacSha512(utf8Encode('Bitcoin seed'), seed);
    return TestHdNode._(
      bytesToBigint(Uint8List.sublistView(i, 0, 32)),
      Uint8List.sublistView(i, 32, 64),
      0,
    );
  }

  final BigInt _key;
  final Uint8List chainCode;
  final int parentFingerprint;

  Uint8List get publicKey => _compressed(_key);

  int get fingerprint => publicKeyFingerprint(publicKey);

  /// Derive `m/i0'/i1'/...` (every level hardened, which is what a wallet
  /// export's account entries are).
  TestHdNode deriveHardened(List<int> indices) =>
      derivePath([for (final index in indices) (index, true)]);

  /// Derive a full path, hardened or not. The soft `0/index` tail is the
  /// private side of what a watch-only view reproduces from the account key
  /// alone, so an address computed down this route owes nothing to the code
  /// under test.
  TestHdNode derivePath(List<(int, bool)> levels) {
    var node = this;
    for (final (index, hardened) in levels) {
      final data = hardened
          ? concatBytes([
              Uint8List.fromList([0]),
              _ser256(node._key),
              u32be(0x80000000 + index),
            ])
          : concatBytes([node.publicKey, u32be(index)]);
      final i = hmacSha512(node.chainCode, data);
      final il = bytesToBigint(Uint8List.sublistView(i, 0, 32));
      node = TestHdNode._(
        (il + node._key) % _domain.n,
        Uint8List.sublistView(i, 32, 64),
        node.fingerprint,
      );
    }
    return node;
  }
}

// --- expectations assembled by hand from byte primitives ---------------------

/// The bech32 address a Cosmos zone spells for [node]'s key under [prefix]:
/// hash160 of the compressed key, regrouped to 5-bit words, no witness
/// version. Built from the primitives so it shares no code with the view.
String bech32AddressOf(TestHdNode node, String prefix) {
  return bech32Encode(
    prefix,
    convertBits(hash160(node.publicKey), 8, 5, pad: true),
  );
}

/// XRPL's own base58 dictionary — the same 58 symbols as Bitcoin's, ordered
/// differently.
const String xrpAlphabet =
    'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

/// The XRPL classic address of [node]'s key, spelled out step by step:
/// `0x00 || hash160(key)`, four bytes of double-SHA-256, base58 over the XRPL
/// dictionary.
String xrpAddressOf(TestHdNode node) {
  final payload = concatBytes([
    Uint8List.fromList([0x00]),
    hash160(node.publicKey),
  ]);
  final raw =
      concatBytes([payload, Uint8List.sublistView(sha256d(payload), 0, 4)]);
  final fiftyEight = BigInt.from(58);
  var value = bytesToBigint(raw);
  final out = StringBuffer();
  while (value > BigInt.zero) {
    out.write(xrpAlphabet[(value % fiftyEight).toInt()]);
    value = value ~/ fiftyEight;
  }
  for (final b in raw) {
    if (b != 0) break;
    out.write(xrpAlphabet[0]);
  }
  return String.fromCharCodes(out.toString().codeUnits.reversed);
}

// --- wallet-export CBOR builders --------------------------------------------

CborValue pathComponents(List<(int, bool)> levels) {
  final items = <CborValue>[];
  for (final (index, hardened) in levels) {
    items
      ..add(cbUint(index))
      ..add(cbBool(hardened));
  }
  return cbArray(items);
}

CborValue accountEntry(
  TestHdNode node,
  List<(int, bool)> levels, [
  List<(int, CborValue)> extras = const [],
]) {
  return cbMap([
    (3, cbBytes(node.publicKey)),
    (4, cbBytes(node.chainCode)),
    (
      6,
      cbTag(
        304,
        cbMap([
          (1, pathComponents(levels)),
          (2, cbUint(0x12345678)),
        ]),
      )
    ),
    (8, cbUint(node.parentFingerprint)),
    ...extras,
  ]);
}

EraAccounts buildWallet() {
  final master = TestHdNode.fromMasterSeed(testSeed);
  final evm = master.deriveHardened([44, 60, 0]);
  final btc = master.deriveHardened([84, 0, 0]);
  final tron = master.deriveHardened([44, 195, 0]);
  final cosmos = master.deriveHardened([44, 118, 0]);
  final xrp = master.deriveHardened([44, 144, 0]);
  final walletCbor = cborEncode(
    cbMap([
      (1, cbUint(master.fingerprint)),
      (
        2,
        cbArray([
          accountEntry(
            evm,
            [(44, true), (60, true), (0, true)],
            [(9, cbText('Account 1'))],
          ),
          accountEntry(btc, [(84, true), (0, true), (0, true)]),
          accountEntry(tron, [(44, true), (195, true), (0, true)]),
          accountEntry(cosmos, [(44, true), (118, true), (0, true)]),
          accountEntry(xrp, [(44, true), (144, true), (0, true)]),
        ])
      ),
      (3, cbText('ERA Wallet')),
    ]),
  );
  return EraAccounts.fromUr(Ur('crypto-multi-accounts', walletCbor));
}

/// One chain selector as the classifier's hardened clause sees it: the
/// account path that reaches it, whether its view additionally demands a
/// 32-byte Ed25519 key, and how it answers when the export carries nothing it
/// accepts (null, or an empty list). Bitcoin is absent on purpose — `btc()`
/// is the one selector that reads the path itself, and has its own group.
typedef ChainSelectorCase = ({
  AccountChain chain,
  int purpose,
  int coinType,
  bool ed25519,
  bool Function(EraAccounts accounts) answersEmpty,
});

final List<ChainSelectorCase> chainSelectorCases = [
  (
    chain: AccountChain.evm,
    purpose: 44,
    coinType: 60,
    ed25519: false,
    answersEmpty: (a) => a.evm() == null,
  ),
  (
    chain: AccountChain.bch,
    purpose: 44,
    coinType: 145,
    ed25519: false,
    answersEmpty: (a) => a.bch() == null,
  ),
  (
    chain: AccountChain.solana,
    purpose: 44,
    coinType: 501,
    ed25519: true,
    answersEmpty: (a) => a.solana().isEmpty,
  ),
  (
    chain: AccountChain.tron,
    purpose: 44,
    coinType: 195,
    ed25519: false,
    answersEmpty: (a) => a.tron() == null,
  ),
  (
    chain: AccountChain.ton,
    purpose: 44,
    coinType: 607,
    ed25519: true,
    answersEmpty: (a) => a.ton() == null,
  ),
  (
    chain: AccountChain.cardano,
    purpose: 1852,
    coinType: 1815,
    ed25519: true,
    answersEmpty: (a) => a.cardano() == null,
  ),
  (
    chain: AccountChain.sui,
    purpose: 44,
    coinType: 784,
    ed25519: true,
    answersEmpty: (a) => a.sui().isEmpty,
  ),
  (
    chain: AccountChain.cosmos,
    purpose: 44,
    coinType: 118,
    ed25519: false,
    answersEmpty: (a) => a.cosmos() == null,
  ),
  (
    chain: AccountChain.xrp,
    purpose: 44,
    coinType: 144,
    ed25519: false,
    answersEmpty: (a) => a.xrp() == null,
  ),
];

void main() {
  group('address derivation from a linked wallet', () {
    final accounts = buildWallet();

    test('derives the canonical first EVM address of the test seed', () {
      // The universally published first address of the BIP-39 test mnemonic.
      expect(accounts.evm()?.deriveAddress(0),
          '0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
    });

    test('derives the canonical BIP-84 first receive and change addresses', () {
      final btc = accounts.btc()!;
      expect(
          btc.deriveAddress(0), 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
      expect(
          btc.deriveAddress(1), 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
      expect(btc.deriveAddress(0, change: true),
          'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el');
    });

    test('reconstructs the canonical BIP-84 zpub and the reference xpub', () {
      final btc = accounts.btc()!;
      expect(
        btc.zpub(),
        'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs',
      );
      // Independent oracle for the generic serialization: an independent BIP-32 implementation's
      // publicExtendedKey for m/84'/0'/0' of the same public seed.
      expect(
        btc.xpub(),
        'xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V',
      );
    });

    test('derives a well-formed Tron address', () {
      final address = accounts.tron()!.deriveAddress(0);
      expect(address.startsWith('T'), isTrue);
      expect(address.length, 34);
    });

    test('derives Cosmos addresses under whichever zone HRP is asked for', () {
      final cosmos = accounts.cosmos()!;
      final child = TestHdNode.fromMasterSeed(testSeed).derivePath(
          [(44, true), (118, true), (0, true), (0, false), (0, false)]);
      expect(cosmos.accountPath, "m/44'/118'/0'");
      expect(cosmos.xfp, '12345678');
      expect(cosmos.pathFor(4), "m/44'/118'/0'/0/4");
      expect(
          bytesToHex(cosmos.derivePublicKey(0)), bytesToHex(child.publicKey));
      // One key, one hash160, as many addresses as there are zones — which is
      // why the prefix has no default.
      expect(cosmos.deriveAddress(0, prefix: 'cosmos'),
          bech32AddressOf(child, 'cosmos'));
      expect(cosmos.deriveAddress(0, prefix: 'osmo'),
          bech32AddressOf(child, 'osmo'));
      expect(cosmos.deriveAddress(0, prefix: 'celestia'),
          bech32AddressOf(child, 'celestia'));
      expect(cosmos.deriveAddress(0, prefix: 'cosmos'), startsWith('cosmos1'));
    });

    test('derives the XRP classic address of the linked account', () {
      final xrp = accounts.xrp()!;
      final child = TestHdNode.fromMasterSeed(testSeed).derivePath(
          [(44, true), (144, true), (0, true), (0, false), (0, false)]);
      expect(xrp.accountPath, "m/44'/144'/0'");
      expect(xrp.xfp, '12345678');
      expect(bytesToHex(xrp.derivePublicKey(0)), bytesToHex(child.publicKey));
      expect(xrp.deriveAddress(0), xrpAddressOf(child));
      expect(xrp.deriveAddress(0), startsWith('r'));
      expect(
        xrp.deriveAddress(1),
        xrpAddressOf(TestHdNode.fromMasterSeed(testSeed).derivePath(
            [(44, true), (144, true), (0, true), (0, false), (1, false)])),
      );
    });

    test('the device signs XRP with one named path', () {
      final xrp = accounts.xrp()!;
      expect(xrp.signingPath, "m/44'/144'/0'/0/0");
      expect(xrp.pathFor(0), xrp.signingPath);
      expect(xrp.pathFor(2), "m/44'/144'/0'/0/2");
    });

    test('classifies the Cosmos and XRP entries by path, not by label', () {
      final byPath = {for (final key in accounts.keys) key.path: key.chain};
      expect(byPath["m/44'/118'/0'"], AccountChain.cosmos);
      expect(byPath["m/44'/144'/0'"], AccountChain.xrp);
      expect(byPath["m/44'/144'/0'"], isNot(AccountChain.unknown));
    });

    test('reproduces the published XRPL address of a published key', () {
      // The XRPL account whose secp256k1 signing key this is — the pairing is
      // published, so a codec that agrees with it is right about the
      // alphabet, the 0x00 type prefix and the double-SHA-256 checksum at
      // once.
      expect(
        derive.xrpAddressFromPublicKey(hexToBytes(
            '0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020')),
        'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
      );
      // The published worked example uses an Ed25519 key (0xED-prefixed).
      // The encoding does not care which curve produced the 33 bytes, and
      // pinning both proves that.
      expect(
        derive.xrpAddressFromPublicKey(hexToBytes(
            'ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32')),
        'rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN',
      );
    });

    test('paths and xfps follow the linked entries', () {
      expect(accounts.evm()?.pathFor(7), "m/44'/60'/0'/0/7");
      expect(accounts.btc()?.changePath(3), "m/84'/0'/0'/1/3");
      expect(accounts.xfpFor("m/84'/0'/0'"), '12345678');
      expect(accounts.xfpFor("m/44'/118'/0'"), '12345678');
      expect(accounts.xfpFor("m/44'/144'/0'"), '12345678');
      expect(() => accounts.xfpFor("m/49'/0'/0'"), throwsA(isA<EraSdkError>()));
    });

    test('refuses a wallet export with no derivable accounts', () {
      final empty = cborEncode(
        cbMap([
          (1, cbUint(1)),
          (
            2,
            cbArray([
              cbMap([(9, cbText('x'))])
            ])
          ),
        ]),
      );
      expect(
        () => EraAccounts.fromUr(Ur('crypto-multi-accounts', empty)),
        throwsA(isA<EraSdkError>()
            .having((e) => e.message, 'message', contains('no account'))),
      );
    });

    test('refuses a non-wallet UR type', () {
      expect(
        () => EraAccounts.fromUr(
            Ur('eth-signature', cborEncode(cbMap([(1, cbUint(1))])))),
        throwsA(
            isA<EraSdkError>().having((e) => e.code, 'code', 'wrong-ur-type')),
      );
    });
  });

  group('xfp fallback for path-only origins', () {
    // Cardano-style entries ship an origin with a path but NO source
    // fingerprint (key 2) — the wrapper's master fingerprint takes over.
    final pub = derive.ed25519ScalarMultBase(BigInt.from(7));
    final chainCode = sha256(utf8Encode('path-only-origin-cc'));
    final walletCbor = cborEncode(
      cbMap([
        (1, cbUint(0xaabbccdd)),
        (
          2,
          cbArray([
            cbMap([
              (3, cbBytes(pub)),
              (4, cbBytes(chainCode)),
              (
                6,
                cbTag(
                  304,
                  cbMap([
                    (1, pathComponents([(1852, true), (1815, true), (0, true)]))
                  ]),
                )
              ),
            ]),
          ])
        ),
      ]),
    );
    final accounts =
        EraAccounts.fromUr(Ur('crypto-multi-accounts', walletCbor));

    test('the master fingerprint answers for the entry', () {
      expect(accounts.masterFingerprint, 'aabbccdd');
      expect(accounts.keys[0].xfp, 'aabbccdd');
      expect(accounts.cardano()?.xfp, 'aabbccdd');
      expect(accounts.xfpFor("m/1852'/1815'/0'"), 'aabbccdd');
    });

    test('the Cardano view still soft-derives from the entry key', () {
      final cardano = accounts.cardano()!;
      expect(cardano.pathFor(0, 0), "m/1852'/1815'/0'/0/0");
      final payment = cardano.deriveKey(0, 0);
      final stake = cardano.deriveKey(2, 0);
      expect(payment.length, 32);
      expect(stake.length, 32);
      expect(bytesToHex(payment), isNot(bytesToHex(stake)));
    });
  });

  group('the note is a label, never chain metadata', () {
    final master = TestHdNode.fromMasterSeed(testSeed);

    CborValue entryWithNote(
      TestHdNode node,
      List<(int, bool)> levels,
      int xfp,
      String? note,
    ) {
      return cbMap([
        (3, cbBytes(node.publicKey)),
        (4, cbBytes(node.chainCode)),
        (
          6,
          cbTag(
            304,
            cbMap([
              (1, pathComponents(levels)),
              (2, cbUint(xfp)),
            ]),
          )
        ),
        (8, cbUint(node.parentFingerprint)),
        if (note != null) (10, cbText(note)),
      ]);
    }

    test('classification follows the path even under a foreign note', () {
      final sol = derive.ed25519ScalarMultBase(BigInt.from(9));
      final walletCbor = cborEncode(
        cbMap([
          (1, cbUint(1)),
          (
            2,
            cbArray([
              cbMap([
                (3, cbBytes(sol)),
                (
                  6,
                  cbTag(
                    304,
                    cbMap([
                      (1, pathComponents([(44, true), (501, true), (0, true)])),
                      (2, cbUint(0x33333333)),
                    ]),
                  )
                ),
                (10, cbText('account.standard')),
              ]),
            ])
          ),
        ]),
      );
      final accounts =
          EraAccounts.fromUr(Ur('crypto-multi-accounts', walletCbor));
      expect(accounts.keys[0].chain, AccountChain.solana);
      expect(accounts.evm(), isNull);
      expect(accounts.solana().first.address,
          derive.solanaAddressFromPublicKey(sol));
    });

    test('evm() prefers the standard-scheme entry over other notes', () {
      final ledger = master.deriveHardened([44, 60, 1]);
      final standard = master.deriveHardened([44, 60, 0]);
      final walletCbor = cborEncode(
        cbMap([
          (1, cbUint(1)),
          (
            2,
            cbArray([
              entryWithNote(ledger, [(44, true), (60, true), (1, true)],
                  0x11110001, 'account.ledger_live'),
              entryWithNote(standard, [(44, true), (60, true), (0, true)],
                  0x11111111, 'account.standard'),
            ])
          ),
        ]),
      );
      final accounts =
          EraAccounts.fromUr(Ur('crypto-multi-accounts', walletCbor));
      expect(accounts.evm()?.accountPath, "m/44'/60'/0'");
      expect(accounts.evm()?.xfp, '11111111');
    });

    test('evm() falls back to the only entry when no note matches', () {
      final ledger = master.deriveHardened([44, 60, 1]);
      final walletCbor = cborEncode(
        cbMap([
          (1, cbUint(1)),
          (
            2,
            cbArray([
              entryWithNote(ledger, [(44, true), (60, true), (1, true)],
                  0x11110001, 'account.ledger_live'),
            ])
          ),
        ]),
      );
      final accounts =
          EraAccounts.fromUr(Ur('crypto-multi-accounts', walletCbor));
      expect(accounts.evm()?.accountPath, "m/44'/60'/1'");
    });
  });

  group('standalone crypto-hdkey export (Tonkeeper-style TON link)', () {
    final pub = Uint8List.fromList(List.filled(32, 3));
    final hdkey = cborEncode(
      cbMap([
        (3, cbBytes(pub)),
        (
          6,
          cbTag(
            304,
            cbMap([
              (1, pathComponents([(44, true), (607, true), (0, true)])),
              (2, cbUint(0xdeadbeef)),
            ]),
          )
        ),
        (10, cbText('ERA_Main')),
      ]),
    );

    test('parses the {3,6,10} minimal shape into a TON view', () {
      final accounts = EraAccounts.fromUr(Ur('crypto-hdkey', hdkey));
      expect(accounts.masterFingerprint, 'deadbeef');
      final ton = accounts.ton()!;
      expect(ton.accountPath, "m/44'/607'/0'");
      expect(ton.xfp, 'deadbeef');
      expect(ton.publicKey, pub);
      expect(ton.name, 'ERA_Main');
      expect(accounts.keys[0].chain, AccountChain.ton);
    });

    test('refuses an hdkey without an origin keypath', () {
      final bare = cborEncode(cbMap([(3, cbBytes(pub))]));
      expect(
        () => EraAccounts.fromUr(Ur('crypto-hdkey', bare)),
        throwsA(isA<EraSdkError>()
            .having((e) => e.code, 'code', 'malformed-reply')),
      );
    });
  });

  // The pull model (`generateKeyDerivationCall`) is answered with an export
  // whose entry is the FULL signing path — a five-level leaf, not an account.
  // Classification reads levels 0 and 1 only, so that leaf still classifies as
  // XRP and `xrp()` wraps it AS THOUGH it were an account: `signingPath` and
  // `derivePublicKey` then sit two BIP-32 levels below the only key the device
  // will sign with. `doc/getting-started/02-link-device.md` documents exactly
  // this and sends the reader to `keys` instead; these tests are what makes
  // that page's claims checkable rather than remembered.
  group('a pull-model XRP answer is a leaf, not an account', () {
    final master = TestHdNode.fromMasterSeed(testSeed);
    final leafLevels = <(int, bool)>[
      (44, true),
      (144, true),
      (0, true),
      (0, false),
      (0, false),
    ];
    final leaf = master.derivePath(leafLevels);
    final accounts = EraAccounts.fromUr(Ur(
      'crypto-multi-accounts',
      cborEncode(cbMap([
        (1, cbUint(master.fingerprint)),
        (2, cbArray([accountEntry(leaf, leafLevels)])),
      ])),
    ));

    test('the leaf classifies as XRP, so xrp() does NOT return null', () {
      expect(accounts.keys.single.path, "m/44'/144'/0'/0/0");
      expect(accounts.keys.single.chain, AccountChain.xrp);
      expect(accounts.xrp(), isNotNull);
    });

    test('and the view it returns is two levels too deep', () {
      final view = accounts.xrp()!;
      expect(view.accountPath, "m/44'/144'/0'/0/0");
      expect(view.signingPath, "m/44'/144'/0'/0/0/0/0");
      expect(bytesToHex(view.derivePublicKey(0)),
          isNot(bytesToHex(leaf.publicKey)));
      expect(view.deriveAddress(0), isNot(xrpAddressOf(leaf)));
    });

    test('the documented route reads the signing key itself', () {
      final key =
          accounts.keys.firstWhere((k) => k.path == "m/44'/144'/0'/0/0");
      expect(bytesToHex(key.publicKey!), bytesToHex(leaf.publicKey));
      expect(
          derive.xrpAddressFromPublicKey(key.publicKey!), xrpAddressOf(leaf));
    });
  });

  // Nine of the ten chain selectors are `_classify(path) == <chain>` and
  // nothing else, so ONE clause inside the classifier — the first two levels
  // must both be hardened — is the entire hardened gate for all nine. An
  // export is hostile input and a `crypto-keypath` can spell a soft level, so
  // without that clause an entry at `m/44/60'/0'` would come back as THE EVM
  // account of the linked wallet: a different key, under a path the device
  // will not sign for. Bitcoin is the tenth and the exception — it checks
  // hardenedness while selecting, and is pinned in the group below.
  group('a soft top level is not a chain', () {
    final master = TestHdNode.fromMasterSeed(testSeed);
    // The four Ed25519 selectors also require a 32-byte key. Handed a
    // secp256k1 one they answer empty on the LENGTH and never reach the
    // clause under test — which is what the positive control catches.
    final ed25519Key = derive.ed25519ScalarMultBase(BigInt.from(9));
    final chainCode = sha256(utf8Encode('soft-top-level-cc'));

    EraAccounts walletOf(List<(int, bool)> levels, {required bool ed25519}) {
      final entry = cbMap([
        (
          3,
          cbBytes(ed25519 ? ed25519Key : master.derivePath(levels).publicKey)
        ),
        (4, cbBytes(chainCode)),
        (
          6,
          cbTag(
            304,
            cbMap([
              (1, pathComponents(levels)),
              (2, cbUint(0x12345678)),
            ]),
          )
        ),
      ]);
      return EraAccounts.fromUr(Ur(
        'crypto-multi-accounts',
        cborEncode(cbMap([
          (1, cbUint(master.fingerprint)),
          (2, cbArray([entry])),
        ])),
      ));
    }

    for (final selector in chainSelectorCases) {
      test('${selector.chain.name}: neither top level may be soft', () {
        for (final softLevel in [0, 1]) {
          final accounts = walletOf(
            [
              (selector.purpose, softLevel != 0),
              (selector.coinType, softLevel != 1),
              (0, true),
            ],
            ed25519: selector.ed25519,
          );
          final path = accounts.keys.single.path;
          expect(accounts.keys.single.chain, AccountChain.unknown,
              reason: path);
          expect(selector.answersEmpty(accounts), isTrue, reason: path);
        }

        // The positive control: the SAME entry with both levels hardened IS
        // that chain, and its selector answers with it. Without it the two
        // assertions above would pass just as well on an entry no selector
        // could ever have accepted.
        final accounts = walletOf(
          [
            (selector.purpose, true),
            (selector.coinType, true),
            (0, true),
          ],
          ed25519: selector.ed25519,
        );
        expect(accounts.keys.single.chain, selector.chain);
        expect(selector.answersEmpty(accounts), isFalse);
      });
    }
  });

  // The `testnet` flag SELECTS the account (coin type 1'), it does not just
  // re-spell the mainnet one under a testnet HRP. The exact addresses and
  // extended keys of every purpose on both networks live in the SHARED
  // fixture `test/fixtures/parity/accounts-testnet.json` and are asserted by
  // `accounts_testnet_parity_test.dart`; what is left here is the behaviour
  // that fixture cannot express — which entry is picked, which asks are
  // refused outright, and what a coin-type-1' path classifies as.
  group('Bitcoin: the network selects the account', () {
    final master = TestHdNode.fromMasterSeed(testSeed);

    /// A three-level account entry with an explicit origin xfp, so that WHICH
    /// entry a view selected is visible in its xfp alone. Levels are given as
    /// `(index, hardened)` because the hardened-ness of the first two is part
    /// of what selection must check.
    CborValue btcEntry(List<(int, bool)> levels, int xfp) {
      final node = master.derivePath(levels);
      return cbMap([
        (3, cbBytes(node.publicKey)),
        (4, cbBytes(node.chainCode)),
        (
          6,
          cbTag(
            304,
            cbMap([
              (1, pathComponents(levels)),
              (2, cbUint(xfp)),
            ]),
          )
        ),
        (8, cbUint(node.parentFingerprint)),
      ]);
    }

    /// `m/<p0>'/<p1>'/0'`, every level hardened — a normal account entry.
    CborValue account(int p0, int p1, int xfp) =>
        btcEntry([(p0, true), (p1, true), (0, true)], xfp);

    EraAccounts walletOf(List<CborValue> entries) {
      return EraAccounts.fromUr(Ur(
        'crypto-multi-accounts',
        cborEncode(cbMap([
          (1, cbUint(master.fingerprint)),
          (2, cbArray(entries)),
        ])),
      ));
    }

    const purposes = [84, 44, 49, 86];

    /// The xfp given to the entry for [purpose] on each network: `aa0000xx`
    /// on mainnet, `bb0000xx` on testnet, where `xx` is the purpose in hex
    /// (84 -> `54`). One glance at an xfp says which entry a view picked.
    String xfpHex(int purpose, {required bool testnet}) =>
        '${testnet ? 'bb' : 'aa'}0000'
        '${purpose.toRadixString(16).padLeft(2, '0')}';

    /// `m/<purpose>'/0'/0'` for each purpose.
    List<CborValue> mainnetEntries() =>
        [for (final p in purposes) account(p, 0, 0xaa000000 + p)];

    /// `m/<purpose>'/1'/0'` for each purpose.
    List<CborValue> testnetEntries() =>
        [for (final p in purposes) account(p, 1, 0xbb000000 + p)];

    group('an export carrying both networks', () {
      // Testnet entries come FIRST in the list: a mainnet lookup has to walk
      // past all four of them to reach its own account.
      final accounts = walletOf([...testnetEntries(), ...mainnetEntries()]);

      test('btc() selects coin type 0 for every purpose', () {
        for (final purpose in purposes) {
          final btc = accounts.btc(purpose: purpose)!;
          expect(btc.accountPath, "m/$purpose'/0'/0'",
              reason: 'purpose $purpose path');
          expect(btc.xfp, xfpHex(purpose, testnet: false),
              reason: 'purpose $purpose xfp');
        }
      });

      test('btc(testnet: true) selects coin type 1 for every purpose', () {
        for (final purpose in purposes) {
          final btc = accounts.btc(purpose: purpose, testnet: true)!;
          expect(btc.accountPath, "m/$purpose'/1'/0'",
              reason: 'purpose $purpose path');
          expect(btc.xfp, xfpHex(purpose, testnet: true),
              reason: 'purpose $purpose xfp');
        }
      });

      test('the two networks never share an answer', () {
        for (final purpose in purposes) {
          final mainnet = accounts.btc(purpose: purpose)!;
          final testnet = accounts.btc(purpose: purpose, testnet: true)!;
          expect(testnet.accountPath, isNot(mainnet.accountPath),
              reason: 'purpose $purpose path');
          expect(testnet.xfp, isNot(mainnet.xfp),
              reason: 'purpose $purpose xfp');
          expect(testnet.xpub(), isNot(mainnet.xpub()),
              reason: 'purpose $purpose xpub');
        }
      });
    });

    // Item that used to come for free from the chain classifier: the old
    // predicate ran `_classify(e.path) == AccountChain.btc`, which bounded
    // `purpose` to the four BIP values as a side effect. Selecting on a bare
    // integer lost that bound, and `typedef BtcPurpose = int` lets any int
    // compile.
    // The purposes the bound must refuse. The export built for them CARRIES
    // an account at every one, on BOTH coin types, so widening the bound by a
    // single value turns one of these asks non-null. Without that the null is
    // an empty search agreeing with the guard and the test measures nothing.
    // The same list is used by the TypeScript SDK's suite, value for value.
    //
    // -1 is not in it and cannot be: a derivation index is unsigned, so no
    // export can carry `m/-1'/…`. It gets its own test below — the one
    // refusal here that no fixture can make real.
    const foreignPurposes = [0, 1, 43, 45, 48, 60, 85, 87, 1852];

    group('the purpose is bounded to the four BIP values', () {
      /// `m/<p>'/0'/0'` and `m/<p>'/1'/0'` for every refused purpose, each
      /// with an xfp that names which entry a leaked view would have picked.
      List<CborValue> foreignEntries() => [
            for (final p in foreignPurposes) ...[
              account(p, 0, 0xcc000000 + p),
              account(p, 1, 0xdd000000 + p),
            ],
          ];

      String foreignXfp(int purpose, {required bool testnet}) =>
          ((testnet ? 0xdd000000 : 0xcc000000) + purpose)
              .toRadixString(16)
              .padLeft(8, '0');

      // An export that really CARRIES the out-of-set accounts, so a null
      // answer is the guard talking and not an empty search.
      final accounts = walletOf([
        ...foreignEntries(),
        ...mainnetEntries(),
        ...testnetEntries(),
      ]);

      test('the out-of-set entries are present and addressable by path', () {
        final paths = accounts.keys.map((k) => k.path).toList();
        for (final purpose in foreignPurposes) {
          for (final testnet in [false, true]) {
            final path = "m/$purpose'/${testnet ? 1 : 0}'/0'";
            expect(paths, contains(path), reason: path);
            expect(accounts.xfpFor(path), foreignXfp(purpose, testnet: testnet),
                reason: path);
          }
        }
      });

      test('btc() refuses every purpose outside {44, 49, 84, 86}', () {
        for (final purpose in foreignPurposes) {
          expect(accounts.btc(purpose: purpose), isNull,
              reason: 'mainnet, purpose $purpose');
          expect(accounts.btc(purpose: purpose, testnet: true), isNull,
              reason: 'testnet, purpose $purpose');
        }
      });

      test('and a negative purpose, which no export could carry', () {
        expect(accounts.btc(purpose: -1), isNull);
        expect(accounts.btc(purpose: -1, testnet: true), isNull);
      });

      test('the four supported purposes still resolve on both networks', () {
        for (final purpose in purposes) {
          expect(
              accounts.btc(purpose: purpose)?.accountPath, "m/$purpose'/0'/0'");
          expect(accounts.btc(purpose: purpose, testnet: true)?.accountPath,
              "m/$purpose'/1'/0'");
        }
      });
    });

    // A crypto-keypath can express soft levels, and an export is hostile
    // input. Without the hardened-ness clause an entry at m/84'/1/0' would be
    // served as a Bitcoin testnet account.
    group('the first two levels must be hardened', () {
      test('a soft coin type is not a network', () {
        final accounts = walletOf([
          btcEntry([(84, true), (1, false), (0, true)], 0xbb000054),
          btcEntry([(84, true), (0, false), (0, true)], 0xaa000054),
        ]);
        expect(accounts.keys.map((k) => k.path), ["m/84'/1/0'", "m/84'/0/0'"]);
        expect(accounts.btc(testnet: true), isNull);
        expect(accounts.btc(), isNull);
      });

      test('a soft purpose is not a script type', () {
        final accounts = walletOf([
          btcEntry([(84, false), (1, true), (0, true)], 0xbb000054),
          btcEntry([(84, false), (0, true), (0, true)], 0xaa000054),
        ]);
        expect(accounts.keys.map((k) => k.path), ["m/84/1'/0'", "m/84/0'/0'"]);
        expect(accounts.btc(testnet: true), isNull);
        expect(accounts.btc(), isNull);
      });

      test('the same levels, hardened, do resolve', () {
        final accounts = walletOf([account(84, 1, 0xbb000054)]);
        expect(accounts.btc(testnet: true)?.accountPath, "m/84'/1'/0'");
      });
    });

    // A `crypto-keypath` may carry a path of ANY length from one level up,
    // and the parser keeps it — so an entry shorter than the two levels
    // selection reads is input this SDK really sees, not a hypothesis.
    // Reading level 1 of it without a length check is a range error thrown
    // out of a public method, where every other refusal on this path is a
    // typed `EraSdkError` or a null the caller can branch on.
    group('an entry shorter than the levels selection reads', () {
      /// `m/84'` — one level, so `path[1]` does not exist.
      CborValue shortEntry(int xfp) => btcEntry([(84, true)], xfp);

      test('is walked past, and the real account still resolves', () {
        final accounts = walletOf([
          shortEntry(0xee000054),
          account(84, 0, 0xaa000054),
          account(84, 1, 0xbb000054),
        ]);
        // It IS a parsed entry sitting ahead of the accounts, not one the
        // parser dropped: selection really does have to walk past it.
        expect(accounts.keys.first.path, "m/84'");

        final mainnet = accounts.btc()!;
        expect(mainnet.accountPath, "m/84'/0'/0'");
        expect(mainnet.xfp, 'aa000054');

        final testnet = accounts.btc(testnet: true)!;
        expect(testnet.accountPath, "m/84'/1'/0'");
        expect(testnet.xfp, 'bb000054');
      });

      test('and on its own it answers null, on every purpose and network', () {
        final accounts = walletOf([shortEntry(0xee000054)]);
        for (final purpose in purposes) {
          expect(accounts.btc(purpose: purpose), isNull,
              reason: 'mainnet, purpose $purpose');
          expect(accounts.btc(purpose: purpose, testnet: true), isNull,
              reason: 'testnet, purpose $purpose');
        }
        // The path is still addressable by name — the entry is refused as an
        // ACCOUNT, not discarded.
        expect(accounts.xfpFor("m/84'"), 'ee000054');
      });
    });

    test(
        'a mainnet-only export refuses a testnet ask instead of re-spelling '
        'the mainnet key', () {
      final accounts = walletOf(mainnetEntries());
      final mainnet = accounts.btc()!;
      // The regression this change exists to prevent: the old predicate
      // ignored `testnet` when SELECTING, so this call handed back the
      // MAINNET account and merely re-spelled its key under a testnet HRP.
      // Both strings below come from one and the same child key, so the
      // second is the mainnet address's own hash160 wearing a `tb` prefix —
      // an address on a chain whose coins this account will never hold.
      final mainnetChild = master.derivePath(
          [(84, true), (0, true), (0, true), (0, false), (0, false)]).publicKey;
      expect(derive.btcP2wpkhAddressFromPublicKey(mainnetChild),
          'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
      expect(derive.btcP2wpkhAddressFromPublicKey(mainnetChild, 'tb'),
          'tb1qcr8te4kr609gcawutmrza0j4xv80jy8zmfp6l0');
      // Selection must fail instead of producing that.
      final testnetAsk = accounts.btc(testnet: true);
      expect(testnetAsk, isNull);
      expect(testnetAsk?.accountPath, isNot(mainnet.accountPath));
      expect(testnetAsk?.xfp, isNot(mainnet.xfp));
      expect(testnetAsk?.xpub(), isNot(mainnet.xpub()));
      for (final purpose in purposes) {
        expect(accounts.btc(purpose: purpose, testnet: true), isNull,
            reason: 'purpose $purpose');
      }
      // …and the mainnet account is untouched by any of it.
      expect(mainnet.accountPath, "m/84'/0'/0'");
      expect(mainnet.deriveAddress(0),
          'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
    });

    test('a testnet-only export answers the testnet ask and only that one', () {
      final accounts = walletOf(testnetEntries());
      for (final purpose in purposes) {
        expect(accounts.btc(purpose: purpose), isNull,
            reason: 'mainnet ask, purpose $purpose');
      }
      final btc = accounts.btc(testnet: true)!;
      expect(btc.accountPath, "m/84'/1'/0'");
      expect(btc.xfp, 'bb000054'); // 0xbb000000 | 84
      // The path is still addressable by name, whatever it classifies as.
      expect(accounts.xfpFor("m/84'/1'/0'"), 'bb000054');
    });

    test('classify leaves a coin-type-1 path unknown, on purpose', () {
      // SLIP-44 gives coin type 1 to "Testnet (all coins)", so m/84'/1'/0' is
      // as much a Litecoin or Dogecoin testnet account as a Bitcoin one —
      // PsbtCoin admits those chains. Attribution reads the path alone, with
      // no caller intent to disambiguate it, so it must stay `unknown`;
      // btc(testnet: true) may resolve the same entry only because the caller
      // named the chain.
      final accounts = walletOf(testnetEntries());
      for (final key in accounts.keys) {
        expect(key.chain, AccountChain.unknown, reason: key.path);
      }
      expect(accounts.btc(testnet: true), isNotNull);
      // The mainnet coin type is what earns the Bitcoin label.
      final mainnet = walletOf(mainnetEntries());
      for (final key in mainnet.keys) {
        expect(key.chain, AccountChain.btc, reason: key.path);
      }
    });

    test('a taproot view refuses addresses by code AND message', () {
      final accounts = walletOf([...mainnetEntries(), ...testnetEntries()]);
      for (final testnet in [false, true]) {
        final btc = accounts.btc(purpose: 86, testnet: testnet)!;
        expect(
          () => btc.deriveAddress(0),
          throwsA(isA<EraSdkError>()
              .having((e) => e.code, 'code', 'invalid-props')
              .having(
                  (e) => e.message,
                  'message',
                  'taproot addresses need the BIP-341 output-key tweak; '
                      'derive them from xpub() with your Bitcoin library')),
          reason: 'testnet: $testnet',
        );
      }
    });

    test('zpub stays a BIP-84 form on both networks, by code AND message', () {
      final accounts = walletOf([...mainnetEntries(), ...testnetEntries()]);
      for (final testnet in [false, true]) {
        for (final purpose in [44, 49, 86]) {
          expect(
            () => accounts.btc(purpose: purpose, testnet: testnet)!.zpub(),
            throwsA(isA<EraSdkError>()
                .having((e) => e.code, 'code', 'invalid-props')
                .having((e) => e.message, 'message',
                    'zpub is the SLIP-132 form of the BIP-84 account only')),
            reason: 'purpose $purpose, testnet: $testnet',
          );
        }
      }
    });
  });

  group('the golden wallet export parses end-to-end', () {
    final fixture = jsonDecode(
      File('test/fixtures/reference-golden.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    final walletUr = fixture['walletUr'] as String;
    final wallet = fixture['wallet'] as Map<String, dynamic>;

    test('links the reference wallet export', () {
      final accounts = EraAccounts.fromUr(walletUr);
      expect(accounts.sourceUr, walletUr);
      expect(accounts.masterFingerprint, wallet['masterFingerprint']);
      expect(accounts.device.name, 'ERA Wallet');
      expect(accounts.device.id, 'TEST-DEVICE-ID');
      expect(accounts.device.firmwareVersion, '9.9.9');

      final evm = wallet['evm'] as Map<String, dynamic>;
      expect(accounts.evm()?.xfp, evm['xfp']);
      expect(accounts.evm()?.accountPath, evm['accountPath']);
      expect(accounts.evm()?.pathFor(0), '${evm['accountPath']}/0/0');

      final btc = wallet['btc'] as Map<String, dynamic>;
      expect(accounts.btc()?.xfp, btc['xfp']);
      expect(accounts.btc()?.accountPath, btc['accountPath']);

      final sol = wallet['sol'] as Map<String, dynamic>;
      expect(accounts.solana().first.xfp, sol['xfp']);
      expect(accounts.solana().first.path, sol['accountPath']);

      final tron = wallet['tron'] as Map<String, dynamic>;
      expect(accounts.tron()?.xfp, tron['xfp']);
      expect(accounts.xfpFor(tron['accountPath'] as String), tron['xfp']);
    });
  });
}
