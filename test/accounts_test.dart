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

  /// Derive `m/i0'/i1'/...` (every level hardened, which is all the wallet
  /// exports in this suite need).
  TestHdNode deriveHardened(List<int> indices) {
    var node = this;
    for (final index in indices) {
      final data = concatBytes([
        Uint8List.fromList([0]),
        _ser256(node._key),
        u32be(0x80000000 + index),
      ]);
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
        ])
      ),
      (3, cbText('ERA Wallet')),
    ]),
  );
  return EraAccounts.fromUr(Ur('crypto-multi-accounts', walletCbor));
}

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
      // Independent oracle for the generic serialization: @scure/bip32's own
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

    test('paths and xfps follow the linked entries', () {
      expect(accounts.evm()?.pathFor(7), "m/44'/60'/0'/0/7");
      expect(accounts.btc()?.changePath(3), "m/84'/0'/0'/1/3");
      expect(accounts.xfpFor("m/84'/0'/0'"), '12345678');
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

  group('the golden wallet export parses end-to-end', () {
    final fixture = jsonDecode(
      File('test/fixtures/ts-parity-golden.json').readAsStringSync(),
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
