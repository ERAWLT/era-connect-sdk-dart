import 'dart:convert';
import 'dart:io';

import 'package:era_connect/era_connect.dart';
import 'package:test/test.dart';

/// [BtcAccountView]'s own PUBLIC constructor, driven the way an integrator
/// can drive it.
///
/// `lib/era_connect.dart` re-exports `accounts.dart` wholesale, so the
/// constructor is published API, and `parseMultiAccountsUr` hands a caller
/// exactly the material it takes ([RawAccountEntry]). Every other test in
/// this suite reaches the view through `EraAccounts.btc()`, which pre-filters
/// what it passes — the purpose bound and the coin-type check both live
/// there. So the guards INSIDE the view are, from `btc()`, unreachable: a
/// reader who deletes one sees the whole suite stay green. These tests are
/// what the constructor itself promises, with no selector in front of it.
///
/// Key material and every expectation come from the shared fixture
/// `test/fixtures/parity/accounts-testnet.json` (independently derived,
/// published BIP-32/49/84 vectors), so nothing here is this SDK agreeing
/// with itself.
void main() {
  final fixture = jsonDecode(
    File('test/fixtures/parity/accounts-testnet.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final wallet = fixture['wallet'] as Map<String, dynamic>;
  final entriesJson = (wallet['entries'] as List).cast<Map<String, dynamic>>();
  final expectations =
      (fixture['accounts'] as List).cast<Map<String, dynamic>>();

  Map<String, dynamic> materialAt(String path) =>
      entriesJson.firstWhere((e) => e['path'] == path);

  Map<String, dynamic> expectationFor(int purpose, {required bool testnet}) =>
      expectations.firstWhere(
          (a) => a['purpose'] == purpose && a['testnet'] == testnet);

  int xfpOf(String path) =>
      int.parse(materialAt(path)['xfp'] as String, radix: 16);

  /// The entry a caller gets out of [parseMultiAccountsUr] for [path],
  /// optionally re-pathed to [at] so the SAME key can be presented under a
  /// different derivation path.
  RawAccountEntry entryFor(String path, {String? at}) {
    final material = materialAt(path);
    return RawAccountEntry(
      path: parsePath(at ?? path),
      xfp: int.parse(material['xfp'] as String, radix: 16),
      publicKey: hexToBytes(material['publicKeyHex'] as String),
      chainCode: hexToBytes(material['chainCodeHex'] as String),
      parentFingerprint:
          int.parse(material['parentFingerprint'] as String, radix: 16),
      name: null,
      note: null,
    );
  }

  Matcher throwsInvalidProps(String message) => throwsA(isA<EraSdkError>()
      .having((e) => e.code, 'code', 'invalid-props')
      .having((e) => e.message, 'message', message));

  // The network is NOT a constructor parameter — it is read off the entry's
  // own coin type. There is therefore no argument, and no combination of
  // arguments, that dresses one network's key as the other's. A `testnet`
  // boolean here would put that back: passing `true` beside the m/84'/0'/0'
  // entry yields the MAINNET key under a `tb` HRP, an address on a chain
  // whose coins the account will never hold.
  group('the view answers for the entry it was given', () {
    for (final testnet in [false, true]) {
      final coinType = testnet ? "1'" : "0'";
      final network = testnet ? 'testnet' : 'mainnet';

      for (final purpose in [84, 44, 49, 86]) {
        final path = "m/$purpose'/$coinType/0'";
        final want = expectationFor(purpose, testnet: testnet);

        test('$network, purpose $purpose: paths, xfp and extended keys', () {
          final view = BtcAccountView(entryFor(path), purpose, xfpOf(path));

          expect(view.purpose, purpose);
          expect(view.accountPath, want['accountPath']);
          expect(view.xfp, want['xfp']);
          expect(view.receivePath(0), want['receivePath0']);
          expect(view.changePath(0), want['changePath0']);

          // The version bytes carry the network: xpub/tpub, zpub/vpub.
          expect(view.xpub(), want['xpub']);
          expect(view.xpub(), startsWith(testnet ? 'tpub' : 'xpub'));

          final zpub = want['zpub'] as String;
          if (zpub == 'throws:invalid-props') {
            expect(purpose, isNot(84));
            expect(
              view.zpub,
              throwsInvalidProps(
                  'zpub is the SLIP-132 form of the BIP-84 account only'),
            );
          } else {
            expect(view.zpub(), zpub);
            expect(view.zpub(), startsWith(testnet ? 'vpub' : 'zpub'));
          }
        });

        test('$network, purpose $purpose: addresses', () {
          final view = BtcAccountView(entryFor(path), purpose, xfpOf(path));
          final receive = (want['receive'] as List).cast<String>();

          if (want['deriveAddress'] == 'throws:invalid-props') {
            expect(purpose, 86);
            expect(receive, isEmpty);
            const message =
                'taproot addresses need the BIP-341 output-key tweak; '
                'derive them from xpub() with your Bitcoin library';
            expect(() => view.deriveAddress(0), throwsInvalidProps(message));
            return;
          }

          expect(receive, isNotEmpty);
          for (var i = 0; i < receive.length; i++) {
            expect(view.deriveAddress(i), receive[i], reason: 'receive $i');
          }
          expect(view.deriveAddress(0, change: true), want['change0']);
        });
      }
    }

    test('one purpose, two entries: every answer follows the entry', () {
      for (final purpose in [84, 44, 49, 86]) {
        final mainnetPath = "m/$purpose'/0'/0'";
        final testnetPath = "m/$purpose'/1'/0'";
        final mainnet =
            BtcAccountView(entryFor(mainnetPath), purpose, xfpOf(mainnetPath));
        final testnet =
            BtcAccountView(entryFor(testnetPath), purpose, xfpOf(testnetPath));

        expect(mainnet.accountPath, isNot(testnet.accountPath),
            reason: 'purpose $purpose path');
        expect(mainnet.xfp, isNot(testnet.xfp), reason: 'purpose $purpose xfp');
        expect(mainnet.xpub(), isNot(testnet.xpub()),
            reason: 'purpose $purpose xpub');
        expect(mainnet.xpub(), startsWith('xpub'));
        expect(testnet.xpub(), startsWith('tpub'));
        if (purpose != 86) {
          expect(mainnet.deriveAddress(0), isNot(testnet.deriveAddress(0)),
              reason: 'purpose $purpose address');
        }
      }
    });
  });

  // Only a HARDENED level is a SLIP-44 coin type. A `crypto-keypath` can
  // express soft levels and an export is hostile input, so m/84'/1/0' must
  // not be read as "testnet": nothing in a soft level says which network the
  // key belongs to, and the view stays on the mainnet encoding.
  //
  // `btc()` never lets such an entry through — it checks hardenedness while
  // SELECTING — which is exactly why the check inside the view needs its own
  // pin: without one, deleting it looks free.
  group('a soft level is not a coin type', () {
    const mainnetSource = "m/84'/0'/0'";
    const mainnetAddress0 = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu';
    // The same key's hash160 under the testnet HRP — an address on a chain
    // whose coins this account will never hold.
    const testnetAddress0 = 'tb1qcr8te4kr609gcawutmrza0j4xv80jy8zmfp6l0';

    BtcAccountView viewAt(String path) => BtcAccountView(
        entryFor(mainnetSource, at: path), 84, xfpOf(mainnetSource));

    test('the hardened coin type 1 IS the testnet coin type', () {
      // One key, one purpose. The apostrophe on the second level is the
      // whole difference between these two cases.
      final view = viewAt("m/84'/1'/0'");
      expect(view.accountPath, "m/84'/1'/0'");
      expect(view.deriveAddress(0), testnetAddress0);
      expect(view.xpub(), startsWith('tpub'));
      expect(view.zpub(), startsWith('vpub'));
    });

    test('a soft coin type 1 is not, so the view stays on mainnet', () {
      final view = viewAt("m/84'/1/0'");
      expect(view.accountPath, "m/84'/1/0'");
      expect(view.deriveAddress(0), mainnetAddress0);
      expect(view.deriveAddress(0), isNot(testnetAddress0));
      expect(view.xpub(), startsWith('xpub'));
      expect(view.zpub(), startsWith('zpub'));
    });

    test('a soft coin type 0 is not one either', () {
      final view = viewAt("m/84'/0/0'");
      expect(view.deriveAddress(0), mainnetAddress0);
      expect(view.xpub(), startsWith('xpub'));
    });

    test('an entry with no coin-type level at all answers mainnet', () {
      final view = viewAt("m/84'");
      expect(view.accountPath, "m/84'");
      expect(view.deriveAddress(0), mainnetAddress0);
      expect(view.xpub(), startsWith('xpub'));
    });
  });

  // Coin type is not a boolean. SLIP-44 numbers every chain, and the
  // detector reads ONE value out of the path — 1, "Testnet (all coins)" —
  // which is what its doc comment promises: "every other coin type a Bitcoin
  // view can wrap is a mainnet account". Exporting `RawAccountEntry` while
  // keeping this constructor public is what put that promise within a
  // caller's reach, and the four coin types below are the very chains this
  // SDK's own `PsbtCoin` admits through the same PSBT flow. Reading the level
  // as "anything but 0" would answer every one of them with tb1…/tpub…/vpub…:
  // testnet spellings of an account that is on neither Bitcoin network.
  group('coin type 1 alone is the testnet coin type', () {
    const source = "m/84'/0'/0'";
    const foreignCoinTypes = {
      2: 'Litecoin',
      3: 'Dogecoin',
      5: 'Dash',
      145: 'Bitcoin Cash',
    };

    foreignCoinTypes.forEach((coinType, chain) {
      test('$chain (coin type $coinType) is a mainnet account', () {
        final path = "m/84'/$coinType'/0'";
        final view =
            BtcAccountView(entryFor(source, at: path), 84, xfpOf(source));
        final want = expectationFor(84, testnet: false);

        expect(view.accountPath, path);
        expect(view.deriveAddress(0), startsWith('bc1'));
        expect(view.xpub(), startsWith('xpub'));
        expect(view.zpub(), startsWith('zpub'));

        // Same key, same depth, same child number: a coin type is not part
        // of the serialization, only the NETWORK is — and this is not a
        // testnet. So the answers are the mainnet account's own, character
        // for character, straight out of the shared fixture.
        expect(view.deriveAddress(0), (want['receive'] as List).first);
        expect(view.deriveAddress(0, change: true), want['change0']);
        expect(view.xpub(), want['xpub']);
        expect(view.zpub(), want['zpub']);
      });
    });

    test('and coin type 1, alone, is not', () {
      // The contrast, on the same key: one level's value is the whole
      // difference between the two networks' spellings.
      final view = BtcAccountView(
          entryFor(source, at: "m/84'/1'/0'"), 84, xfpOf(source));
      expect(view.deriveAddress(0), startsWith('tb1'));
      expect(view.xpub(), startsWith('tpub'));
      expect(view.zpub(), startsWith('vpub'));
    });
  });

  // The purpose bound lives on `btc()`, so the view itself accepts any
  // integer — and the last arm of its address switch is the only thing
  // standing between an unsupported purpose and a confident wrong answer.
  group('an unsupported BIP purpose is refused, never guessed', () {
    const source = "m/84'/0'/0'";

    test('by code AND message, on receive and on change', () {
      final entry = entryFor(source);
      final xfp = xfpOf(source);

      // What a "just default to native segwit" arm would answer for every
      // purpose below: the P2WPKH address of the same key, because that is
      // all the fallback could compute.
      final nativeSegwit = BtcAccountView(entry, 84, xfp).deriveAddress(0);
      expect(nativeSegwit, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');

      // 48 is BIP-48 (multisig), a path real exports carry: its funds are
      // controlled by a multisig script, so answering with the single-sig
      // address of the same key names an output the caller does not control.
      for (final purpose in [0, 1, 45, 48, 85, 87, 141, 1852]) {
        final view = BtcAccountView(entry, purpose, xfp);
        final message = 'unsupported BIP purpose $purpose';
        expect(() => view.deriveAddress(0), throwsInvalidProps(message),
            reason: 'receive, purpose $purpose');
        expect(() => view.deriveAddress(0, change: true),
            throwsInvalidProps(message),
            reason: 'change, purpose $purpose');
      }
    });

    test('and on a testnet entry too', () {
      const testnetSource = "m/84'/1'/0'";
      final view =
          BtcAccountView(entryFor(testnetSource), 48, xfpOf(testnetSource));
      expect(() => view.deriveAddress(0),
          throwsInvalidProps('unsupported BIP purpose 48'));
    });
  });
}
