import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:era_connect/src/accounts/accounts.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/registry/keypath.dart';
import 'package:era_connect/src/registry/multi_accounts.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:test/test.dart';

/// Parity against `test/fixtures/parity/accounts-testnet.json` — the SHARED
/// artifact for Bitcoin account selection, read by this SDK and by its
/// sibling. The wallet blob is test INPUT (built once with the SDK's own
/// encoder); every expectation in it is an independently derived published
/// BIP-32/49/84 vector and is never regenerated from an implementation, so a
/// port that drifts fails here rather than agreeing with itself.
///
/// What the fixture cannot express stays in code: the refusals it only MARKS
/// (`throws:<code>`), the null answers, and the classification of a
/// coin-type-1' path. Refusals are pinned on both the `code` (API) and the
/// message, so neither half can change unnoticed.
///
/// The file states the same wallet TWICE — as `wallet.cborHex` and as
/// `wallet.ur` — and every expectation below is derived from the first. So
/// the second is pinned only by the cross-check in "the two representations
/// state the same wallet": without it, a UR carrying a flipped key byte and
/// a valid CRC32 rides along unnoticed.
void main() {
  // SHA-256 of the shared fixture as it sits on disk. The SIBLING SDK carries
  // a byte-identical copy at its own path and pins this same constant, which
  // is the only thing making the two files one artifact rather than two that
  // used to match. `dart format` does not touch JSON, so nothing in this
  // repo's gates can rewrite the file — an editor or a hand edit can, and
  // that is what this catches. The sibling's formatter DOES cover JSON and
  // therefore excludes this path in its config, for this reason.
  const sharedFixtureSha256 =
      'c754db2221e3758258b0b9b9e9b84a4fc6b3478d2e81fa44760aa251fef7822d';

  final fixtureFile = File('test/fixtures/parity/accounts-testnet.json');
  final fixtureBytes = fixtureFile.readAsBytesSync();
  final fixture = jsonDecode(utf8.decode(fixtureBytes)) as Map<String, dynamic>;
  final wallet = fixture['wallet'] as Map<String, dynamic>;
  final entries = (wallet['entries'] as List).cast<Map<String, dynamic>>();
  final expectations =
      (fixture['accounts'] as List).cast<Map<String, dynamic>>();
  final accounts = EraAccounts.fromUr(
    Ur('crypto-multi-accounts', hexToBytes(wallet['cborHex'] as String)),
  );

  String? hexOrNull(Uint8List? bytes) =>
      bytes == null ? null : bytesToHex(bytes);

  Matcher throwsInvalidProps(String message) => throwsA(isA<EraSdkError>()
      .having((e) => e.code, 'code', 'invalid-props')
      .having((e) => e.message, 'message', message));

  /// Every field of a raw entry, as comparable values. The views expose only
  /// what they need, so the raw parse is what a field-by-field comparison of
  /// two representations has to go through.
  Map<String, Object?> describe(RawAccountEntry entry) => {
        'path': formatPath(entry.path),
        'xfp': entry.xfp == null ? null : xfpToHex(entry.xfp!),
        'publicKey': hexOrNull(entry.publicKey),
        'chainCode': hexOrNull(entry.chainCode),
        'parentFingerprint': entry.parentFingerprint == null
            ? null
            : xfpToHex(entry.parentFingerprint!),
        'name': entry.name,
        'note': entry.note,
      };

  final rawFromCbor = parseMultiAccountsUr(
    Ur('crypto-multi-accounts', hexToBytes(wallet['cborHex'] as String)),
  );

  group('accounts testnet parity: the shared file', () {
    test('is byte-for-byte the artifact both SDKs read', () {
      // Not a checksum of a value this suite computed — a checksum of the
      // FILE, so a reformat, a re-ordering or a hand edit on either side is
      // a failure here instead of a silent divergence between the copies.
      expect(
        crypto.sha256.convert(fixtureBytes).toString(),
        sharedFixtureSha256,
        reason: 'the sibling SDK pins this same constant for its own copy; '
            'if you changed the fixture on purpose, update BOTH suites',
      );
    });
  });

  group('accounts testnet parity: the export', () {
    test('the two representations state the same wallet', () {
      // `cborHex` and `ur` are two spellings of one export, and EVERY
      // expectation in the file is derived from the first. Comparing them on
      // a fingerprint and a path list leaves the key material of the second
      // unpinned: a UR whose first public key ends 4b instead of b4, re-CRC'd,
      // passes that. So compare the parses field for field.
      final rawFromUrString = parseMultiAccountsUr(wallet['ur'] as String);
      expect(rawFromUrString.masterFingerprint, rawFromCbor.masterFingerprint);
      expect(rawFromUrString.deviceName, rawFromCbor.deviceName);
      expect(rawFromUrString.deviceId, rawFromCbor.deviceId);
      expect(rawFromUrString.deviceVersion, rawFromCbor.deviceVersion);
      expect(rawFromUrString.entries.length, rawFromCbor.entries.length);
      expect(
        rawFromUrString.entries.map(describe).toList(),
        rawFromCbor.entries.map(describe).toList(),
      );
    });

    test('the UR string form parses to the same wallet', () {
      final fromString = EraAccounts.fromUr(wallet['ur'] as String);
      expect(fromString.sourceUr, wallet['ur']);
      expect(fromString.masterFingerprint, wallet['masterFingerprint']);
      expect(fromString.keys.map((k) => k.path),
          entries.map((e) => e['path']).toList());
    });

    test('every entry: path, origin xfp, key material and parent', () {
      expect(accounts.masterFingerprint, wallet['masterFingerprint']);
      expect(accounts.keys.length, entries.length);
      expect(rawFromCbor.entries.length, entries.length);
      for (var i = 0; i < entries.length; i++) {
        final key = accounts.keys[i];
        final raw = rawFromCbor.entries[i];
        final want = entries[i];
        expect(key.path, want['path'], reason: 'entries[$i].path');
        expect(key.xfp, want['xfp'], reason: 'entries[$i].xfp');
        expect(hexOrNull(key.publicKey), want['publicKeyHex'],
            reason: 'entries[$i].publicKey');
        expect(hexOrNull(key.chainCode), want['chainCodeHex'],
            reason: 'entries[$i].chainCode');
        // The parent fingerprint reaches an integrator only through the raw
        // entry, and only the extended keys depend on it — read it here so
        // the field is pinned by name and not just by a wrong xpub.
        expect(raw.parentFingerprint, isNotNull,
            reason: 'entries[$i].parentFingerprint');
        expect(xfpToHex(raw.parentFingerprint!), want['parentFingerprint'],
            reason: 'entries[$i].parentFingerprint');
      }
    });

    test('the testnet entries come first, and mainnet still skips past them',
        () {
      // The fixture is ordered this way on purpose: a selector that returned
      // the first Bitcoin-looking entry would hand a mainnet caller a testnet
      // account, and this is where that fails loudly.
      expect(accounts.keys.first.path, "m/84'/1'/0'");
      expect(accounts.btc()!.accountPath, "m/84'/0'/0'");
      expect(accounts.btc()!.accountPath, isNot(accounts.keys.first.path));
    });
  });

  group('accounts testnet parity: selection', () {
    for (final want in expectations) {
      test(want['name'] as String, () {
        final purpose = want['purpose'] as int;
        final testnet = want['testnet'] as bool;
        final btc = accounts.btc(purpose: purpose, testnet: testnet);
        expect(btc, isNotNull, reason: 'no account selected');

        expect(btc!.accountPath, want['accountPath']);
        expect(btc.purpose, purpose);
        expect(btc.xfp, want['xfp']);
        expect(btc.receivePath(0), want['receivePath0']);
        expect(btc.changePath(0), want['changePath0']);
        expect(btc.xpub(), want['xpub']);

        final receive = (want['receive'] as List).cast<String>();
        for (var i = 0; i < receive.length; i++) {
          expect(btc.deriveAddress(i), receive[i], reason: 'receive $i');
        }
        final change0 = want['change0'] as String?;
        if (change0 != null) {
          expect(btc.deriveAddress(0, change: true), change0);
        }

        if (want['deriveAddress'] == 'throws:invalid-props') {
          expect(receive, isEmpty);
          expect(change0, isNull);
          const message =
              'taproot addresses need the BIP-341 output-key tweak; '
              'derive them from xpub() with your Bitcoin library';
          expect(() => btc.deriveAddress(0), throwsInvalidProps(message));
          expect(() => btc.deriveAddress(0, change: true),
              throwsInvalidProps(message));
        } else {
          expect(want['deriveAddress'], 'supported');
          expect(receive, isNotEmpty);
        }

        final zpub = want['zpub'] as String;
        if (zpub == 'throws:invalid-props') {
          expect(purpose, isNot(84));
          expect(
            () => btc.zpub(),
            throwsInvalidProps(
                'zpub is the SLIP-132 form of the BIP-84 account only'),
          );
        } else {
          expect(purpose, 84);
          expect(btc.zpub(), zpub);
        }
      });
    }
  });
}
