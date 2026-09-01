import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:era_connect/src/accounts/accounts.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/hardware_call/key_derivation.dart';
import 'package:era_connect/src/scan/ur_scanner.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:test/test.dart';

/// Parity against the TypeScript SDK: `test/fixtures/parity/accounts.json`
/// dumps EVERY view output of the reference `parseAccounts` over a
/// generator-built wallet (fixed synthetic inputs, the standard test seed);
/// the Dart port must reproduce every value and refuse every tampered reply.
void main() {
  final fixture = jsonDecode(
    File('test/fixtures/parity/accounts.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final wallet = fixture['wallet'] as Map<String, dynamic>;
  final views = wallet['views'] as Map<String, dynamic>;
  final accounts = EraAccounts.fromUr(
    Ur('crypto-multi-accounts', hexToBytes(wallet['cborHex'] as String)),
  );

  String? hexOrNull(Uint8List? bytes) =>
      bytes == null ? null : bytesToHex(bytes);

  group('accounts parity: wallet export', () {
    test('the UR string form parses to the same wallet', () {
      final fromString = EraAccounts.fromUr(wallet['ur'] as String);
      expect(fromString.sourceUr, wallet['ur']);
      expect(fromString.masterFingerprint, wallet['masterFingerprint']);
      expect(fromString.keys.length, (wallet['keys'] as List).length);
    });

    test('master fingerprint and device metadata', () {
      expect(accounts.masterFingerprint, wallet['masterFingerprint']);
      final device = wallet['device'] as Map<String, dynamic>;
      expect(accounts.device.name, device['name']);
      expect(accounts.device.id, device['id']);
      expect(accounts.device.firmwareVersion, device['firmwareVersion']);
    });

    test('every exported key: classification, path, xfp, material', () {
      final expected = (wallet['keys'] as List).cast<Map<String, dynamic>>();
      expect(accounts.keys.length, expected.length);
      for (var i = 0; i < expected.length; i++) {
        final key = accounts.keys[i];
        final want = expected[i];
        expect(key.chain, AccountChain.values.byName(want['chain'] as String),
            reason: 'keys[$i].chain');
        expect(key.path, want['path'], reason: 'keys[$i].path');
        expect(key.xfp, want['xfp'], reason: 'keys[$i].xfp');
        expect(hexOrNull(key.publicKey), want['publicKeyHex'],
            reason: 'keys[$i].publicKey');
        expect(hexOrNull(key.chainCode), want['chainCodeHex'],
            reason: 'keys[$i].chainCode');
        expect(key.name, want['name'], reason: 'keys[$i].name');
        expect(key.note, want['note'], reason: 'keys[$i].note');
      }
    });

    test('xfpFor answers for every account path', () {
      final expected = (wallet['xfpFor'] as Map<String, dynamic>);
      for (final entry in expected.entries) {
        expect(accounts.xfpFor(entry.key), entry.value,
            reason: 'xfpFor(${entry.key})');
      }
      expect(wallet['xfpForMissing'], 'throws:account-not-found');
      expect(
        () => accounts.xfpFor("m/9'/9'/9'"),
        throwsA(isA<EraSdkError>()
            .having((e) => e.code, 'code', 'account-not-found')),
      );
    });
  });

  group('accounts parity: chain views', () {
    test('evm (note preference, addresses, xpub)', () {
      final want = views['evm'] as Map<String, dynamic>;
      final evm = accounts.evm()!;
      expect(evm.accountPath, want['accountPath']);
      expect(evm.xfp, want['xfp']);
      expect(evm.pathFor(0), want['pathFor0']);
      expect(evm.xpub(), want['xpub']);
      final addresses = (want['addresses'] as List).cast<String>();
      for (var i = 0; i < addresses.length; i++) {
        expect(evm.deriveAddress(i), addresses[i], reason: 'evm address $i');
      }
    });

    test('btc purpose 84 (paths, addresses, xpub, zpub, testnet)', () {
      final want = views['btc84'] as Map<String, dynamic>;
      final btc = accounts.btc()!;
      expect(btc.accountPath, want['accountPath']);
      expect(btc.xfp, want['xfp']);
      expect(btc.receivePath(0), want['receivePath0']);
      expect(btc.changePath(3), want['changePath3']);
      expect(btc.xpub(), want['xpub']);
      expect(btc.zpub(), want['zpub']);
      final receive = (want['receive'] as List).cast<String>();
      expect(btc.deriveAddress(0), receive[0]);
      expect(btc.deriveAddress(1), receive[1]);
      expect(btc.deriveAddress(0, change: true), want['change0']);
      expect(accounts.btc(testnet: true)!.deriveAddress(0),
          want['testnetReceive0']);
    });

    test('btc purpose 44 (legacy P2PKH)', () {
      final want = views['btc44'] as Map<String, dynamic>;
      final btc = accounts.btc(purpose: 44)!;
      expect(btc.xfp, want['xfp']);
      expect(btc.deriveAddress(0), want['address0']);
      expect(accounts.btc(purpose: 44, testnet: true)!.deriveAddress(0),
          want['testnetAddress0']);
    });

    test('btc purpose 49 (nested segwit)', () {
      final want = views['btc49'] as Map<String, dynamic>;
      final btc = accounts.btc(purpose: 49)!;
      expect(btc.xfp, want['xfp']);
      expect(btc.deriveAddress(0), want['address0']);
      expect(accounts.btc(purpose: 49, testnet: true)!.deriveAddress(0),
          want['testnetAddress0']);
    });

    test('btc purpose 86 (taproot: xpub only, addresses refused)', () {
      final want = views['btc86'] as Map<String, dynamic>;
      final btc = accounts.btc(purpose: 86)!;
      expect(btc.xfp, want['xfp']);
      expect(btc.xpub(), want['xpub']);
      expect(want['deriveAddress0'], 'throws:invalid-props');
      expect(
        () => btc.deriveAddress(0),
        throwsA(
            isA<EraSdkError>().having((e) => e.code, 'code', 'invalid-props')),
      );
      expect(
        () => btc.zpub(),
        throwsA(
            isA<EraSdkError>().having((e) => e.code, 'code', 'invalid-props')),
      );
    });

    test('bch (CashAddr forms and the sign-request public key)', () {
      final want = views['bch'] as Map<String, dynamic>;
      final bch = accounts.bch()!;
      expect(bch.accountPath, want['accountPath']);
      expect(bch.xfp, want['xfp']);
      expect(bch.receivePath(0), want['receivePath0']);
      expect(bch.changePath(0), want['changePath0']);
      expect(bytesToHex(bch.derivePublicKey(0)), want['publicKey0Hex']);
      expect(bch.deriveAddress(0), want['address0']);
      expect(bch.deriveAddress(0, withPrefix: true), want['address0Prefixed']);
      expect(bch.deriveAddress(0, change: true), want['change0']);
    });

    test('tron', () {
      final want = views['tron'] as Map<String, dynamic>;
      final tron = accounts.tron()!;
      expect(tron.accountPath, want['accountPath']);
      expect(tron.xfp, want['xfp']);
      expect(tron.pathFor(5), want['pathFor5']);
      final addresses = (want['addresses'] as List).cast<String>();
      expect(tron.deriveAddress(0), addresses[0]);
      expect(tron.deriveAddress(1), addresses[1]);
    });

    test('ton', () {
      final want = views['ton'] as Map<String, dynamic>;
      final ton = accounts.ton()!;
      expect(ton.accountPath, want['accountPath']);
      expect(ton.xfp, want['xfp']);
      expect(bytesToHex(ton.publicKey), want['publicKeyHex']);
      expect(ton.name, want['name']);
    });

    test('cardano (path-only origin xfp, soft-derived vkeys)', () {
      final want = views['cardano'] as Map<String, dynamic>;
      final cardano = accounts.cardano()!;
      expect(cardano.accountPath, want['accountPath']);
      expect(cardano.xfp, want['xfp']);
      expect(bytesToHex(cardano.publicKey), want['publicKeyHex']);
      expect(bytesToHex(cardano.chainCode), want['chainCodeHex']);
      expect(cardano.pathFor(0, 0), want['pathFor00']);
      final deriveKeys = want['deriveKeys'] as Map<String, dynamic>;
      for (final entry in deriveKeys.entries) {
        final parts = entry.key.split('/');
        expect(
          bytesToHex(
              cardano.deriveKey(int.parse(parts[0]), int.parse(parts[1]))),
          entry.value,
          reason: 'cardano deriveKey ${entry.key}',
        );
      }
    });

    test('sui signers', () {
      final want = (views['sui'] as List).cast<Map<String, dynamic>>();
      final sui = accounts.sui();
      expect(sui.length, want.length);
      for (var i = 0; i < want.length; i++) {
        expect(sui[i].path, want[i]['path']);
        expect(sui[i].xfp, want[i]['xfp']);
        expect(bytesToHex(sui[i].publicKey), want[i]['publicKeyHex']);
        expect(sui[i].address, want[i]['address']);
      }
    });

    test('solana signers', () {
      final want = (views['solana'] as List).cast<Map<String, dynamic>>();
      final solana = accounts.solana();
      expect(solana.length, want.length);
      for (var i = 0; i < want.length; i++) {
        expect(solana[i].path, want[i]['path']);
        expect(solana[i].xfp, want[i]['xfp']);
        expect(solana[i].index, want[i]['index']);
        expect(bytesToHex(solana[i].publicKey), want[i]['publicKeyHex']);
        expect(solana[i].address, want[i]['address']);
      }
    });
  });

  group('accounts parity: key-derivation hardware call', () {
    KeyDerivationSchema schemaOf(Map<String, dynamic> raw) {
      return KeyDerivationSchema(
        path: raw['path'] as String,
        curve: switch (raw['curve'] as String?) {
          null => null,
          'secp256k1' => DerivationCurve.secp256k1,
          'ed25519' => DerivationCurve.ed25519,
          final other => throw StateError('unknown curve $other'),
        },
        algo: switch (raw['algo'] as String?) {
          null => null,
          'slip10' => DerivationAlgorithm.slip10,
          'bip32ed25519' => DerivationAlgorithm.bip32ed25519,
          final other => throw StateError('unknown algo $other'),
        },
        chainType: raw['chainType'] as String?,
      );
    }

    for (final raw in (fixture['keyDerivationCalls'] as List)
        .cast<Map<String, dynamic>>()) {
      test('${raw['name']} rebuilds byte-identical', () {
        final context =
            resolveContext(EraConnectConfig(origin: raw['origin'] as String));
        final call = generateKeyDerivationCall(
          context,
          KeyDerivationCallProps(
            schemas: (raw['schemas'] as List)
                .cast<Map<String, dynamic>>()
                .map(schemaOf)
                .toList(),
            origin: raw['propsOrigin'] as String?,
          ),
        );
        expect(call.ur.type, raw['urType']);
        expect(bytesToHex(call.ur.cbor), raw['cborHex']);
        expect(call.ur.toString(), raw['ur']);
        expect(call.replyTypes, (raw['replyTypes'] as List).cast<String>());
      });
    }

    test('an empty schema list is refused', () {
      expect(fixture['emptySchemas'], 'throws:invalid-props');
      expect(
        () => generateKeyDerivationCall(
            resolveContext(), const KeyDerivationCallProps(schemas: [])),
        throwsA(
            isA<EraSdkError>().having((e) => e.code, 'code', 'invalid-props')),
      );
    });

    test('the call scanner assembles and parses the wallet export', () {
      final call = generateKeyDerivationCall(
        resolveContext(),
        const KeyDerivationCallProps(
            schemas: [KeyDerivationSchema(path: "m/44'/60'/0'")]),
      );
      final scanner = call.scanner();
      final result = scanner.receivePart(wallet['ur'] as String);
      expect(result, isA<ScanComplete>());
      final linked = scanner.parse();
      expect(linked.masterFingerprint, wallet['masterFingerprint']);
      expect(linked.evm()?.accountPath,
          (views['evm'] as Map<String, dynamic>)['accountPath']);
    });
  });

  group('accounts parity: replies and tampered exports', () {
    test('standalone crypto-hdkey reply parses to the recorded TON view', () {
      final want = (fixture['replies'] as Map<String, dynamic>)['tonHdkey']
          as Map<String, dynamic>;
      final linked = EraAccounts.fromUr(want['ur'] as String);
      expect(linked.masterFingerprint, want['masterFingerprint']);
      final ton = linked.ton()!;
      expect(ton.accountPath, want['accountPath']);
      expect(ton.xfp, want['xfp']);
      expect(bytesToHex(ton.publicKey), want['publicKeyHex']);
      expect(ton.name, want['name']);
    });

    for (final tampered
        in ((fixture['replies'] as Map<String, dynamic>)['tampered'] as List)
            .cast<Map<String, dynamic>>()) {
      test('${tampered['name']} is refused', () {
        final expected = tampered['expect'] as String;
        expect(expected, startsWith('throws:'));
        final code = expected.substring('throws:'.length);
        expect(
          () => EraAccounts.fromUr(tampered['ur'] as String),
          throwsA(isA<EraSdkError>().having((e) => e.code, 'code', code)),
        );
      });
    }
  });
}
