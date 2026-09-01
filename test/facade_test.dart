import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';
import 'package:test/test.dart';

/// The public-API journey, imports restricted to the two entry libraries an
/// integrator would use: link -> build a request -> animate -> scan back ->
/// (a reply parse is covered per chain; here the transport loop closes).
void main() {
  final era = EraConnect(EraConnectConfig(origin: 'Facade Test'));

  final golden = jsonDecode(
    File('test/fixtures/ts-parity-golden.json').readAsStringSync(),
  ) as Map<String, dynamic>;

  test('links the golden wallet and exposes every chain getter', () {
    final accounts = era.parseAccounts(golden['walletUr'] as String);
    expect(accounts.masterFingerprint, isNotEmpty);
    expect(accounts.evm(), isNotNull);

    // Getters must all materialize (lazy singletons).
    expect(identical(era.evm, era.evm), isTrue);
    expect(identical(era.bch, era.bch), isTrue);
    era
      ..btc
      ..solana
      ..tron
      ..ton
      ..cardano
      ..sui
      ..cosmos
      ..xrp
      ..raw;
  });

  test('a request animates and reassembles through the scanner', () {
    final request = era.evm.generateSignRequest(EvmSignRequestProps(
      requestId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
      signData: Uint8List.fromList(List.generate(600, (i) => i % 251)),
      dataType: EvmDataType.transaction,
      path: "m/44'/60'/0'/0/0",
      xfp: 0x11223344,
      chainId: 1,
    ));

    final animated =
        request.toAnimated(AnimatedUrOptions(maxFragmentLength: 80));
    expect(animated.isSingleFrame, isFalse);

    final scanner =
        era.scanner(UrScannerOptions(expectedTypes: ['eth-sign-request']));
    var frames = 0;
    while (!scanner.isComplete) {
      scanner.receivePart(animated.nextFrame());
      frames++;
      expect(frames, lessThan(200), reason: 'fountain must converge');
    }
    final reassembled = scanner.result();
    expect(reassembled.type, request.ur.type);
    expect(reassembled.cbor, request.ur.cbor);
  });

  test('the key-derivation hardware call builds through the facade', () {
    final call = era.generateKeyDerivationCall(KeyDerivationCallProps(
      schemas: [
        KeyDerivationSchema(path: "m/44'/60'/0'"),
      ],
    ));
    expect(call.ur.type, 'qr-hardware-call');
    expect(call.ur.cbor, isNotEmpty);
  });

  test('raw round-trips an arbitrary UR', () {
    final ur = era.raw.ur('crypto-keypath', Uint8List.fromList([0xa0]));
    final parsed = era.raw.parse(ur.toString());
    expect(parsed.type, 'crypto-keypath');
    expect(parsed.cbor, ur.cbor);
  });
}
