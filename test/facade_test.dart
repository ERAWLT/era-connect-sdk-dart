import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';
import 'package:era_connect/verify.dart' as verify;
import 'package:test/test.dart';

/// The public-API journey, imports restricted to the two entry libraries an
/// integrator would use: link -> build a request -> animate -> scan back ->
/// (a reply parse is covered per chain; here the transport loop closes).
void main() {
  final era = EraConnect(EraConnectConfig(origin: 'Facade Test'));

  final golden = jsonDecode(
    File('test/fixtures/reference-golden.json').readAsStringSync(),
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

  // Every name below is reachable ONLY through the two entry libraries'
  // `show` clauses. The clauses are hand-written, so a symbol drops off the
  // public surface without any other test noticing: this group names each one
  // so that a removal fails to compile rather than reaching a release.
  group('the public surface carries what an integrator has to name', () {
    test('request ids can be minted and rendered', () {
      final id = randomRequestId();
      expect(id.length, 16);
      final uuid = uuidStringify(id);
      expect(uuid,
          matches(RegExp(r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')));
      // The UUID string is the same 16 bytes a request would echo back.
      expect(hexToBytes(uuid.replaceAll('-', '')), id);
      expect(bytesToHex(id), uuid.replaceAll('-', ''));
    });

    test('the wallet UR types pin a link scanner', () {
      expect(walletUrTypes, contains('crypto-multi-accounts'));
      final scanner = era.scanner(
        UrScannerOptions(expectedTypes: walletUrTypes.toList()),
      );
      expect(
        scanner.receivePart(golden['walletUr'] as String),
        isA<ScanComplete>(),
      );
    });

    test('the wallet UR type set cannot be widened from outside', () {
      // This exported object IS what `parseMultiAccountsUr` reads at its type
      // gate — there is no private copy behind it — so a mutable set here
      // would let any importer admit a foreign type into the linking path.
      // `const` is what refuses the write.
      const foreign = 'totally-not-a-wallet';
      expect(() => walletUrTypes.add(foreign), throwsUnsupportedError);
      expect(walletUrTypes, isNot(contains(foreign)));

      // …and the gate still refuses the type the write was aiming at.
      expect(
        () => parseMultiAccountsUr(Ur(foreign, Uint8List.fromList([0xa0]))),
        throwsA(
            isA<EraSdkError>().having((e) => e.code, 'code', 'wrong-ur-type')),
      );
    });

    test('the raw export is reachable without the typed views', () {
      final RawMultiAccounts raw =
          parseMultiAccountsUr(golden['walletUr'] as String);
      expect(raw.entries, isNotEmpty);
      final RawAccountEntry entry = raw.entries.first;
      final List<PathLevel> levels = parsePath(formatPath(entry.path));
      expect(pathEquals(levels, entry.path), isTrue);
    });

    test('the device-facing origin has a nameable default', () {
      expect(resolveContext().origin, defaultOrigin);
      expect(resolveContext(EraConnectConfig(origin: 'MyWallet')).origin,
          isNot(defaultOrigin));
    });

    test('the Cardano witness type is nameable from verify.dart alone', () {
      final List<verify.CardanoWitness> witnesses = [];
      final verdict = verify.verifyCardanoSignature(
        verify.VerifyCardanoSignatureArgs(
          signData: Uint8List.fromList([0x81, 0x40]),
          witnesses: witnesses,
        ),
      );
      expect(verdict.ok, isFalse);
    });
  });
}
