import 'dart:typed_data';

import 'package:era_connect/src/accounts/accounts.dart';
import 'package:era_connect/src/accounts/derive.dart';
import 'package:era_connect/src/cbor/decode.dart';
import 'package:era_connect/src/cbor/encode.dart';
import 'package:era_connect/src/cbor/model.dart';
import 'package:era_connect/src/chains/cardano.dart';
import 'package:era_connect/src/chains/shared.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:era_connect/src/core/errors.dart';
import 'package:era_connect/src/crypto/digests.dart';
import 'package:era_connect/src/ur/ur.dart';
import 'package:era_connect/src/verify/cardano.dart';
import 'package:test/test.dart';

import 'helpers/icarus.dart';

Matcher throwsSdkError(String code) =>
    throwsA(isA<EraSdkError>().having((e) => e.code, 'code', code));

Matcher throwsFormatException(String messagePart) => throwsA(
      isA<FormatException>()
          .having((e) => e.message, 'message', contains(messagePart)),
    );

void main() {
  final era = CardanoChain(const EraConnectConfig(origin: 'ADA Test'));
  final requestId = Uint8List.fromList(List.generate(16, (i) => i + 1));
  final txHash32 = Uint8List.fromList(List.filled(32, 0xaa));

  // A tiny plausible tx CBOR: [bodyMap, {}, true, null].
  final txBody = cbMap([
    (
      0,
      cbArray([
        cbArray([cbBytes(txHash32), cbUint(0)])
      ])
    ),
    (2, cbUint(170000)),
  ]);
  final signData = cborEncode(
    cbArray([txBody, cbMap([]), cbBool(true), const CborNull()]),
  );

  group('Cardano request wire shape', () {
    final request = era.generateSignRequest(CardanoSignRequestProps(
      requestId: requestId,
      signData: signData,
      utxos: [
        CardanoUtxoRef(
          transactionHash: txHash32,
          index: 0,
          amount: '2000000',
          path: "m/1852'/1815'/0'/0/0",
          xfp: 'deadbeef',
          address: 'addr1qtestaddress',
        ),
      ],
      certKeys: const [
        CardanoCertKeyRef(path: "m/1852'/1815'/0'/2/0", xfp: 'deadbeef'),
      ],
    ));

    test(
        'emits {1: uuid37, 2: signData, 3: [2201 utxo], 4: [2204 certKey], 5: origin}',
        () {
      final map = asMap(cborDecode(request.ur.cbor))!;
      expect(request.ur.type, 'cardano-sign-request');
      final utxoList = asArray(mapGet(map, 3))!;
      final utxoTagged = utxoList[0];
      expect(utxoTagged, isA<CborTag>());
      expect((utxoTagged as CborTag).tag, 2201);
      final utxo = asMap(utxoTagged)!;
      expect(asBytes(mapGet(utxo, 1)), txHash32);
      expect(asUint(mapGet(utxo, 2))!.toInt(), 0);
      expect(asText(mapGet(utxo, 3)), '2000000');
      expect(asText(mapGet(utxo, 5)), 'addr1qtestaddress');
      final certList = asArray(mapGet(map, 4))!;
      expect(certList[0], isA<CborTag>());
      expect((certList[0] as CborTag).tag, 2204);
      expect(asText(mapGet(map, 5)), 'ADA Test');
      expect(request.replyTypes, ['cardano-signature']);
    });

    test('pins the request CBOR golden', () {
      expect(
        bytesToHex(request.ur.cbor),
        'a501d825500102030405060708090a0b0c0d0e0f1002583184a20081825820aaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00021a'
        '00029810a0f5f60381d90899a5015820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa020003673230303030303004d90130a2018a'
        '19073cf5190717f500f500f400f4021adeadbeef05716164647231717465737461'
        '6464726573730481d9089ca102d90130a2018a19073cf5190717f500f502f400f4'
        '021adeadbeef05684144412054657374',
      );
    });
  });

  group('the tx-body digest walker', () {
    test('extracts the encoded first element of a definite array', () {
      final body = firstArrayItemBytes(signData);
      expect(bytesToHex(body), bytesToHex(cborEncode(txBody)));
    });

    test('handles an indefinite-length outer array', () {
      final definiteBody = cborEncode(txBody);
      final indefinite = concatBytes([
        Uint8List.fromList([0x9f]),
        definiteBody,
        cborEncode(cbMap([])),
        Uint8List.fromList([0xff]),
      ]);
      expect(
        bytesToHex(firstArrayItemBytes(indefinite)),
        bytesToHex(definiteBody),
      );
    });

    test('refuses non-arrays and empty arrays', () {
      expect(
        () => firstArrayItemBytes(cborEncode(cbMap([]))),
        throwsFormatException('array'),
      );
      expect(
        () => firstArrayItemBytes(cborEncode(cbArray([]))),
        throwsFormatException('empty'),
      );
    });
  });

  group(
      'Icarus end-to-end: private-side signing vs SDK public-side verification',
      () {
    // Deterministic entropy → account xprv → child 0/0 signs; the SDK,
    // holding only the PUBLIC account key material (like a linked wallet),
    // must derive the same child vkey and verify the witness.
    final entropy =
        Uint8List.fromList(List.generate(32, (i) => (i * 11) % 251));
    final master = icarusMasterFromEntropy(entropy);
    final account = derivePath(master, const [
      IcarusLevel(index: 1852, hardened: true),
      IcarusLevel(index: 1815, hardened: true),
      IcarusLevel(index: 0, hardened: true),
    ]);
    final accountPub = publicKeyOf(account.kL);
    final digest = blake2b256(firstArrayItemBytes(signData));

    final paymentKey = derivePath(account, const [
      IcarusLevel(index: 0, hardened: false),
      IcarusLevel(index: 0, hardened: false),
    ]);
    final witness = CardanoWitness(
      vkey: publicKeyOf(paymentKey.kL),
      signature: extendedSign(paymentKey, digest),
    );

    test('public soft derivation matches private derivation', () {
      final derived =
          cardanoSoftDerivePath(accountPub, account.chainCode, [0, 0]);
      expect(bytesToHex(derived), bytesToHex(witness.vkey));
    });

    test('verifies a bound witness set end to end', () {
      final witnessSet = cborEncode(cbMap([
        (
          0,
          cbTag(
            258,
            cbArray([
              cbArray([cbBytes(witness.vkey), cbBytes(witness.signature)])
            ]),
          )
        ),
      ]));
      final result = verifyCardanoSignature(VerifyCardanoSignatureArgs(
        signData: signData,
        witnessSet: witnessSet,
        account: VerifyCardanoAccount(
          publicKey: accountPub,
          chainCode: account.chainCode,
          accountPath: "m/1852'/1815'/0'",
        ),
        signerPaths: const ["m/1852'/1815'/0'/0/0"],
      ));
      expect(result.ok, isTrue);
      expect(result.checked, isTrue);
    });

    test('accepts an untagged witness array too', () {
      final untagged = cborEncode(cbMap([
        (
          0,
          cbArray([
            cbArray([cbBytes(witness.vkey), cbBytes(witness.signature)])
          ])
        ),
      ]));
      expect(parseWitnessSet(untagged).length, 1);
    });

    test('refuses a witness from a key the request did not ask for', () {
      final foreignKey = derivePath(account, const [
        IcarusLevel(index: 0, hardened: false),
        IcarusLevel(index: 7, hardened: false),
      ]);
      final foreign = CardanoWitness(
        vkey: publicKeyOf(foreignKey.kL),
        signature: extendedSign(foreignKey, digest),
      );
      final result = verifyCardanoSignature(VerifyCardanoSignatureArgs(
        signData: signData,
        witnesses: [witness, foreign],
        account: VerifyCardanoAccount(
          publicKey: accountPub,
          chainCode: account.chainCode,
          accountPath: "m/1852'/1815'/0'",
        ),
        signerPaths: const ["m/1852'/1815'/0'/0/0"],
      ));
      expect(result.ok, isFalse);
      expect(result.reason, contains('did not ask for'));
    });

    test('refuses when a requested signer path has no witness', () {
      final result = verifyCardanoSignature(VerifyCardanoSignatureArgs(
        signData: signData,
        witnesses: [witness],
        account: VerifyCardanoAccount(
          publicKey: accountPub,
          chainCode: account.chainCode,
          accountPath: "m/1852'/1815'/0'",
        ),
        signerPaths: const ["m/1852'/1815'/0'/0/0", "m/1852'/1815'/0'/2/0"],
      ));
      expect(result.ok, isFalse);
      expect(result.reason, contains('no witness'));
    });

    test('refuses a tampered transaction', () {
      final tampered = Uint8List.fromList(signData);
      tampered[tampered.length - 4] ^= 0x01;
      final result = verifyCardanoSignature(
        VerifyCardanoSignatureArgs(signData: tampered, witnesses: [witness]),
      );
      expect(result.ok, isFalse);
    });
  });

  group('Cardano reply roundtrip through the scanner', () {
    test('parses the witness set and validates the echo', () {
      final entropy = Uint8List.fromList(List.filled(32, 9));
      final master = icarusMasterFromEntropy(entropy);
      final account = derivePath(master, const [
        IcarusLevel(index: 1852, hardened: true),
        IcarusLevel(index: 1815, hardened: true),
        IcarusLevel(index: 0, hardened: true),
      ]);
      final request = era.generateSignRequest(CardanoSignRequestProps(
        requestId: requestId,
        signData: signData,
        utxos: [
          CardanoUtxoRef(
            transactionHash: txHash32,
            index: 1,
            path: "m/1852'/1815'/0'/0/0",
            xfp: 'cafebabe',
          ),
        ],
      ));
      final digest = blake2b256(firstArrayItemBytes(signData));
      final child = derivePath(account, const [
        IcarusLevel(index: 0, hardened: false),
        IcarusLevel(index: 0, hardened: false),
      ]);
      final witnessSet = cborEncode(cbMap([
        (
          0,
          cbTag(
            258,
            cbArray([
              cbArray([
                cbBytes(publicKeyOf(child.kL)),
                cbBytes(extendedSign(child, digest)),
              ])
            ]),
          )
        ),
      ]));
      final reply = Ur(
        'cardano-signature',
        cborEncode(cbMap([
          (1, cbTag(37, cbBytes(requestId))),
          (2, cbBytes(witnessSet)),
        ])),
      );
      final scanner = request.scanner();
      scanner.receivePart(reply.toWireString());
      final parsed = scanner.parse();
      expect(parsed.witnesses.length, 1);
      expect(parsed.witnessSet, witnessSet);

      final stale = Ur(
        'cardano-signature',
        cborEncode(cbMap([
          (1, cbTag(37, cbBytes(Uint8List.fromList(List.filled(16, 7))))),
          (2, cbBytes(witnessSet)),
        ])),
      );
      expect(
        () => era.parseSignature(stale, ExpectedReply(requestId: requestId)),
        throwsSdkError('request-id-mismatch'),
      );
    });
  });

  group(
      'Cardano linking (path-only origin falls back to the master fingerprint)',
      () {
    test('parses a Vespr-style entry {3,4,6(path-only)}', () {
      final entropy = Uint8List.fromList(List.filled(32, 4));
      final master = icarusMasterFromEntropy(entropy);
      final account = derivePath(master, const [
        IcarusLevel(index: 1852, hardened: true),
        IcarusLevel(index: 1815, hardened: true),
        IcarusLevel(index: 0, hardened: true),
      ]);
      final wallet = cborEncode(
        cbMap([
          (1, cbUint(0xdeadbeef)),
          (
            2,
            cbArray([
              cbMap([
                (3, cbBytes(publicKeyOf(account.kL))),
                (4, cbBytes(account.chainCode)),
                (
                  6,
                  cbTag(
                    304,
                    cbMap([
                      (
                        1,
                        cbArray([
                          cbUint(1852),
                          cbBool(true),
                          cbUint(1815),
                          cbBool(true),
                          cbUint(0),
                          cbBool(true),
                        ]),
                      ),
                    ]),
                  ),
                ), // origin[1]-only: NO source fingerprint — the device's real shape
              ]),
            ]),
          ),
          (3, cbText('ERA Wallet')),
          (5, cbText('9.9.9')),
        ]),
      );
      final accounts = EraAccounts.fromUr(Ur('crypto-multi-accounts', wallet));
      final ada = accounts.cardano()!;
      expect(ada.accountPath, "m/1852'/1815'/0'");
      expect(
          ada.xfp, 'deadbeef'); // fell back to the wrapper master fingerprint
      expect(
        bytesToHex(ada.deriveKey(0, 0)),
        bytesToHex(publicKeyOf(derivePath(account, const [
          IcarusLevel(index: 0, hardened: false),
          IcarusLevel(index: 0, hardened: false),
        ]).kL)),
      );
    });
  });
}
