import 'dart:typed_data';

import 'package:era_connect/bch.dart' as bch;
import 'package:era_connect/btc.dart' as btc;
import 'package:era_connect/cardano.dart' as cardano;
import 'package:era_connect/cosmos.dart' as cosmos;
import 'package:era_connect/era_connect.dart';
import 'package:era_connect/evm.dart' as evm;
import 'package:era_connect/solana.dart' as solana;
import 'package:era_connect/sui.dart' as sui;
import 'package:era_connect/ton.dart' as ton;
import 'package:era_connect/tron.dart' as tron;
import 'package:era_connect/verify.dart' as verify;
import 'package:era_connect/xrp.dart' as xrp;
import 'package:test/test.dart';

/// The narrow entry libraries: the ten per-chain ones the docs name as the
/// primary import route, plus `verify.dart`.
///
/// Each gates its surface with a HAND-WRITTEN `show` clause, and no other
/// test in this suite imports any of them — so a symbol can drop off the
/// published API, or a whole chain module stop being exported, with every
/// gate green. Every name below is therefore load-bearing: a clause that
/// loses one fails to COMPILE here, which is the only signal there is.
void main() {
  /// What a per-chain library advertises beside its chain module. Naming
  /// each type through the library's OWN prefix is the pin; comparing the
  /// list with the root library's is the proof that the narrow door leads
  /// into the same room rather than to a second copy of the plumbing.
  void expectsTheSharedPlumbing(
    List<Type> advertised,
    String origin,
    ChainContext namedContext,
  ) {
    expect(advertised, [
      ChainContext,
      EraConnectConfig,
      ExpectedReply,
      SignRequest,
      EraSdkError,
      AnimatedUr,
      AnimatedUrOptions,
      UrScanner,
      UrScannerOptions,
      Ur,
    ]);
    // The device-facing default an integrator can name instead of retyping.
    expect(origin, defaultOrigin);
    expect(namedContext.origin, 'Subpath Test');
  }

  test('package:era_connect/evm.dart', () {
    expect(evm.EvmChain, EvmChain);
    expectsTheSharedPlumbing(
      [
        evm.ChainContext,
        evm.EraConnectConfig,
        evm.ExpectedReply,
        evm.SignRequest,
        evm.EraSdkError,
        evm.AnimatedUr,
        evm.AnimatedUrOptions,
        evm.UrScanner,
        evm.UrScannerOptions,
        evm.Ur,
      ],
      evm.defaultOrigin,
      evm.resolveContext(evm.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  test('package:era_connect/btc.dart', () {
    expect(btc.BtcChain, BtcChain);
    expectsTheSharedPlumbing(
      [
        btc.ChainContext,
        btc.EraConnectConfig,
        btc.ExpectedReply,
        btc.SignRequest,
        btc.EraSdkError,
        btc.AnimatedUr,
        btc.AnimatedUrOptions,
        btc.UrScanner,
        btc.UrScannerOptions,
        btc.Ur,
      ],
      btc.defaultOrigin,
      btc.resolveContext(btc.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  test('package:era_connect/bch.dart', () {
    expect(bch.BchChain, BchChain);
    expectsTheSharedPlumbing(
      [
        bch.ChainContext,
        bch.EraConnectConfig,
        bch.ExpectedReply,
        bch.SignRequest,
        bch.EraSdkError,
        bch.AnimatedUr,
        bch.AnimatedUrOptions,
        bch.UrScanner,
        bch.UrScannerOptions,
        bch.Ur,
      ],
      bch.defaultOrigin,
      bch.resolveContext(bch.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  test('package:era_connect/solana.dart', () {
    expect(solana.SolanaChain, SolanaChain);
    expectsTheSharedPlumbing(
      [
        solana.ChainContext,
        solana.EraConnectConfig,
        solana.ExpectedReply,
        solana.SignRequest,
        solana.EraSdkError,
        solana.AnimatedUr,
        solana.AnimatedUrOptions,
        solana.UrScanner,
        solana.UrScannerOptions,
        solana.Ur,
      ],
      solana.defaultOrigin,
      solana.resolveContext(solana.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  test('package:era_connect/tron.dart', () {
    expect(tron.TronChain, TronChain);
    expectsTheSharedPlumbing(
      [
        tron.ChainContext,
        tron.EraConnectConfig,
        tron.ExpectedReply,
        tron.SignRequest,
        tron.EraSdkError,
        tron.AnimatedUr,
        tron.AnimatedUrOptions,
        tron.UrScanner,
        tron.UrScannerOptions,
        tron.Ur,
      ],
      tron.defaultOrigin,
      tron.resolveContext(tron.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  test('package:era_connect/ton.dart', () {
    expect(ton.TonChain, TonChain);
    expectsTheSharedPlumbing(
      [
        ton.ChainContext,
        ton.EraConnectConfig,
        ton.ExpectedReply,
        ton.SignRequest,
        ton.EraSdkError,
        ton.AnimatedUr,
        ton.AnimatedUrOptions,
        ton.UrScanner,
        ton.UrScannerOptions,
        ton.Ur,
      ],
      ton.defaultOrigin,
      ton.resolveContext(ton.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  test('package:era_connect/cardano.dart', () {
    expect(cardano.CardanoChain, CardanoChain);
    expectsTheSharedPlumbing(
      [
        cardano.ChainContext,
        cardano.EraConnectConfig,
        cardano.ExpectedReply,
        cardano.SignRequest,
        cardano.EraSdkError,
        cardano.AnimatedUr,
        cardano.AnimatedUrOptions,
        cardano.UrScanner,
        cardano.UrScannerOptions,
        cardano.Ur,
      ],
      cardano.defaultOrigin,
      cardano.resolveContext(cardano.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  test('package:era_connect/sui.dart', () {
    expect(sui.SuiChain, SuiChain);
    expectsTheSharedPlumbing(
      [
        sui.ChainContext,
        sui.EraConnectConfig,
        sui.ExpectedReply,
        sui.SignRequest,
        sui.EraSdkError,
        sui.AnimatedUr,
        sui.AnimatedUrOptions,
        sui.UrScanner,
        sui.UrScannerOptions,
        sui.Ur,
      ],
      sui.defaultOrigin,
      sui.resolveContext(sui.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  test('package:era_connect/cosmos.dart', () {
    expect(cosmos.CosmosChain, CosmosChain);
    expectsTheSharedPlumbing(
      [
        cosmos.ChainContext,
        cosmos.EraConnectConfig,
        cosmos.ExpectedReply,
        cosmos.SignRequest,
        cosmos.EraSdkError,
        cosmos.AnimatedUr,
        cosmos.AnimatedUrOptions,
        cosmos.UrScanner,
        cosmos.UrScannerOptions,
        cosmos.Ur,
      ],
      cosmos.defaultOrigin,
      cosmos.resolveContext(cosmos.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  test('package:era_connect/xrp.dart', () {
    expect(xrp.XrpChain, XrpChain);
    expectsTheSharedPlumbing(
      [
        xrp.ChainContext,
        xrp.EraConnectConfig,
        xrp.ExpectedReply,
        xrp.SignRequest,
        xrp.EraSdkError,
        xrp.AnimatedUr,
        xrp.AnimatedUrOptions,
        xrp.UrScanner,
        xrp.UrScannerOptions,
        xrp.Ur,
      ],
      xrp.defaultOrigin,
      xrp.resolveContext(xrp.EraConnectConfig(origin: 'Subpath Test')),
    );
  });

  // Names alone would pass even if a library exported types nothing can
  // produce. One journey through a single subpath import — build, animate,
  // scan back — is what says the narrow door is a working one.
  test('a request builds, animates and reassembles through evm.dart alone', () {
    final chain = evm.EvmChain(evm.EraConnectConfig(origin: 'Subpath Test'));
    final evm.SignRequest<evm.EvmSignatureResult> request =
        chain.generateSignRequest(evm.EvmSignRequestProps(
      requestId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
      signData: Uint8List.fromList(List.generate(600, (i) => i % 251)),
      dataType: evm.EvmDataType.transaction,
      path: "m/44'/60'/0'/0/0",
      xfp: 0x11223344,
      chainId: 1,
    ));

    final evm.AnimatedUr animated =
        request.toAnimated(evm.AnimatedUrOptions(maxFragmentLength: 80));
    final evm.UrScanner scanner =
        evm.UrScanner(evm.UrScannerOptions(expectedTypes: [request.ur.type]));
    var frames = 0;
    while (!scanner.isComplete) {
      scanner.receivePart(animated.nextFrame());
      frames++;
      expect(frames, lessThan(200), reason: 'fountain must converge');
    }
    final evm.Ur reassembled = scanner.result();
    expect(reassembled.type, request.ur.type);
    expect(reassembled.cbor, request.ur.cbor);
  });

  // `verify.dart` re-exports the error class, with a comment in the clause
  // saying why: `parsePsbt` and `bocRootHash` throw it, and an app that
  // imports THIS library alone cannot write `on EraSdkError catch` without
  // it. Nothing else in the suite imports verify.dart by itself, so dropping
  // the line leaves every gate green — except this catch clause, which stops
  // naming a type.
  test('package:era_connect/verify.dart names the error its parsers throw', () {
    expect(verify.EraSdkError, EraSdkError);
    try {
      // "psbt" without its 0xff separator: the magic is five bytes.
      verify.parsePsbt(Uint8List.fromList([0x70, 0x73, 0x62, 0x74]));
      fail('a truncated PSBT must not parse');
    } on verify.EraSdkError catch (e) {
      expect(e.code, isNotEmpty);
    }
  });
}
