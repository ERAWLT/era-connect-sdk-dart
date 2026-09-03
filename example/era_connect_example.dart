// The whole integration in one file: link -> request -> animate -> scan ->
// verify. QR rendering and the camera are the app's job (any Flutter QR /
// scanner package works); the SDK owns every byte of the protocol.
import 'dart:typed_data';

import 'package:era_connect/era_connect.dart';
import 'package:era_connect/verify.dart' as verify;

void main() {
  final era = EraConnect(EraConnectConfig(origin: 'ExampleWallet'));

  // 1. LINK — the user shows the device's "connect" QR; you scan it.
  //    Feed camera frames into a scanner until it completes:
  //      final scanner = era.scanner(
  //        UrScannerOptions(expectedTypes: ['crypto-multi-accounts']));
  //      scanner.receivePart(frameText); // repeat per camera frame
  //      final accounts = era.parseAccounts(scanner.result());
  //    Then derive addresses locally, no device round-trip:
  //      accounts.evm()!.deriveAddress(0);   // 0x…
  //      accounts.btc()!.deriveAddress(0);   // bc1q…
  //      accounts.bch()!.deriveAddress(0);   // CashAddr

  // 2. SIGN — build the transaction with your chain tooling, then:
  final request = era.evm.generateSignRequest(EvmSignRequestProps(
    signData: Uint8List.fromList(List.filled(64, 7)), // your raw RLP / message
    dataType: EvmDataType.transaction,
    path: "m/44'/60'/0'/0/0", // from the linked account
    xfp: '12345678', //          accounts.evm()!.xfp
    chainId: 1,
  ));

  // 3. DISPLAY — render request frames as QR codes (animate for large payloads).
  final animated = request.toAnimated();
  for (var i = 0; i < animated.fragmentCount; i++) {
    final frame = animated.nextFrame(); // hand to your QR widget
    print(
        'frame ${i + 1}/${animated.fragmentCount}: ${frame.substring(0, 40)}…');
  }

  // 4. SCAN the device's reply QR back:
  //      final scanner = request.scanner();       // pinned to the reply type
  //      scanner.receivePart(frameText);          // repeat per camera frame
  //      final signature = scanner.parse();       // request-id echo enforced
  //
  // 5. VERIFY before broadcasting — "did the device sign exactly what I sent?"
  //      final check = verify.verifyEvmSignature(...);
  //      if (!check.ok) throw StateError(check.reason!);
  //
  // Chain guides with complete, runnable reply/verify flows live in doc/:
  //   doc/getting-started/  — the five-step funnel
  //   doc/chains/           — one guide per chain family
  //   doc/advanced/         — verification, QR tuning, Flutter integration
  print(verify.verified.ok); // the verify library is one import away
}
