import 'dart:typed_data';

import 'package:era_connect/src/accounts/derive.dart';
import 'package:era_connect/src/core/bytes.dart';
import 'package:test/test.dart';

/// BIP-86 "Test vectors" — the published account key and the addresses it must
/// produce. These are the ground truth for the TapTweak: the witness program is
/// the tweaked output key Q, never the BIP-32 child key P. Encoding P instead
/// yields a valid-looking `bc1p…` that no BIP-86 signer can spend, which is
/// exactly the bug this function was written to close.
///
/// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
///
/// The account material below is the key and chain code inside the published
/// account xpub
/// `xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ`
/// (`m/86'/0'/0'`), taken from the BIP rather than from this package.
final _accountKey = hexToBytes(
    '03418278a2885c8bb98148158d1474634097a179c642f23cf1cc04da629ac6f0fb');
final _accountChainCode = hexToBytes(
    'c61a8f27e98182314d2444da3e600eb5836ec8ad183c86c311f95df8082b18aa');

Uint8List _childAt(int change, int index) =>
    derivePublicKey(_accountKey, _accountChainCode, change, index);

void main() {
  group('btcTaprootAddressFromPublicKey', () {
    const vectors = <List<Object>>[
      [0, 0, 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'],
      [0, 1, 'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh'],
      [1, 0, 'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7'],
    ];

    for (final v in vectors) {
      final change = v[0] as int, index = v[1] as int, want = v[2] as String;
      test('matches BIP-86 vector $change/$index', () {
        expect(btcTaprootAddressFromPublicKey(_childAt(change, index)), want);
      });
    }

    test('is not the untweaked internal key', () {
      // The defect this replaces: bech32m over x(child) rather than x(Q). If
      // the tweak is ever dropped again, this says so out loud instead of
      // letting a wrong address ship.
      final child = _childAt(0, 0);
      expect(bytesToHex(Uint8List.sublistView(child, 1)),
          'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115');
      expect(
          btcTaprootAddressFromPublicKey(child),
          isNot(
              'bc1pej9yh3jd39aam30mctm8paaghg9nsemezpk0zg3udlza0nt0cy2sqvps98'));
    });

    test('uses bech32m, not bech32', () {
      final addr = btcTaprootAddressFromPublicKey(_childAt(0, 0));
      expect(addr.startsWith('bc1p'), isTrue);
      expect(addr.length, 62);
    });

    test('honours the testnet hrp', () {
      expect(
          btcTaprootAddressFromPublicKey(_childAt(0, 0), 'tb')
              .startsWith('tb1p'),
          isTrue);
    });

    test('refuses anything but a 33-byte compressed key', () {
      expect(
        () => btcTaprootAddressFromPublicKey(
            Uint8List.sublistView(_childAt(0, 0), 1)),
        throwsA(predicate((e) => '$e'.contains('33-byte compressed key'))),
      );
    });

    test('ignores the child key Y parity, as BIP-341 lift_x requires', () {
      // lift_x always takes the even-Y point, so a 0x02 and a 0x03 prefix over
      // the same x must land on the same address. A hand-rolled tweak that
      // forgets to negate the odd case gets this wrong.
      final child = _childAt(0, 0);
      final flipped = Uint8List.fromList(child);
      flipped[0] = child[0] == 0x02 ? 0x03 : 0x02;
      expect(btcTaprootAddressFromPublicKey(flipped),
          btcTaprootAddressFromPublicKey(child));
    });
  });
}
