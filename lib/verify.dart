/// Subpath library: `package:era_connect/verify.dart`.
///
/// "Did the device sign exactly what I sent?" — run these between parsing a
/// reply and broadcasting it. Kept out of the root library's hot path so the
/// curve arithmetic is only linked by apps that import it (do).
library;

export 'src/verify/bch.dart';
export 'src/verify/btc.dart';
export 'src/verify/cardano.dart';
export 'src/verify/cosmos.dart';
export 'src/verify/evm.dart';
export 'src/verify/psbt_reader.dart';
export 'src/verify/result.dart';
export 'src/verify/solana.dart';
export 'src/verify/sui.dart';
export 'src/verify/ton.dart';
export 'src/verify/ton_boc.dart';
export 'src/verify/tron.dart';
export 'src/verify/xrp.dart';
