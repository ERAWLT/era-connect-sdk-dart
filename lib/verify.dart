/// Subpath library: `package:era_connect/verify.dart`.
///
/// "Did the device sign exactly what I sent?" — run these between parsing a
/// reply and broadcasting it. Kept out of the root library's hot path so the
/// curve arithmetic is only linked by apps that import it (do).
///
/// Every type an argument object DECLARES is exported here, so an app that
/// imports this library alone can name the values it hands the verifiers and
/// catch what the parsers throw.
library;

// `VerifyCardanoSignatureArgs.witnesses` is a list of these.
export 'src/chains/cardano.dart' show CardanoWitness;
// `VerifyEvmSignatureArgs.dataType` is one of these.
export 'src/chains/evm.dart' show EvmDataType;
// `VerifyTonSignatureArgs.dataType` is one of these.
export 'src/chains/ton.dart' show TonDataType;
// `VerifyTronSignatureArgs.latestBlock` is a TronLatestBlock, and its
// `signedTx` is a SignedTronTx (or the raw hex of one).
export 'src/chains/tron.dart' show SignedTronTx, TronLatestBlock;
// `parsePsbt` and `bocRootHash` throw this; `on EraSdkError catch` needs it.
export 'src/core/errors.dart';
export 'src/verify/bch.dart';
export 'src/verify/btc.dart';
export 'src/verify/cardano.dart'
    show
        VerifyCardanoAccount,
        VerifyCardanoSignatureArgs,
        verifyCardanoSignature;
export 'src/verify/cosmos.dart';
export 'src/verify/evm.dart';
export 'src/verify/psbt_reader.dart'
    show ParsedPsbt, PsbtInputType, PsbtKeyValue, parsePsbt;
export 'src/verify/result.dart';
export 'src/verify/solana.dart';
export 'src/verify/sui.dart';
export 'src/verify/ton.dart';
export 'src/verify/ton_boc.dart';
export 'src/verify/tron.dart';
export 'src/verify/xrp.dart';
