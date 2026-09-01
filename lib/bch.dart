/// Subpath library: `package:era_connect/bch.dart` — the bch chain module
/// plus the shared request/scan plumbing, without the rest of the SDK.
library;

export 'src/chains/bch.dart';
export 'src/chains/shared.dart'
    show
        ChainContext,
        EraConnectConfig,
        ExpectedReply,
        SignRequest,
        resolveContext;
export 'src/core/errors.dart';
export 'src/qr/animated_ur.dart';
export 'src/scan/ur_scanner.dart';
export 'src/ur/ur.dart' show Ur;
