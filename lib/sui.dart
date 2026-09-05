/// Subpath library: `package:era_connect/sui.dart` — the sui chain module
/// plus the shared request/scan plumbing, without the rest of the SDK.
library;

export 'src/chains/sui.dart';
export 'src/chains/shared.dart'
    show
        ChainContext,
        EraConnectConfig,
        ExpectedReply,
        SignRequest,
        defaultOrigin,
        resolveContext;
export 'src/core/errors.dart';
export 'src/qr/animated_ur.dart';
export 'src/scan/ur_scanner.dart';
export 'src/ur/ur.dart' show Ur;
