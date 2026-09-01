import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

/// Ed25519 signature verification (RFC 8032). Returns false instead of
/// throwing on structurally invalid inputs — verify helpers report, they do
/// not crash.
bool ed25519Verify(Uint8List publicKey32, Uint8List message, Uint8List signature64) {
  if (publicKey32.length != 32 || signature64.length != 64) return false;
  try {
    return ed.verify(ed.PublicKey(publicKey32), message, signature64);
  } on Object {
    return false;
  }
}
