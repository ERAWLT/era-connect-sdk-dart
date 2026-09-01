import 'dart:typed_data';

import 'package:archive/archive.dart'
    show GZipEncoder, Inflate, InputMemoryStream;

import '../core/errors.dart';
import '../ur/crc32.dart';

/// Smallest possible gzip stream: 10-byte header + 8-byte trailer.
const int _minGzipBytes = 18;

/// Deterministic gzip (fixed level, zeroed mtime) for reproducible request bytes.
Uint8List gzipCompress(Uint8List data) {
  final out = const GZipEncoder().encodeBytes(data, level: 9);
  // The dart:io-backed encoder (zlib) already stamps MTIME = 0; the pure-Dart
  // encoder used on the web stamps the current time. Zero the four MTIME
  // bytes unconditionally so the same input yields the same bytes everywhere.
  out[4] = 0;
  out[5] = 0;
  out[6] = 0;
  out[7] = 0;
  return out;
}

/// Inflate with a hard output ceiling.
///
/// The ceiling is enforced AFTER a one-shot inflate rather than during it:
/// every caller caps the COMPRESSED input first (payload and scan limits),
/// and DEFLATE expands at most ~1032:1, so the transient allocation is
/// bounded before the cap check runs. The trailer's ISIZE (declared inflated
/// length) is still checked up front as a cheap refusal of honest bombs
/// before any work.
///
/// ISIZE is used a second time as a truncation check at the end — an
/// inflater hands back a partial buffer for a truncated stream without
/// erroring, and a genuine device reply always declares honestly.
Uint8List gunzipCapped(Uint8List data, int maxOutputBytes) {
  if (data.length < _minGzipBytes) {
    throw EraSdkError(
      'gzip-error',
      'compressed payload is too short to be a gzip stream',
    );
  }
  if (data[0] != 0x1f || data[1] != 0x8b) {
    throw EraSdkError(
      'gzip-error',
      'compressed payload is not a gzip stream',
    );
  }
  final n = data.length;
  final isize = data[n - 4] |
      (data[n - 3] << 8) |
      (data[n - 2] << 16) |
      (data[n - 1] << 24);
  if (isize > maxOutputBytes) {
    throw EraSdkError(
      'gzip-error',
      'compressed payload declares $isize bytes, over the $maxOutputBytes byte ceiling',
    );
  }

  // Hand-parse the member header (RFC 1952): CM must be DEFLATE, the three
  // reserved FLG bits must be clear, and the optional FEXTRA/FNAME/FCOMMENT/
  // FHCRC fields are skipped with every read bounds-checked against the
  // start of the 8-byte trailer.
  if (data[2] != 8) {
    throw EraSdkError(
      'gzip-error',
      'compressed payload is malformed: unknown compression method',
    );
  }
  final flg = data[3];
  if (flg & 0xe0 != 0) {
    throw EraSdkError(
      'gzip-error',
      'compressed payload is malformed: reserved header flag bits set',
    );
  }
  final bodyEnd = n - 8;
  var offset = 10;
  EraSdkError truncatedHeader() => EraSdkError(
        'gzip-error',
        'compressed payload is malformed: truncated header',
      );
  if (flg & 0x04 != 0) {
    // FEXTRA: 2-byte little-endian XLEN, then XLEN bytes.
    if (offset + 2 > bodyEnd) throw truncatedHeader();
    final xlen = data[offset] | (data[offset + 1] << 8);
    offset += 2;
    if (offset + xlen > bodyEnd) throw truncatedHeader();
    offset += xlen;
  }
  if (flg & 0x08 != 0) {
    // FNAME: zero-terminated.
    for (;;) {
      if (offset >= bodyEnd) throw truncatedHeader();
      if (data[offset++] == 0) break;
    }
  }
  if (flg & 0x10 != 0) {
    // FCOMMENT: zero-terminated.
    for (;;) {
      if (offset >= bodyEnd) throw truncatedHeader();
      if (data[offset++] == 0) break;
    }
  }
  if (flg & 0x02 != 0) {
    // FHCRC: CRC16 of the header.
    if (offset + 2 > bodyEnd) throw truncatedHeader();
    offset += 2;
  }
  if (offset >= bodyEnd) {
    throw EraSdkError(
      'gzip-error',
      'compressed payload is malformed: truncated deflate stream',
    );
  }

  // The inflater stops at the final DEFLATE block, so handing it everything
  // up to the trailer is safe even for a crafted multi-member stream — the
  // extra members are never inflated and the trailer checks below refuse
  // them (and any other trailing garbage).
  Uint8List out;
  try {
    final body = data.sublist(offset, bodyEnd);
    final input = InputMemoryStream(body);
    out = Uint8List.fromList(Inflate.stream(input).getBytes());
    // DEFLATE is self-terminating, so the inflater stops at the final block
    // and would silently ignore bytes wedged between the stream and the
    // trailer. The reference SDK's streaming decoder refuses them (they are
    // neither a trailer nor a next member) — refuse them here too.
    if (input.position != body.length) {
      throw EraSdkError(
        'gzip-error',
        'compressed payload is malformed: trailing bytes after the DEFLATE stream',
      );
    }
  } catch (e) {
    if (e is EraSdkError) rethrow;
    throw EraSdkError('gzip-error', 'compressed payload is malformed: $e');
  }

  if (out.length > maxOutputBytes) {
    throw EraSdkError(
      'gzip-error',
      'compressed payload inflates past the $maxOutputBytes byte ceiling',
    );
  }
  if (out.length != isize) {
    throw EraSdkError(
      'gzip-error',
      'compressed payload inflated to ${out.length} bytes but declares $isize — truncated or malformed',
    );
  }
  // The trailer CRC32 (little-endian, bytes n-8..n-5) must cover the inflated
  // output. The inflater does not verify it, and the reference
  // implementation's native decoder does — without this check a corrupted
  // stream, or a CONCATENATED multi-member stream (whose final member's CRC
  // cannot cover the whole output), would be accepted here and refused there.
  final declaredCrc = data[n - 8] |
      (data[n - 7] << 8) |
      (data[n - 6] << 16) |
      (data[n - 5] << 24);
  if (crc32(out) != declaredCrc) {
    throw EraSdkError(
      'gzip-error',
      'compressed payload is malformed: CRC mismatch',
    );
  }
  return out;
}
