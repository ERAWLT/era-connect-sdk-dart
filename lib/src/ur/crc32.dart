import 'dart:typed_data';

final Uint32List _table = () {
  final table = Uint32List(256);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) != 0 ? (0xedb88320 ^ (c >> 1)) & 0xffffffff : c >> 1;
    }
    table[i] = c & 0xffffffff;
  }
  return table;
}();

/// IEEE CRC-32 (polynomial 0xEDB88320), table-driven, result as unsigned.
int crc32(Uint8List bytes) {
  var crc = 0xffffffff;
  for (final byte in bytes) {
    crc = ((crc >> 8) ^ _table[(crc ^ byte) & 0xff]) & 0xffffffff;
  }
  return (crc ^ 0xffffffff) & 0xffffffff;
}
