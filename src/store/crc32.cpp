#include "store/crc32.h"

namespace rockey {
namespace store {

uint32_t Crc32Extend(uint32_t c, const uint8_t* data, size_t len) {
  static uint32_t table[256];
  static bool init = false;
  if (!init) {
    for (uint32_t i = 0; i < 256; ++i) {
      uint32_t c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      table[i] = c;
    }
    init = true;
  }
  for (size_t i = 0; i < len; ++i) c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
  return c;
}

uint32_t Crc32(const uint8_t* data, size_t len) {
  return Crc32Extend(0xFFFFFFFFu, data, len) ^ 0xFFFFFFFFu;
}

}  // namespace store
}  // namespace rockey