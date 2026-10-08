#include "crypto/rand.h"

extern "C" {
#include "esp_random.h"
}

#include "core/log.h"

namespace rockey {
namespace rand {

void Fill(uint8_t* out, size_t len) {
  if (!out || len == 0) return;
  esp_fill_random(out, len);
}

uint32_t U32() {
  uint8_t b[4];
  Fill(b, sizeof(b));
  return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
         (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
}

uint64_t U64() {
  uint64_t lo = U32();
  uint64_t hi = U32();
  return lo | (hi << 32);
}

uint32_t Below(uint32_t bound) {
  if (bound == 0) return 0;
  // 拒绝采样，避免取模偏置
  uint32_t limit = 0xFFFFFFFFu - (0xFFFFFFFFu % bound);
  for (int i = 0; i < 64; ++i) {
    uint32_t v = U32();
    if (v < limit) return v % bound;
  }
  RK_LOGE("rand", "rejection sampling exhausted");
  return 0;
}

}  // namespace rand
}  // namespace rockey