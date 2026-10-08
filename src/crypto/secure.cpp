#include "crypto/secure.h"

namespace rockey {
namespace secure {

void Wipe(void* p, size_t n) {
  if (!p || n == 0) return;
  volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
  for (size_t i = 0; i < n; ++i) v[i] = 0;
}

bool ConstEq(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
  return diff == 0;
}

bool ConstEq(const void* a, const void* b, size_t n) {
  return ConstEq(static_cast<const uint8_t*>(a), static_cast<const uint8_t*>(b), n);
}

}  // namespace secure
}  // namespace rockey