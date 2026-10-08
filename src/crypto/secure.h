// 安全缓冲与常数时间比较。
//
// 需求 §2：解锁材料仅在设备内短暂存在，锁定/断电/重启清理。
// SecretBytes 在析构时无条件清零，且编译器无法省略（volatile 写）。
#ifndef ROCKEY_CRYPTO_SECURE_H
#define ROCKEY_CRYPTO_SECURE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace rockey {
namespace secure {

// 不可省略的清零：编译器不会因为结果未被使用而删掉 volatile 写。
void Wipe(void* p, size_t n);

bool ConstEq(const void* a, const void* b, size_t n);
bool ConstEq(const uint8_t* a, const uint8_t* b, size_t n);

template <size_t N>
class SecretBytes {
 public:
  SecretBytes() { Wipe(data_, N); }
  ~SecretBytes() { Wipe(data_, N); }
  SecretBytes(const SecretBytes&) = delete;
  SecretBytes& operator=(const SecretBytes&) = delete;

  uint8_t* data() { return data_; }
  const uint8_t* data() const { return data_; }
  static constexpr size_t size() { return N; }

  void Clear() { Wipe(data_, N); }
  bool Set(const uint8_t* src, size_t n) {
    if (n != N) return false;
    Wipe(data_, N);
    memcpy(data_, src, N);
    return true;
  }
  bool Equal(const uint8_t* other) const { return ConstEq(data_, other, N); }

 private:
  uint8_t data_[N];
};

}  // namespace secure
}  // namespace rockey

#endif  // ROCKEY_CRYPTO_SECURE_H