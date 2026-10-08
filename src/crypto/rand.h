// 随机数：只使用芯片硬件 RNG（esp_random），失败即拒绝，不降级到弱源。
#ifndef ROCKEY_CRYPTO_RAND_H
#define ROCKEY_CRYPTO_RAND_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace rand {

void Fill(uint8_t* out, size_t len);
uint32_t U32();
uint64_t U64();
// [0, bound) 均匀；bound == 0 返回 0
uint32_t Below(uint32_t bound);

}  // namespace rand
}  // namespace rockey

#endif  // ROCKEY_CRYPTO_RAND_H