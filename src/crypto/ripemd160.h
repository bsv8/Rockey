// RIPEMD-160（ISO/IEC 10118-3）。
//
// 用途：BSV P2PKH 地址的 hash160 = RIPEMD160(SHA256(pubkey))。
// ESP-IDF 的 mbedTLS 出于体积把 MBEDTLS_RIPEMD160_C 编译掉了，这里按规范实现
// 并内置官方向量自检（见 SelfTest()）。
#ifndef ROCKEY_CRYPTO_RIPEMD160_H
#define ROCKEY_CRYPTO_RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace ripemd {

constexpr size_t kDigestLen = 20;
void Hash(const uint8_t* data, size_t len, uint8_t out[kDigestLen]);
bool SelfTest();

}  // namespace ripemd
}  // namespace rockey

#endif  // ROCKEY_CRYPTO_RIPEMD160_H