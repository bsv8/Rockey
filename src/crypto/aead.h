// AES-256-GCM。
//
// 为什么自己实现：ESP-IDF 为缩小体积把 mbedTLS 的 MBEDTLS_GCM_C /
// MBEDTLS_CHACHAPOLY_C / MBEDTLS_RIPEMD160_C 编译掉了（mbedcrypto.a 里只剩
// esp_aes_* 硬件加速部分），而本地秘密 v3 必须与 WebCrypto 的 AES-GCM 逐字节
// 兼容，不能换成别的 AEAD。
//
// 实现：块加密用 ESP32 硬件 AES（esp_aes_crypt_ecb），GHASH 用 GF(2^128) 软件乘法。
// 严格按 NIST SP 800-38D：12 字节 IV -> J0 = IV || 0^00000001，tag 128 位。
// 内置 NIST GCM 测试向量自检，见 SelfTest()。
#ifndef ROCKEY_CRYPTO_AEAD_H
#define ROCKEY_CRYPTO_AEAD_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace aead {

constexpr size_t kKeyLen = 32;   // AES-256
constexpr size_t kNonceLen = 12;  // GCM 标准 IV 长度
constexpr size_t kTagLen = 16;

// AAD 与密文分离；认证失败时不得留下明文
bool Seal(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], const uint8_t* aad,
          size_t aadLen, const uint8_t* pt, size_t ptLen, uint8_t* ct, uint8_t tag[kTagLen]);
bool Open(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], const uint8_t* aad,
          size_t aadLen, const uint8_t* ct, size_t ctLen, const uint8_t tag[kTagLen],
          uint8_t* pt);

// NIST SP 800-38D / GCM 规范测试向量自检
bool SelfTest();

}  // namespace aead
}  // namespace rockey

#endif  // ROCKEY_CRYPTO_AEAD_H