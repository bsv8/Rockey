// X25519（RFC 7748）。
//
// 为什么自己实现：握手需要与主机互操作的固定格式 X25519 临时密钥，
// 而 ESP-IDF 5.x 自带 mbedTLS 2.28 对 Montgomery 点的序列化格式不做承诺。
// 本实现严格按 RFC 7748 编写（Montgomery ladder + a24 = 121665，模 2^255-19），
// 并内置 RFC 7748 §5.2 / §6.1 官方测试向量自检，见 SelfTest()。
//
// 域运算复用 mbedtls_mpi（维护中的成熟大数库），只补 20 行 ladder。
#ifndef ROCKEY_CRYPTO_X25519_H
#define ROCKEY_CRYPTO_X25519_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace x25519 {

constexpr size_t kKeyLen = 32;

void Clamp(uint8_t k[32]);
void PublicFromPrivate(const uint8_t priv[32], uint8_t pub[32]);
bool Shared(const uint8_t priv[32], const uint8_t peerPub[32], uint8_t out[32]);
// 内置 RFC 7748 官方向量自检
bool SelfTest();

}  // namespace x25519
}  // namespace rockey

#endif  // ROCKEY_CRYPTO_X25519_H