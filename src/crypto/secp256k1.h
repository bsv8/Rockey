// secp256k1：公钥压缩、严格 DER 与 64 字节 compact 签名、RFC6979 确定性 nonce、
// low-S 规范化。
//
// 冻结规则（协议草案 §5）：
//  - 身份私钥是原始 32 字节标量；不隐式二次 hash；
//  - 签名格式必须由调用方显式指定 DER 或 compact，不把 compact 当带恢复 ID 的格式；
//  - 确定性 nonce 采用 RFC6979(HMAC-SHA256)，与现有软件实作一致，便于双向向量比对；
//  - s 一律归一化为 low-S（s <= n/2），与 Keymaster 现有实现一致。
//
// 域运算使用 ESP-IDF 自带 mbedTLS 2.16 的 mbedtls_ecp_*（维护中的成熟实现），
// 本文件只补上 ECDSA 的规范化逻辑，不自创未审查的密码学构造。
#ifndef ROCKEY_CRYPTO_SECP256K1_H
#define ROCKEY_CRYPTO_SECP256K1_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace secp {

constexpr size_t kPrivLen = 32;
constexpr size_t kPubCompressedLen = 33;  // 02/03 || X
constexpr size_t kSigCompactLen = 64;     // r || s
constexpr size_t kSigDerMax = 72;

enum class SigFormat : uint8_t { kDer, kCompact };

bool ValidatePriv(const uint8_t priv[kPrivLen]);
bool PubkeyFromPriv(const uint8_t priv[kPrivLen], uint8_t pubCompressed[kPubCompressedLen]);
bool ValidatePubkey(const uint8_t pubCompressed[kPubCompressedLen]);

bool SignDer(const uint8_t priv[kPrivLen], const uint8_t digest32[32], uint8_t* derOut,
             size_t* derLen);
bool SignCompact(const uint8_t priv[kPrivLen], const uint8_t digest32[32],
                 uint8_t compactOut[kSigCompactLen]);

bool VerifyDer(const uint8_t pubCompressed[kPubCompressedLen], const uint8_t digest32[32],
               const uint8_t* der, size_t derLen);
bool VerifyCompact(const uint8_t pubCompressed[kPubCompressedLen], const uint8_t digest32[32],
                   const uint8_t compact[kSigCompactLen]);

// DER <-> r||s
size_t EncodeDer(const uint8_t r[32], const uint8_t s[32], uint8_t* out, size_t outCap);
bool DecodeDer(const uint8_t* der, size_t derLen, uint8_t r[32], uint8_t s[32]);

bool LowS(const uint8_t s[32], uint8_t out[32]);

}  // namespace secp
}  // namespace rockey

#endif  // ROCKEY_CRYPTO_SECP256K1_H