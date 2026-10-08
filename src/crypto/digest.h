// 摘要与 KDF：SHA-256 / SHA-256d / HMAC-SHA256 / HKDF / PBKDF2 / SHA-512。
//
// 业务派生（协议草案 §5）严格固定：
//   本地秘密 keySource = active-key-hkdf-v1
//     IKM   = 32 字节身份私钥
//     salt  = UTF-8 "keymaster.vault.local-secret.v3"
//     info  = UTF-8(小写压缩公钥 hex) || 0x00 || UTF-8(scope)
//     输出  = 256 bit
//   AAD 基础文本 = "keymaster:local-secret:v3|" || scope
#ifndef ROCKEY_CRYPTO_DIGEST_H
#define ROCKEY_CRYPTO_DIGEST_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace digest {

constexpr size_t kSha256Len = 32;
constexpr size_t kSha512Len = 64;

void Sha256(const uint8_t* data, size_t len, uint8_t out[kSha256Len]);
void Sha256d(const uint8_t* data, size_t len, uint8_t out[kSha256Len]);  // BSV 双 SHA
void HmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen,
                uint8_t out[kSha256Len]);
// RFC5869 HKDF-SHA256
void HkdfSha256(const uint8_t* ikm, size_t ikmLen, const uint8_t* salt, size_t saltLen,
                const uint8_t* info, size_t infoLen, uint8_t* out, size_t outLen);
// PBKDF2-HMAC-SHA256（PIN 解封材料）
void Pbkdf2Sha256(const uint8_t* pw, size_t pwLen, const uint8_t* salt, size_t saltLen,
                  uint32_t iterations, uint8_t* out, size_t outLen);

// Hex 工具（只用于公开标识符与地址，不用于秘密）
size_t ToHex(const uint8_t* data, size_t len, char* out, size_t outCap);
bool FromHex(const char* hex, size_t hexLen, uint8_t* out, size_t outCap, size_t* outLen);

}  // namespace digest
}  // namespace rockey

#endif  // ROCKEY_CRYPTO_DIGEST_H