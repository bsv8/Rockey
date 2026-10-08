// 本地秘密 v3：与 Keymaster `active-key-hkdf-v1` 逐字节兼容。
//
// 冻结（对齐 keymaster.cc packages/plugin-vault/src）：
//   IKM   = 32 字节身份私钥（原样，不哈希、不编码）
//   HKDF  = SHA-256，salt = UTF-8 "keymaster.vault.local-secret.v3"（固定串，31 字节）
//           info = UTF-8(小写压缩公钥 hex 文本) || 0x00 || UTF-8(scope)
//           输出 256 bit，用作 AES-256-GCM 密钥
//   AAD   = UTF-8("keymaster:local-secret:v3|" || scope) || 0x00 || salt(16)
//   envelope = { version:3, keySource:"active-key-hkdf-v1",
//                saltHex, nonceHex, ciphertextHex }  ciphertextHex = 密文||16B tag
//
// 易错点（务必保持）：
//  - envelope 的 16 字节 salt 只进 AAD，绝不是 HKDF 的 salt；
//  - HKDF 命名空间用点号，AAD 命名空间用冒号加竖线；
//  - scope 在 HKDF info 与 AAD 中各出现一次，不做任何归一化；
//  - 长期派生密钥永不离开设备，也不提供给任何插件。
#ifndef ROCKEY_OPS_LOCAL_SECRET_H
#define ROCKEY_OPS_LOCAL_SECRET_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace ops {

constexpr uint8_t kEnvelopeVersion = 3;
constexpr const char* kKeySource = "active-key-hkdf-v1";
constexpr size_t kSaltLen = 16;
constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;
constexpr size_t kScopeMax = 256;
constexpr size_t kPlaintextMax = 4096;

struct SealedSecret {
  uint8_t salt[kSaltLen] = {0};
  uint8_t nonce[kNonceLen] = {0};
  uint8_t ciphertext[kPlaintextMax + kTagLen] = {0};
  size_t ciphertextLen = 0;
};

// scope 校验与 Keymaster 侧一致：非空、长度 <= 256、拒绝 C0 控制与 DEL
bool ValidateScope(const char* scope, size_t len);

// 在设备内部派生；返回 false 表示 scope 非法或私钥不可用
bool DeriveKey(const char* scope, size_t scopeLen, uint8_t out[32]);

bool Seal(const char* scope, size_t scopeLen, const uint8_t* plaintext, size_t ptLen,
          SealedSecret* out);
bool Open(const char* scope, size_t scopeLen, const SealedSecret& sealed, uint8_t* plaintext,
          size_t ptCap, size_t* ptLen);

// 只做兼容性自检（用固定私钥与固定 salt/nonce 比对公开向量）
bool SelfTest();

}  // namespace ops
}  // namespace rockey

#endif  // ROCKEY_OPS_LOCAL_SECRET_H