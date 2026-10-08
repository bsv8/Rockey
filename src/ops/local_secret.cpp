#include "ops/local_secret.h"

#include <string.h>

#include "crypto/aead.h"
#include "crypto/digest.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/secure.h"
#include "store/keystore.h"

namespace rockey {
namespace ops {
namespace {

constexpr const char* kHkdfSalt = "keymaster.vault.local-secret.v3";
constexpr const char* kAadPrefix = "keymaster:local-secret:v3|";

// AAD = UTF8(prefix || scope) || 0x00 || salt
void BuildAad(const char* scope, size_t scopeLen, const uint8_t salt[kSaltLen], uint8_t* out,
              size_t* outLen) {
  size_t prefixLen = strlen(kAadPrefix);
  size_t n = prefixLen + scopeLen + 1 + kSaltLen;
  memcpy(out, kAadPrefix, prefixLen);
  memcpy(out + prefixLen, scope, scopeLen);
  out[prefixLen + scopeLen] = 0;
  memcpy(out + prefixLen + scopeLen + 1, salt, kSaltLen);
  *outLen = n;
}

}  // namespace

bool ValidateScope(const char* scope, size_t len) {
  if (!scope || len == 0 || len > kScopeMax) return false;
  for (size_t i = 0; i < len; ++i) {
    uint8_t c = static_cast<uint8_t>(scope[i]);
    if (c <= 0x1F || c == 0x7F) return false;
  }
  return true;
}

bool DeriveKey(const char* scope, size_t scopeLen, uint8_t out[32]) {
  if (!ValidateScope(scope, scopeLen)) return false;
  const uint8_t* priv = keystore::KeyStore::PrivateKey();
  if (!priv) return false;
  const uint8_t* pub = keystore::KeyStore::PublicKey();

  // info = 小写压缩公钥 hex 文本 || 0x00 || scope
  uint8_t info[2 * 33 + 1 + kScopeMax];
  size_t hexLen = digest::ToHex(pub, 33, reinterpret_cast<char*>(info), sizeof(info));
  if (hexLen == 0) return false;
  info[hexLen] = 0x00;
  memcpy(info + hexLen + 1, scope, scopeLen);

  digest::HkdfSha256(priv, 32, reinterpret_cast<const uint8_t*>(kHkdfSalt), strlen(kHkdfSalt),
                     info, hexLen + 1 + scopeLen, out, 32);
  secure::Wipe(info, sizeof(info));
  return true;
}

bool Seal(const char* scope, size_t scopeLen, const uint8_t* plaintext, size_t ptLen,
          SealedSecret* out) {
  if (!out || ptLen > kPlaintextMax) return false;
  if (ptLen && !plaintext) return false;
  secure::SecretBytes<32> key{};
  if (!DeriveKey(scope, scopeLen, key.data())) return false;

  rand::Fill(out->salt, kSaltLen);
  rand::Fill(out->nonce, kNonceLen);

  uint8_t aad[64 + kScopeMax + kSaltLen];
  size_t aadLen = 0;
  BuildAad(scope, scopeLen, out->salt, aad, &aadLen);

  bool ok = aead::Seal(key.data(), out->nonce, aad, aadLen, plaintext, ptLen, out->ciphertext,
                             out->ciphertext + ptLen);
  if (ok) out->ciphertextLen = ptLen + kTagLen;
  secure::Wipe(aad, sizeof(aad));
  return ok;
}

bool Open(const char* scope, size_t scopeLen, const SealedSecret& sealed, uint8_t* plaintext,
          size_t ptCap, size_t* ptLen) {
  if (sealed.ciphertextLen < kTagLen) return false;
  size_t bodyLen = sealed.ciphertextLen - kTagLen;
  if (bodyLen > ptCap || bodyLen > kPlaintextMax) return false;
  secure::SecretBytes<32> key{};
  if (!DeriveKey(scope, scopeLen, key.data())) return false;

  uint8_t aad[64 + kScopeMax + kSaltLen];
  size_t aadLen = 0;
  BuildAad(scope, scopeLen, sealed.salt, aad, &aadLen);

  bool ok = aead::Open(key.data(), sealed.nonce, aad, aadLen, sealed.ciphertext, bodyLen,
                             sealed.ciphertext + bodyLen, plaintext);
  secure::Wipe(aad, sizeof(aad));
  if (ok && ptLen) *ptLen = bodyLen;
  return ok;
}

bool SelfTest() {
  // 公开向量：私钥 = 1，scope = "storage.bucket-password"，固定 salt/nonce/明文。
  // 与 keymaster.cc 的 active-key-hkdf-v1 逐字节一致（WebCrypto HKDF-SHA256 + AES-256-GCM）。
  // 该向量由 scripts/check_test_vectors.py 对照权威实现复核。
  static const uint8_t kPriv1[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  static const uint8_t kExpectKey[32] = {0x8b, 0x95, 0x34, 0xf1, 0x6d, 0x1e, 0xec, 0x17,
                                         0x14, 0xc3, 0xc5, 0x64, 0x26, 0x52, 0xd3, 0xef,
                                         0xf0, 0xa9, 0xf7, 0xb7, 0x2e, 0x5d, 0xa4, 0xe9,
                                         0x97, 0x3d, 0x66, 0x6e, 0x8b, 0x25, 0x91, 0x12};
  static const char kScope[] = "storage.bucket-password";
  static const char kPubHex[] = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  static const uint8_t kPlain[] = "provider-secret";
  static const uint8_t kSalt[kSaltLen] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  static const uint8_t kNonce[kNonceLen] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b};
  static const uint8_t kExpectCt[31] = {0xea, 0x07, 0xbe, 0xc9, 0xb7, 0xf4, 0x61, 0xd9, 0x1d, 0x00, 0xf2, 0x79,
                                        0xb9, 0xad, 0xe3, 0x83, 0x03, 0xba, 0xa3, 0xf1, 0xa2, 0x8f, 0xd7, 0x37,
                                        0x37, 0x75, 0xc7, 0x84, 0xe7, 0x8f, 0x41};

  // 1) 公钥
  uint8_t pub[33];
  if (!secp::PubkeyFromPriv(kPriv1, pub)) return false;
  char hex[67];
  digest::ToHex(pub, 33, hex, sizeof(hex));
  if (memcmp(hex, kPubHex, 66) != 0) return false;

  // 2) HKDF 派生
  uint8_t info[2 * 33 + 1 + kScopeMax];
  size_t hexLen = digest::ToHex(pub, 33, reinterpret_cast<char*>(info), sizeof(info));
  info[hexLen] = 0x00;
  memcpy(info + hexLen + 1, kScope, sizeof(kScope) - 1);
  uint8_t key[32];
  digest::HkdfSha256(kPriv1, 32, reinterpret_cast<const uint8_t*>(kHkdfSalt), strlen(kHkdfSalt),
                     info, hexLen + 1 + sizeof(kScope) - 1, key, 32);
  bool ok = memcmp(key, kExpectKey, 32) == 0;
  secure::Wipe(key, sizeof(key));
  if (!ok) return false;

  // 3) AAD + 密文
  uint8_t aad[128];
  size_t aadLen = 0;
  BuildAad(kScope, sizeof(kScope) - 1, kSalt, aad, &aadLen);
  uint8_t ct[sizeof(kPlain) - 1 + kTagLen];
  uint8_t tag[kTagLen];
  if (!aead::Seal(kExpectKey, kNonce, aad, aadLen, kPlain, sizeof(kPlain) - 1, ct, tag)) {
    return false;
  }
  memcpy(ct + sizeof(kPlain) - 1, tag, kTagLen);
  ok = memcmp(ct, kExpectCt, sizeof(kExpectCt)) == 0;
  secure::Wipe(aad, sizeof(aad));
  if (!ok) return false;

  // 4) 换 scope 必须解封失败（scope 双重绑定）
  SealedSecret sealed;
  memset(&sealed, 0, sizeof(sealed));
  memcpy(sealed.salt, kSalt, kSaltLen);
  memcpy(sealed.nonce, kNonce, kNonceLen);
  memcpy(sealed.ciphertext, ct, sizeof(kExpectCt));
  sealed.ciphertextLen = sizeof(kExpectCt);
  uint8_t plain[64];
  size_t plainLen = 0;
  ok = Open(kScope, sizeof(kScope) - 1, sealed, plain, sizeof(plain), &plainLen) &&
       plainLen == sizeof(kPlain) - 1 && memcmp(plain, kPlain, plainLen) == 0;
  secure::Wipe(plain, sizeof(plain));
  if (!ok) return false;
  if (Open("other", 5, sealed, plain, sizeof(plain), &plainLen)) return false;
  secure::Wipe(plain, sizeof(plain));

  // 5) 篡改 envelope salt 必须解封失败
  sealed.salt[0] ^= 0x01;
  if (Open(kScope, sizeof(kScope) - 1, sealed, plain, sizeof(plain), &plainLen)) return false;
  secure::Wipe(plain, sizeof(plain));
  return true;
}

}  // namespace ops
}  // namespace rockey