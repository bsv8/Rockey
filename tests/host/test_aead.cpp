// 主机侧测试：把 src/crypto/aead.cpp 的 AES-GCM 与 mbedTLS 的 GCM 逐字节对照。
//
// 为什么要有这一组：aead.cpp 自己实现 GHASH 与 GCTR（只有 AES 分组来自
// ESP-IDF）。曾经有一处把 GHASH 的输入取成了解密后的明文而不是密文，
// 于是 Open 永远失败 —— 设备解不了封装、解不开旧本地秘密、也解不开任何
// 加密帧。而它自己的 SelfTest 当时又拿 AES-256 的输出去比 AES-128 的
// NIST 用例，一直在报"失败"，把真正的问题盖住了。
//
// 这里用 mbedtls_gcm 作为成熟实现的参照，覆盖空明文 / 整块 / 跨块 /
// 带尾零头 / 带 AAD / 长 AAD 组合，并验证 Open 往返与各类篡改拒绝。
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" {
#include <mbedtls/gcm.h>
}

#include "crypto/aead.h"

namespace {

int g_pass = 0;
int g_fail = 0;

void Check(bool cond, const char* what) {
  if (cond) {
    g_pass++;
  } else {
    g_fail++;
    printf("  FAIL %s\n", what);
  }
}

void Fuzz() {
  uint32_t s = 0xC0FFEEu;
  auto next = [&s]() -> uint8_t {
    s = s * 1664525u + 1013904223u;
    return static_cast<uint8_t>(s >> 24);
  };

  static const int kLens[] = {0, 1, 15, 16, 17, 31, 32, 33, 64, 100};
  for (int aadLen : kLens) {
    for (int ptLen : kLens) {
      uint8_t key[32], nonce[12], pt[128], aad[128], refCt[128], refTag[16];
      for (int i = 0; i < 32; ++i) key[i] = next();
      for (int i = 0; i < 12; ++i) nonce[i] = next();
      for (int i = 0; i < ptLen; ++i) pt[i] = next();
      for (int i = 0; i < aadLen; ++i) aad[i] = next();

      mbedtls_gcm_context g;
      mbedtls_gcm_init(&g);
      int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
      if (rc != 0) {
        mbedtls_gcm_free(&g);
        continue;
      }
      rc = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, static_cast<size_t>(ptLen), nonce,
                                      12, aad, static_cast<size_t>(aadLen), pt, refCt, 16, refTag);
      mbedtls_gcm_free(&g);
      if (rc != 0) {
        g_fail++;
        printf("  FAIL mbedtls reference failed for pt=%d aad=%d\n", ptLen, aadLen);
        continue;
      }

      uint8_t ct[128], tag[16];
      bool sealed = rockey::aead::Seal(key, nonce, aadLen ? aad : nullptr,
                                       static_cast<size_t>(aadLen), ptLen ? pt : nullptr,
                                       static_cast<size_t>(ptLen), ct, tag);
      Check(sealed, "Seal succeeded");
      if (!sealed) continue;
      Check(ptLen == 0 || memcmp(ct, refCt, static_cast<size_t>(ptLen)) == 0,
            "ciphertext matches mbedtls");
      Check(memcmp(tag, refTag, 16) == 0, "tag matches mbedtls");

      uint8_t back[128];
      Check(rockey::aead::Open(key, nonce, aadLen ? aad : nullptr, static_cast<size_t>(aadLen), ct,
                               static_cast<size_t>(ptLen), tag, back),
            "Open accepts what Seal produced");
      Check(ptLen == 0 || memcmp(back, pt, static_cast<size_t>(ptLen)) == 0, "plaintext restored");

      if (ptLen) {
        tag[0] ^= 0x80;
        Check(!rockey::aead::Open(key, nonce, aadLen ? aad : nullptr, static_cast<size_t>(aadLen), ct,
                                  static_cast<size_t>(ptLen), tag, back),
              "tampered tag rejected");
        tag[0] ^= 0x80;
        ct[0] ^= 0x10;
        Check(!rockey::aead::Open(key, nonce, aadLen ? aad : nullptr, static_cast<size_t>(aadLen), ct,
                                  static_cast<size_t>(ptLen), tag, back),
              "tampered ciphertext rejected");
        ct[0] ^= 0x10;
      }
      if (aadLen) {
        aad[0] ^= 0x40;
        Check(!rockey::aead::Open(key, nonce, aad, static_cast<size_t>(aadLen), ct,
                                  static_cast<size_t>(ptLen), tag, back),
              "tampered aad rejected");
        aad[0] ^= 0x40;
      }
      // 换密钥必须失败
      uint8_t otherKey[32];
      memcpy(otherKey, key, 32);
      otherKey[31] ^= 1;
      Check(!rockey::aead::Open(otherKey, nonce, aadLen ? aad : nullptr, static_cast<size_t>(aadLen),
                                ct, static_cast<size_t>(ptLen), tag, back),
            "wrong key rejected");
      // 换 nonce 必须失败
      uint8_t otherNonce[12];
      memcpy(otherNonce, nonce, 12);
      otherNonce[0] ^= 1;
      Check(!rockey::aead::Open(key, otherNonce, aadLen ? aad : nullptr, static_cast<size_t>(aadLen),
                                ct, static_cast<size_t>(ptLen), tag, back),
            "wrong nonce rejected");
    }
  }
}

}  // namespace

int main() {
  printf("rockey host tests: crypto/aead vs mbedtls gcm\n");

  Check(rockey::aead::SelfTest(), "aead::SelfTest() passes");

  // 固定向量（key=00..1f, iv=00,10,...,a0），先于随机化对照确认基础路径
  {
    uint8_t key[32], nonce[12], pt[20], ct[20], tag[16];
    for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 12; ++i) nonce[i] = static_cast<uint8_t>(0x10 * i);
    for (int i = 0; i < 20; ++i) pt[i] = static_cast<uint8_t>(i);
    // 整块 + 4 字节零头、无 AAD：覆盖 CTR 尾块与 GHASH 填充两条路径
    static const uint8_t kCt[20] = {0x59, 0x21, 0x25, 0xd1, 0xab, 0x26, 0x38, 0x50, 0x49, 0x46,
                                    0xcd, 0x87, 0x21, 0xe8, 0x68, 0xda, 0x34, 0x0d, 0x18, 0x54};
    static const uint8_t kTag[16] = {0xcf, 0x15, 0xb3, 0x68, 0xdc, 0x75, 0xdc, 0xf2, 0xa5, 0xd9,
                                     0xeb, 0xe4, 0xec, 0xe5, 0xb7, 0x75};
    Check(rockey::aead::Seal(key, nonce, nullptr, 0, pt, 20, ct, tag), "fixed vector sealed");
    Check(memcmp(ct, kCt, 20) == 0, "fixed ciphertext");
    Check(memcmp(tag, kTag, 16) == 0, "fixed tag");
  }

  Fuzz();

  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}