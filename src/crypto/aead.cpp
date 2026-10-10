#include "crypto/aead.h"

#include <string.h>

extern "C" {
#include "aes/esp_aes.h"
}

#include "crypto/secure.h"

namespace rockey {
namespace aead {
namespace {

// GF(2^128) 乘法：右移实现（GHASH 的 MUL）
void GfMul(uint8_t x[16], const uint8_t y[16]) {
  uint8_t z[16] = {0};
  uint8_t v[16];
  memcpy(v, y, 16);
  for (int i = 0; i < 128; ++i) {
    uint8_t bit = static_cast<uint8_t>((x[i >> 3] >> (7 - (i & 7))) & 1);
    if (bit) {
      for (int k = 0; k < 16; ++k) z[k] ^= v[k];
    }
    // v = v >> 1；最低位为 1 时乘以 R = 0xe1 || 0^120
    uint8_t lsb = static_cast<uint8_t>(v[15] & 1);
    for (int k = 15; k > 0; --k) v[k] = static_cast<uint8_t>((v[k] >> 1) | ((v[k - 1] & 1) << 7));
    v[0] = static_cast<uint8_t>(v[0] >> 1);
    if (lsb) v[0] ^= 0xE1;
  }
  memcpy(x, z, 16);
  secure::Wipe(z, sizeof(z));
  secure::Wipe(v, sizeof(v));
}

struct Aes {
  esp_aes_context ctx;
  bool Init(const uint8_t key[kKeyLen]) {
    esp_aes_init(&ctx);
    return esp_aes_setkey(&ctx, key, kKeyLen * 8) == 0;
  }
  void EncryptBlock(const uint8_t in[16], uint8_t out[16]) {
    esp_aes_crypt_ecb(&ctx, ESP_AES_ENCRYPT, in, out);
  }
  ~Aes() { esp_aes_free(&ctx); }
};

// GHASH_H(A || pad || C || pad || [len(A)]64be || [len(C)]64be)
void Ghash(const uint8_t h[16], const uint8_t* aad, size_t aadLen, const uint8_t* ct,
           size_t ctLen, uint8_t out[16]) {
  uint8_t y[16] = {0};
  uint8_t block[16];
  auto absorb = [&](const uint8_t* p, size_t n) {
    size_t off = 0;
    while (off < n) {
      size_t take = n - off;
      if (take > 16) take = 16;
      memset(block, 0, 16);
      memcpy(block, p + off, take);
      for (int k = 0; k < 16; ++k) y[k] ^= block[k];
      GfMul(y, h);
      off += take;
    }
  };
  if (aadLen) absorb(aad, aadLen);
  if (ctLen) absorb(ct, ctLen);
  uint8_t lenBlock[16] = {0};
  uint64_t aBits = static_cast<uint64_t>(aadLen) * 8;
  uint64_t cBits = static_cast<uint64_t>(ctLen) * 8;
  for (int i = 0; i < 8; ++i) {
    lenBlock[i] = static_cast<uint8_t>(aBits >> (56 - 8 * i));
    lenBlock[8 + i] = static_cast<uint8_t>(cBits >> (56 - 8 * i));
  }
  for (int k = 0; k < 16; ++k) y[k] ^= lenBlock[k];
  GfMul(y, h);
  memcpy(out, y, 16);
  secure::Wipe(y, sizeof(y));
}

void Inc32(uint8_t ctr[16]) {
  for (int i = 15; i >= 12; --i) {
    if (++ctr[i] != 0) break;
  }
}

// GCTR：用计数器块流加密
void Gctr(Aes& aes, uint8_t j0[16], const uint8_t* in, size_t len, uint8_t* out) {
  if (len == 0) return;
  uint8_t ctr[16];
  memcpy(ctr, j0, 16);
  uint8_t ks[16];
  size_t off = 0;
  while (off < len) {
    Inc32(ctr);
    aes.EncryptBlock(ctr, ks);
    size_t take = len - off;
    if (take > 16) take = 16;
    for (size_t i = 0; i < take; ++i) out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
    off += take;
  }
  secure::Wipe(ks, sizeof(ks));
  secure::Wipe(ctr, sizeof(ctr));
}

void MakeJ0(const uint8_t nonce[kNonceLen], uint8_t j0[16]) {
  memcpy(j0, nonce, kNonceLen);
  j0[12] = 0;
  j0[13] = 0;
  j0[14] = 0;
  j0[15] = 1;
}

bool Core(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], const uint8_t* aad,
          size_t aadLen, const uint8_t* in, size_t len, uint8_t* out, uint8_t tag[kTagLen],
          bool encrypting) {
  if (kNonceLen != 12) return false;
  Aes aes;
  if (!aes.Init(key)) return false;
  uint8_t zero[16] = {0};
  uint8_t h[16];
  aes.EncryptBlock(zero, h);
  uint8_t j0[16];
  MakeJ0(nonce, j0);
  Gctr(aes, j0, in, len, out);
  // GHASH 必须覆盖**密文**。
  // 加密方向 out 就是密文；解密方向 in 是密文而 out 是明文 —— 早先这里一律
  // 用 out，于是 Open 的校验和永远算不对，解封、解本地秘密、解密帧全部失败。
  const uint8_t* ctForHash = encrypting ? out : in;
  uint8_t s[16];
  Ghash(h, aad, aadLen, ctForHash, len, s);
  uint8_t ej0[16];
  aes.EncryptBlock(j0, ej0);
  for (int k = 0; k < 16; ++k) tag[k] = static_cast<uint8_t>(s[k] ^ ej0[k]);
  secure::Wipe(h, sizeof(h));
  secure::Wipe(s, sizeof(s));
  secure::Wipe(ej0, sizeof(ej0));
  return true;
}

}  // namespace

bool Seal(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], const uint8_t* aad,
          size_t aadLen, const uint8_t* pt, size_t ptLen, uint8_t* ct, uint8_t tag[kTagLen]) {
  if (!key || !nonce || !tag) return false;
  if (ptLen && !pt) return false;
  return Core(key, nonce, aad, aadLen, pt, ptLen, ct, tag, true);
}

bool Open(const uint8_t key[kKeyLen], const uint8_t nonce[kNonceLen], const uint8_t* aad,
          size_t aadLen, const uint8_t* ct, size_t ctLen, const uint8_t tag[kTagLen],
          uint8_t* pt) {
  if (!key || !nonce || !tag) return false;
  if (ctLen && !ct) return false;
  uint8_t want[kTagLen];
  if (!Core(key, nonce, aad, aadLen, ct, ctLen, pt, want, false)) return false;
  if (!secure::ConstEq(want, tag, kTagLen)) {
    if (pt && ctLen) secure::Wipe(pt, ctLen);
    secure::Wipe(want, sizeof(want));
    return false;
  }
  secure::Wipe(want, sizeof(want));
  return true;
}

bool SelfTest() {
  // 说明：本自检原先拿 **AES-256** 的输出去比 NIST 官方的 **AES-128** 用例
  // （Test case 1/2），所以每次上电都报失败，而实现本身其实是对的。
  // 现在改为与 mbedTLS 的 AES-GCM 逐字节对齐的 AES-256 向量，覆盖
  // 空明文 / 整块 / 带尾部零头 / 带 AAD，以及 Open 的往返与篡改拒绝。
  // AES 分组由 ESP-IDF 提供，GHASH/CTR 组合由本文件实现，所以这里的向量
  // 真正校验的是 GHASH 与 GCTR 的组合，而不是只测 AES。
  //
  // key = 00 01 .. 1f, iv = 00 10 20 .. a0, pt = 00 01 .., aad = a0 a1 ..
  struct Case {
    uint8_t ptLen;
    uint8_t aadLen;
    const uint8_t* ct;
    uint8_t ctLen;
    const uint8_t* tag;
  };
  static const uint8_t kCtEmpty[] = {0};
  static const uint8_t kCtBlock[] = {0x59, 0x21, 0x25, 0xd1, 0xab, 0x26, 0x38, 0x50,
                                     0x49, 0x46, 0xcd, 0x87, 0x21, 0xe8, 0x68, 0xda};
  static const uint8_t kCtTail[] = {0x59, 0x21, 0x25, 0xd1, 0xab, 0x26, 0x38, 0x50, 0x49,
                                    0x46, 0xcd, 0x87, 0x21, 0xe8, 0x68, 0xda, 0x34, 0x0d,
                                    0x18, 0x54};
  static const uint8_t kCtAad[] = {0x59, 0x21, 0x25, 0xd1, 0xab, 0x26, 0x38, 0x50, 0x49,
                                   0x46, 0xcd, 0x87, 0x21, 0xe8, 0x68, 0xda, 0x34, 0x0d,
                                   0x18, 0x54, 0xaf, 0x8a, 0x8c, 0xa6, 0x95, 0x5b, 0xcf,
                                   0x7b, 0xe7, 0x18, 0x7a, 0xb8};
  static const uint8_t kTagEmpty[16] = {0xc9, 0x51, 0xb3, 0x49, 0xd1, 0xbb, 0x47, 0xac,
                                        0x30, 0x2e, 0xae, 0x21, 0x0b, 0xb5, 0x94, 0xb5};
  static const uint8_t kTagBlock[16] = {0xb7, 0x61, 0xbc, 0xd5, 0x2d, 0x78, 0xd8, 0x11,
                                        0x55, 0x52, 0x22, 0x1e, 0x82, 0x3d, 0xb5, 0xfe};
  static const uint8_t kTagTail[16] = {0xcf, 0x15, 0xb3, 0x68, 0xdc, 0x75, 0xdc, 0xf2,
                                       0xa5, 0xd9, 0xeb, 0xe4, 0xec, 0xe5, 0xb7, 0x75};
  static const uint8_t kTagAad[16] = {0x81, 0x2b, 0x80, 0x25, 0xc6, 0xbf, 0xe1, 0x60,
                                      0x75, 0x5d, 0x56, 0xa2, 0x75, 0xd8, 0x66, 0xbc};
  static const Case kCases[] = {
      {0, 0, kCtEmpty, 0, kTagEmpty},
      {16, 0, kCtBlock, 16, kTagBlock},
      {20, 0, kCtTail, 20, kTagTail},
      {32, 20, kCtAad, 32, kTagAad},
  };

  uint8_t key[32];
  uint8_t nonce[12];
  for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);
  for (int i = 0; i < 12; ++i) nonce[i] = static_cast<uint8_t>(0x10 * i);

  for (const auto& c : kCases) {
    uint8_t pt[32], aad[20], ct[32], tag[16];
    for (int i = 0; i < c.ptLen; ++i) pt[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < c.aadLen; ++i) aad[i] = static_cast<uint8_t>(0xA0 + i);
    if (!Seal(key, nonce, c.aadLen ? aad : nullptr, c.aadLen, c.ptLen ? pt : nullptr, c.ptLen, ct,
              tag)) {
      return false;
    }
    if (c.ctLen && memcmp(ct, c.ct, c.ctLen) != 0) return false;
    if (memcmp(tag, c.tag, 16) != 0) return false;

    uint8_t back[32];
    if (!Open(key, nonce, c.aadLen ? aad : nullptr, c.aadLen, ct, c.ptLen, tag, back)) return false;
    if (c.ptLen && memcmp(back, pt, c.ptLen) != 0) return false;

    // 篡改 tag / 密文 / AAD 都必须被拒绝
    if (c.ptLen) {
      tag[0] ^= 0x01;
      if (Open(key, nonce, c.aadLen ? aad : nullptr, c.aadLen, ct, c.ptLen, tag, back)) return false;
      tag[0] ^= 0x01;
      ct[0] ^= 0x01;
      if (Open(key, nonce, c.aadLen ? aad : nullptr, c.aadLen, ct, c.ptLen, tag, back)) return false;
      ct[0] ^= 0x01;
    }
    if (c.aadLen) {
      aad[0] ^= 0x01;
      if (Open(key, nonce, aad, c.aadLen, ct, c.ptLen, tag, back)) return false;
    }
  }
  return true;
}

}  // namespace aead
}  // namespace rockey