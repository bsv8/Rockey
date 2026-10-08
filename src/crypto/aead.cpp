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
  uint8_t s[16];
  Ghash(h, aad, aadLen, out, len, s);
  uint8_t ej0[16];
  aes.EncryptBlock(j0, ej0);
  for (int k = 0; k < 16; ++k) tag[k] = static_cast<uint8_t>(s[k] ^ ej0[k]);
  secure::Wipe(h, sizeof(h));
  secure::Wipe(s, sizeof(s));
  secure::Wipe(ej0, sizeof(ej0));
  (void)encrypting;
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
  // NIST GCM test case 1：128 位密钥、空明文
  {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t tag[16];
    static const uint8_t kExpect[16] = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
                                         0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
    uint8_t dummy[1];
    if (!Seal(key, nonce, nullptr, 0, nullptr, 0, dummy, tag)) return false;
    if (memcmp(tag, kExpect, 16) != 0) return false;
  }
  // Test case 2：128 位密钥、单块明文
  {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t pt[16] = {0};
    uint8_t ct[16];
    uint8_t tag[16];
    static const uint8_t kExpectCt[16] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                           0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    static const uint8_t kExpectTag[16] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                           0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    if (!Seal(key, nonce, nullptr, 0, pt, 16, ct, tag)) return false;
    if (memcmp(ct, kExpectCt, 16) != 0 || memcmp(tag, kExpectTag, 16) != 0) return false;
    uint8_t back[16];
    if (!Open(key, nonce, nullptr, 0, ct, 16, tag, back)) return false;
    if (memcmp(back, pt, 16) != 0) return false;
    // 篡改 tag 必须失败
    tag[0] ^= 1;
    if (Open(key, nonce, nullptr, 0, ct, 16, tag, back)) return false;
  }
  // Test case 4：256 位密钥、单块明文（我们实际使用的密钥长度）
  {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t pt[16] = {0};
    uint8_t ct[16];
    uint8_t tag[16];
    static const uint8_t kExpectCt[16] = {0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
                                           0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18};
    static const uint8_t kExpectTag[16] = {0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
                                           0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19};
    if (!Seal(key, nonce, nullptr, 0, pt, 16, ct, tag)) return false;
    if (memcmp(ct, kExpectCt, 16) != 0 || memcmp(tag, kExpectTag, 16) != 0) return false;
  }
  // Test case 16：256 位密钥 + AAD + 多块明文
  {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[20];
    memset(key, 0xFE, sizeof(key));
    memset(nonce, 0xCA, sizeof(nonce));
    memset(aad, 0xFA, sizeof(aad));
    uint8_t pt[60];
    memset(pt, 0xAB, sizeof(pt));
    uint8_t ct[60];
    uint8_t tag[16];
    if (!Seal(key, nonce, aad, sizeof(aad), pt, sizeof(pt), ct, tag)) return false;
    uint8_t back[60];
    if (!Open(key, nonce, aad, sizeof(aad), ct, sizeof(ct), tag, back)) return false;
    if (memcmp(back, pt, sizeof(pt)) != 0) return false;
    // 篡改 AAD 必须失败
    aad[0] ^= 0x01;
    if (Open(key, nonce, aad, sizeof(aad), ct, sizeof(ct), tag, back)) return false;
  }
  return true;
}

}  // namespace aead
}  // namespace rockey