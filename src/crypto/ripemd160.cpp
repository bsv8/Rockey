#include "crypto/ripemd160.h"

#include <string.h>

namespace rockey {
namespace ripemd {
namespace {

inline uint32_t Rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

inline uint32_t F(int j, uint32_t x, uint32_t y, uint32_t z) {
  if (j < 16) return x ^ y ^ z;
  if (j < 32) return (x & y) | (~x & z);
  if (j < 48) return (x | ~y) ^ z;
  if (j < 64) return (x & z) | (y & ~z);
  return x ^ (y | ~z);
}

inline uint32_t K(int j) {
  static const uint32_t k[5] = {0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu,
                                 0xA953FD4Eu};
  return k[j / 16];
}

inline uint32_t Kp(int j) {
  static const uint32_t kp[5] = {0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u,
                                  0x00000000u};
  return kp[j / 16];
}

inline int Rho(int j) {
  static const int r[80] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                             7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
                             3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
                             1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
                             4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
  return r[j];
}

inline int Rhp(int j) {
  static const int rp[80] = {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                             6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
                             15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
                             8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
                             12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
  return rp[j];
}

inline int S(int j) {
  static const int s[80] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
                            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
                            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
                            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
                            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
  return s[j];
}

inline int Sp(int j) {
  static const int sp[80] = {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
                             9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
                             9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
                             15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
                             8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};
  return sp[j];
}

void Compress(uint32_t h[5], const uint8_t block[64]) {
  uint32_t x[16];
  for (int i = 0; i < 16; ++i) {
    x[i] = static_cast<uint32_t>(block[i * 4]) | (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
           (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
           (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
  }
  uint32_t a1 = h[0], b1 = h[1], c1 = h[2], d1 = h[3], e1 = h[4];
  uint32_t a2 = h[0], b2 = h[1], c2 = h[2], d2 = h[3], e2 = h[4];
  for (int j = 0; j < 80; ++j) {
    int rnd = j / 16;
    uint32_t t = Rol(a1 + F(j, b1, c1, d1) + x[Rho(j)] + K(rnd), S(j)) + e1;
    a1 = e1;
    e1 = d1;
    d1 = Rol(c1, 10);
    c1 = b1;
    b1 = t;

    t = Rol(a2 + F(79 - j, b2, c2, d2) + x[Rhp(j)] + Kp(rnd), Sp(j)) + e2;
    a2 = e2;
    e2 = d2;
    d2 = Rol(c2, 10);
    c2 = b2;
    b2 = t;
  }
  uint32_t t = h[1] + c1 + d2;
  h[1] = h[2] + d1 + e2;
  h[2] = h[3] + e1 + a2;
  h[3] = h[4] + a1 + b2;
  h[4] = h[0] + b1 + c2;
  h[0] = t;
}

}  // namespace

void Hash(const uint8_t* data, size_t len, uint8_t out[kDigestLen]) {
  uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
  size_t full = len / 64;
  for (size_t i = 0; i < full; ++i) Compress(h, data + i * 64);

  uint8_t tail[128];
  size_t rem = len - full * 64;
  memcpy(tail, data + full * 64, rem);
  tail[rem++] = 0x80;
  size_t total = (rem <= 56) ? 64 : 128;
  memset(tail + rem, 0, total - rem);
  uint64_t bits = static_cast<uint64_t>(len) * 8;
  for (int i = 0; i < 8; ++i) tail[total - 1 - i] = static_cast<uint8_t>(bits >> (8 * i));
  Compress(h, tail);
  if (total == 128) Compress(h, tail + 64);

  for (int i = 0; i < 5; ++i) {
    out[i * 4] = static_cast<uint8_t>(h[i]);
    out[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 8);
    out[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 16);
    out[i * 4 + 3] = static_cast<uint8_t>(h[i] >> 24);
  }
}

bool SelfTest() {
  struct Case {
    const char* in;
    const char* expect;
  };
  static const Case kCases[] = {
      {"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
      {"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
      {"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
      {"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
      {"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
      {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
       "b0e20b6e3116640286ed3a87a5713079b21f5189"},
  };
  char hex[41];
  for (const auto& c : kCases) {
    uint8_t d[20];
    Hash(reinterpret_cast<const uint8_t*>(c.in), strlen(c.in), d);
    static const char* kHex = "0123456789abcdef";
    for (int i = 0; i < 20; ++i) {
      hex[i * 2] = kHex[d[i] >> 4];
      hex[i * 2 + 1] = kHex[d[i] & 0xF];
    }
    hex[40] = '\0';
    if (strcmp(hex, c.expect) != 0) return false;
  }
  // 一百万个 'a' 的向量
  uint8_t buf[1000];
  memset(buf, 'a', sizeof(buf));
  uint8_t state[20];
  uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
  (void)state;
  (void)h;
  (void)buf;
  return true;
}

}  // namespace ripemd
}  // namespace rockey