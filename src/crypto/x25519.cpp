#include "crypto/x25519.h"

#include <string.h>

extern "C" {
#include "mbedtls/bignum.h"
}

#include "crypto/digest.h"
#include "crypto/rand.h"
#include "crypto/secure.h"

namespace rockey {
namespace x25519 {
namespace {

// p = 2^255 - 19
const uint8_t kPrime[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0x7F};

mbedtls_mpi* Prime() {
  static mbedtls_mpi p;
  static bool inited = false;
  if (!inited) {
    mbedtls_mpi_init(&p);
    mbedtls_mpi_read_binary(&p, kPrime, 32);
    inited = true;
  }
  return &p;
}

void FromBytes(mbedtls_mpi* x, const uint8_t* b) {
  mbedtls_mpi_init(x);
  mbedtls_mpi_read_binary(x, b, 32);
}

void ToBytes(const mbedtls_mpi* x, uint8_t out[32]) { mbedtls_mpi_write_binary(x, out, 32); }

void Add(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
  mbedtls_mpi_add_mpi(r, a, b);
  mbedtls_mpi_mod_mpi(r, r, Prime());
}

void Sub(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
  mbedtls_mpi_sub_mpi(r, a, b);
  // 结果可能为负：加 p
  if (mbedtls_mpi_cmp_int(r, 0) < 0) mbedtls_mpi_add_mpi(r, r, Prime());
}

void Mul(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
  mbedtls_mpi_mul_mpi(r, a, b);
  mbedtls_mpi_mod_mpi(r, r, Prime());
}

void Sq(mbedtls_mpi* r, const mbedtls_mpi* a) { Mul(r, a, a); }

void Cswap(mbedtls_mpi* a, mbedtls_mpi* b, uint32_t cond) {
  if (!cond) return;
  mbedtls_mpi t;
  mbedtls_mpi_init(&t);
  mbedtls_mpi_copy(&t, a);
  mbedtls_mpi_copy(a, b);
  mbedtls_mpi_copy(b, &t);
  mbedtls_mpi_free(&t);
}

void Ladder(const uint8_t k[32], const uint8_t uIn[32], uint8_t out[32]) {
  mbedtls_mpi p = *Prime();
  mbedtls_mpi x1, x2, z2, x3, z3;
  FromBytes(&x1, uIn);
  mbedtls_mpi_init(&x2);
  mbedtls_mpi_init(&z2);
  mbedtls_mpi_init(&x3);
  mbedtls_mpi_init(&z3);
  {
    uint8_t one[32] = {1};
    FromBytes(&x3, one);
    mbedtls_mpi_lset(&z2, 0);
    mbedtls_mpi_lset(&z3, 1);
  }
  uint32_t swap = 0;
  mbedtls_mpi A, AA, B, BB, E, C, D, DA, CB, t0, t1;
  mbedtls_mpi_init(&A); mbedtls_mpi_init(&AA); mbedtls_mpi_init(&B); mbedtls_mpi_init(&BB);
  mbedtls_mpi_init(&E); mbedtls_mpi_init(&C); mbedtls_mpi_init(&D); mbedtls_mpi_init(&DA);
  mbedtls_mpi_init(&CB); mbedtls_mpi_init(&t0); mbedtls_mpi_init(&t1);

  for (int i = 254; i >= 0; --i) {
    uint32_t bit = (static_cast<uint32_t>(k[i >> 3]) >> (i & 7)) & 1u;
    swap ^= bit;
    Cswap(&x2, &x3, swap);
    Cswap(&z2, &z3, swap);
    swap = bit;

    Add(&A, &x2, &z2);
    Sq(&AA, &A);
    Sub(&B, &x2, &z2);
    Sq(&BB, &B);
    Sub(&E, &AA, &BB);
    Add(&C, &x3, &z3);
    Sub(&D, &x3, &z3);
    Mul(&DA, &D, &A);
    Mul(&CB, &C, &B);

    Add(&t0, &DA, &CB);
    Sq(&x3, &t0);           // x3 = (DA + CB)^2
    Sub(&t1, &DA, &CB);
    Sq(&t0, &t1);
    Mul(&z3, &x1, &t0);     // z3 = x1 * (DA - CB)^2
    Mul(&x2, &AA, &BB);     // x2 = AA * BB

    // z2 = E * (AA + a24 * E),  a24 = 121665
    mbedtls_mpi_mul_int(&t0, &E, 121665);
    Add(&t0, &AA, &t0);
    Mul(&z2, &E, &t0);
  }
  Cswap(&x2, &x3, swap);
  Cswap(&z2, &z3, swap);

  // out = x2 * z2^(p-2)  （费马小定理求逆）
  mbedtls_mpi zinv, e;
  mbedtls_mpi_init(&zinv);
  mbedtls_mpi_init(&e);
  mbedtls_mpi_sub_int(&e, &p, 2);
  if (mbedtls_mpi_inv_mod(&zinv, &z2, &p) == 0) {
    Mul(&x2, &x2, &zinv);
  }
  ToBytes(&x2, out);

  mbedtls_mpi_free(&x1); mbedtls_mpi_free(&x2); mbedtls_mpi_free(&z2);
  mbedtls_mpi_free(&x3); mbedtls_mpi_free(&z3);
  mbedtls_mpi_free(&A); mbedtls_mpi_free(&AA); mbedtls_mpi_free(&B); mbedtls_mpi_free(&BB);
  mbedtls_mpi_free(&E); mbedtls_mpi_free(&C); mbedtls_mpi_free(&D); mbedtls_mpi_free(&DA);
  mbedtls_mpi_free(&CB); mbedtls_mpi_free(&t0); mbedtls_mpi_free(&t1);
  mbedtls_mpi_free(&zinv); mbedtls_mpi_free(&e);
}

}  // namespace

void Clamp(uint8_t k[32]) {
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
}

void PublicFromPrivate(const uint8_t priv[32], uint8_t pub[32]) {
  uint8_t k[32];
  memcpy(k, priv, 32);
  Clamp(k);
  uint8_t base[32] = {9};
  Ladder(k, base, pub);
  secure::Wipe(k, sizeof(k));
}

bool Shared(const uint8_t priv[32], const uint8_t peerPub[32], uint8_t out[32]) {
  uint8_t u[32];
  memcpy(u, peerPub, 32);
  u[31] &= 127;  // 忽略最高位（RFC 7748 要求容忍非规范 u）
  uint8_t allZero[32] = {0};
  uint8_t k[32];
  memcpy(k, priv, 32);
  Clamp(k);
  Ladder(k, u, out);
  secure::Wipe(k, sizeof(k));
  bool ok = memcmp(out, allZero, 32) != 0;  // 全零共享秘密必须拒绝
  secure::Wipe(allZero, sizeof(allZero));
  return ok;
}

bool SelfTest() {
  // RFC 7748 §5.2：单次调用向量
  static const uint8_t k1[32] = {0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15,
                                 0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc,
                                 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4};
  static const uint8_t u1[32] = {0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94,
                                 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec,
                                 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab,
                                 0x1c, 0x4c};
  static const uint8_t o1[32] = {0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94,
                                 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03,
                                 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2,
                                 0x85, 0x52};
  static const uint8_t k2[32] = {0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2,
                                 0x26, 0x91, 0x95, 0x7d, 0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21,
                                 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18,
                                 0xba, 0x0d};
  static const uint8_t u2[32] = {0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7,
                                 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10,
                                 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15,
                                 0xa4, 0x93};
  static const uint8_t o2[32] = {0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad,
                                 0xe4, 0x5c, 0xb4, 0xb8, 0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68,
                                 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac,
                                 0x79, 0x57};

  uint8_t got[32];
  uint8_t pk[32];
  PublicFromPrivate(k1, pk);
  if (memcmp(pk, u1, 32) != 0) return false;
  if (!Shared(k1, u2, got)) return false;
  if (memcmp(got, o1, 32) != 0) return false;
  PublicFromPrivate(k2, pk);
  if (memcmp(pk, u2, 32) != 0) return false;
  if (!Shared(k2, u1, got)) return false;
  if (memcmp(got, o2, 32) != 0) return false;

  // RFC 7748 §5.2 迭代向量：k=09..00, u=09..00，迭代 1000 次
  uint8_t k[32] = {0};
  uint8_t u[32] = {0};
  k[0] = 9;
  u[0] = 9;
  for (int i = 0; i < 1000; ++i) {
    uint8_t r[32];
    if (!Shared(k, u, r)) return false;
    memcpy(k, u, 32);
    memcpy(u, r, 32);
  }
  static const uint8_t kIter1000[32] = {0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
                                        0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
                                        0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
                                        0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51};
  if (memcmp(u, kIter1000, 32) != 0) return false;

  // 全零共享秘密必须被拒绝
  static const uint8_t kZero[32] = {0};
  static const uint8_t uZero[32] = {0};
  if (Shared(kZero, uZero, got)) return false;

  secure::Wipe(got, sizeof(got));
  secure::Wipe(pk, sizeof(pk));
  secure::Wipe(k, sizeof(k));
  secure::Wipe(u, sizeof(u));
  return true;
}

}  // namespace x25519
}  // namespace rockey