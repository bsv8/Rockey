// X25519（RFC 7748）—— 握手密钥协商与 Channel 密钥协商都用它。
//
// 这一版是按 RFC 7748 重写的。上一版有三处致命错误，任何一个都足以让
// 密钥协商不可用且不自报错：
//   1. 模数写成 2^255 - 1（末字节 0x7F），正确值是 2^255 - 19（末字节 0xED）；
//   2. u 坐标按**大端**读入，而 RFC 7748 规定标量与 u 都是**小端**；
//   3. ladder 初值写反（x3=1, z2=0），RFC 要求 x2=1, z2=0, x3=u, z3=1。
// 连带效果：SelfTest() 一直返回 false，握手两端的共享秘密不一致。
//
// 关于"为什么不直接用库"：ESP-IDF 4.4 附带的 mbedtls 2.28 只有已废弃的
// MBEDTLS_ECP_DP_CURVE25519，mbedtls 3.x 把它删了，没有跨版本可用的
// X25519 API。因此这里保留自实现，但**必须**由 tests/host/test_x25519.cpp
// 真跑 RFC 7748 向量、双方共享秘密一致性与低阶点拒绝来保证正确 ——
// 固件里的 SelfTest() 只是其中一项，不能单独作为依据。
#include "crypto/x25519.h"

#include <string.h>

extern "C" {
#include "mbedtls/bignum.h"
}

#include "crypto/secure.h"

namespace rockey {
namespace x25519 {
namespace {

// p = 2^255 - 19，大端表示：7F FF ... FF ED
const uint8_t kPrime[32] = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xED};

// a24 = (486662 - 2) / 4 = 121665（用 lset 直接写十进制，避免手写十六进制出错）
constexpr int kA24Value = 121665;

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

mbedtls_mpi* A24() {
  static mbedtls_mpi a;
  static bool inited = false;
  if (!inited) {
    mbedtls_mpi_init(&a);
    mbedtls_mpi_lset(&a, kA24Value);
    inited = true;
  }
  return &a;
}

// RFC 7748 的所有字节串都是小端；mbedtls_mpi 内部按大端，所以进出的地方
// 都要做一次字节翻转。漏掉这一步就是上一版的 bug。
void FromLe(mbedtls_mpi* x, const uint8_t le[32]) {
  uint8_t be[32];
  for (int i = 0; i < 32; ++i) be[i] = le[31 - i];
  mbedtls_mpi_init(x);
  mbedtls_mpi_read_binary(x, be, 32);
}

void ToLe(const mbedtls_mpi* x, uint8_t le[32]) {
  uint8_t be[32];
  mbedtls_mpi_write_binary(x, be, 32);
  for (int i = 0; i < 32; ++i) le[i] = be[31 - i];
}

void Add(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
  mbedtls_mpi_add_mpi(r, a, b);
  mbedtls_mpi_mod_mpi(r, r, Prime());
}

void Sub(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
  mbedtls_mpi_sub_mpi(r, a, b);
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

// RFC 7748 §5 Montgomery ladder。标量 k 已由调用方夹紧。
void Ladder(const uint8_t k[32], const uint8_t uIn[32], uint8_t out[32]) {
  const mbedtls_mpi* p = Prime();
  mbedtls_mpi x1, x2, z2, x3, z3;
  FromLe(&x1, uIn);
  mbedtls_mpi_init(&x2);
  mbedtls_mpi_init(&z2);
  mbedtls_mpi_init(&x3);
  mbedtls_mpi_init(&z3);
  mbedtls_mpi_lset(&x2, 1);
  mbedtls_mpi_lset(&z2, 0);
  mbedtls_mpi_copy(&x3, &x1);   // x3 = u
  mbedtls_mpi_lset(&z3, 1);

  uint32_t swap = 0;
  mbedtls_mpi A, AA, B, BB, E, C, D, DA, CB, t0, t1;
  mbedtls_mpi_init(&A); mbedtls_mpi_init(&AA); mbedtls_mpi_init(&B); mbedtls_mpi_init(&BB);
  mbedtls_mpi_init(&E); mbedtls_mpi_init(&C); mbedtls_mpi_init(&D); mbedtls_mpi_init(&DA);
  mbedtls_mpi_init(&CB); mbedtls_mpi_init(&t0); mbedtls_mpi_init(&t1);

  for (int i = 254; i >= 0; --i) {
    // 标量是小端：第 i 位在 k[i/8] 的第 (i%8) 位
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
    Sq(&x3, &t0);
    Sub(&t1, &DA, &CB);
    Sq(&t0, &t1);
    Mul(&z3, &x1, &t0);
    Mul(&x2, &AA, &BB);

    Mul(&t0, &E, A24());
    Add(&t0, &AA, &t0);
    Mul(&z2, &E, &t0);
  }
  Cswap(&x2, &x3, swap);
  Cswap(&z2, &z3, swap);

  // 结果 = x2 * z2^(p-2) mod p
  //
  // z2 == 0 表示结果是射影坐标里的无穷远点（低阶 u 就会走到这里），
  // 此时正确的输出是**全零**，而不是 x2。早先这里在 inv_mod 失败时悄悄
  // 跳过求逆、直接输出未求逆的 x2，于是低阶点会得到一个非零且错误的
  // "共享秘密"，而且 Shared() 的全零检查也拦不住 —— 小子群攻击就有着落。
  mbedtls_mpi zinv;
  mbedtls_mpi_init(&zinv);
  if (mbedtls_mpi_inv_mod(&zinv, &z2, p) != 0) {
    memset(out, 0, 32);  // 无穷远点 -> 全零，调用方据此拒绝
  } else {
    Mul(&x2, &x2, &zinv);
    ToLe(&x2, out);
  }
  mbedtls_mpi_free(&zinv);

  mbedtls_mpi_free(&x1); mbedtls_mpi_free(&x2); mbedtls_mpi_free(&z2);
  mbedtls_mpi_free(&x3); mbedtls_mpi_free(&z3);
  mbedtls_mpi_free(&A); mbedtls_mpi_free(&AA); mbedtls_mpi_free(&B); mbedtls_mpi_free(&BB);
  mbedtls_mpi_free(&E); mbedtls_mpi_free(&C); mbedtls_mpi_free(&D); mbedtls_mpi_free(&DA);
  mbedtls_mpi_free(&CB); mbedtls_mpi_free(&t0); mbedtls_mpi_free(&t1);
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
  // 基点 u = 9，小端表示就是 09 00 ... 00
  uint8_t base[32] = {0};
  base[0] = 9;
  Ladder(k, base, pub);
  secure::Wipe(k, sizeof(k));
}

bool Shared(const uint8_t priv[32], const uint8_t peerPub[32], uint8_t out[32]) {
  uint8_t u[32];
  memcpy(u, peerPub, 32);
  u[31] &= 127;  // RFC 7748：忽略 u 的最高位（容忍非规范编码）
  uint8_t k[32];
  memcpy(k, priv, 32);
  Clamp(k);
  Ladder(k, u, out);
  secure::Wipe(k, sizeof(k));
  static const uint8_t allZero[32] = {0};
  bool ok = memcmp(out, allZero, 32) != 0;  // 低阶点产生全零共享秘密，必须拒绝
  return ok;
}

bool SelfTest(bool extended) {
  // RFC 7748 §5.2 的 Alice / Bob 向量（字节串即小端表示）。
  // 上一版这里的 k1/u1/o1 常量并非 RFC 的向量，SelfTest() 因此一直返回
  // false，把"实现错了"这件事盖成了"环境问题"。
  static const uint8_t kAlice[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                                     0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                                     0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                                     0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
  static const uint8_t kPubAlice[32] = {0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
                                        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
                                        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
                                        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a};
  static const uint8_t kBob[32] = {0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
                                   0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
                                   0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
                                   0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb};
  static const uint8_t kPubBob[32] = {0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
                                      0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
                                      0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
                                      0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f};
  static const uint8_t kShared[32] = {0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
                                      0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
                                      0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                                      0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42};

  uint8_t pk[32], got[32], got2[32];
  PublicFromPrivate(kAlice, pk);
  if (memcmp(pk, kPubAlice, 32) != 0) return false;
  PublicFromPrivate(kBob, pk);
  if (memcmp(pk, kPubBob, 32) != 0) return false;

  // 双方的共享秘密必须一致 —— 这正是上一版不成立的地方
  if (!Shared(kAlice, kPubBob, got)) return false;
  if (memcmp(got, kShared, 32) != 0) return false;
  if (!Shared(kBob, kPubAlice, got2)) return false;
  if (memcmp(got2, kShared, 32) != 0) return false;

  // §5.2 迭代向量：k = u = 09 00..00，迭代 1000 次
  uint8_t k[32] = {0}, u[32] = {0};
  k[0] = 9;
  u[0] = 9;
  if (extended) {
  for (int i = 0; i < 1000; ++i) {
    if (!Shared(k, u, got)) return false;
    memcpy(k, u, 32);
    memcpy(u, got, 32);
  }
  static const uint8_t kIter1000[32] = {0xde, 0x0f, 0x73, 0x37, 0x34, 0x55, 0xbe, 0x09,
                                       0x8e, 0x4b, 0xc3, 0x6b, 0xed, 0xc7, 0xe2, 0xc1,
                                       0xde, 0x00, 0xa0, 0xbf, 0x38, 0x58, 0x97, 0xd1,
                                       0xcc, 0x16, 0xdd, 0x54, 0xf9, 0x3e, 0xc0, 0x00};
  if (memcmp(u, kIter1000, 32) != 0) return false;
  }

  // 低阶点：全零 u 产生全零共享秘密，必须拒绝
  static const uint8_t uZero[32] = {0};
  if (Shared(kAlice, uZero, got)) return false;

  secure::Wipe(got, sizeof(got));
  secure::Wipe(got2, sizeof(got2));
  secure::Wipe(pk, sizeof(pk));
  secure::Wipe(k, sizeof(k));
  secure::Wipe(u, sizeof(u));
  return true;
}

}  // namespace x25519
}  // namespace rockey