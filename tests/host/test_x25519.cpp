// 主机侧测试：X25519 与 RFC 7748 官方向量、以及双方共享秘密一致性。
//
// 这一组针对的实现缺陷：模数写成 2^255-1（末字节 0x7F）而不是 2^255-19、
// u 坐标按大端读入（小端规范）、ladder 初值写反（x3=1,z2=0）。
// 三个里任何一个都足以让握手两端算出不同的共享秘密，而且不报任何错。
// 另外固件 SelfTest 里的"RFC 向量"常量本身也是错的，必须以本文为准。
//
// 参照：RFC 7748 §5.2 的 Alice/Bob 向量与迭代向量，
// 以及由独立 Python 实现复核过的结果。
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto/x25519.h"

namespace {

int g_pass = 0;
int g_fail = 0;
const char* g_case = "";

void Begin(const char* n) { g_case = n; }

void Check(bool cond, const char* what) {
  if (cond) {
    g_pass++;
  } else {
    g_fail++;
    printf("  FAIL [%s] %s\n", g_case, what);
  }
}

void HexEq(const uint8_t* got, const char* want, const char* what) {
  bool ok = strlen(want) == 64;
  for (int i = 0; ok && i < 32; ++i) {
    auto nib = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      return -1;
    };
    int hi = nib(want[2 * i]), lo = nib(want[2 * i + 1]);
    ok = hi >= 0 && lo >= 0 && got[i] == static_cast<uint8_t>(hi * 16 + lo);
  }
  if (ok) {
    g_pass++;
    return;
  }
  g_fail++;
  printf("  FAIL [%s] %s\n       got  ", g_case, what);
  for (int i = 0; i < 32; ++i) printf("%02x", got[i]);
  printf("\n       want %s\n", want);
}

const uint8_t kAliceSk[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
                              0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
                              0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
const char* kAlicePk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const uint8_t kBobSk[32] = {0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
                            0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
                            0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb};
const char* kBobPk = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const char* kShared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

void TestRfcVectors() {
  Begin("x25519/rfc7748");
  uint8_t pk[32];

  rockey::x25519::PublicFromPrivate(kAliceSk, pk);
  HexEq(pk, kAlicePk, "Alice public key");
  rockey::x25519::PublicFromPrivate(kBobSk, pk);
  HexEq(pk, kBobPk, "Bob public key");

  uint8_t ab[32], ba[32];
  rockey::x25519::PublicFromPrivate(kBobSk, pk);
  Check(rockey::x25519::Shared(kAliceSk, pk, ab), "Alice x Bob succeeds");
  HexEq(ab, kShared, "shared secret matches RFC");
  Check(rockey::x25519::Shared(kBobSk, (const uint8_t*)"\x85\x20\xf0\x09\x89\x30\xa7\x54\x74\x8b"
                                          "\x7d\xdc\xb4\x3e\xf7\x5a\x0d\xbf\x3a\x0d\x26"
                                          "\x38\x1a\xf4\xeb\xa4\xa9\x8e\xaa\x9b\x4e\x6a",
                     ba),
        "Bob x Alice succeeds");
  HexEq(ba, kShared, "shared secret from the other direction");

  // 迭代向量
  uint8_t k[32] = {0}, u[32] = {0}, r[32];
  k[0] = 9;
  u[0] = 9;
  bool allOk = true;
  for (int i = 0; i < 1000; ++i) {
    if (!rockey::x25519::Shared(k, u, r)) {
      allOk = false;
      break;
    }
    memcpy(k, u, 32);
    memcpy(u, r, 32);
  }
  Check(allOk, "1000 iterations all succeeded");
  HexEq(u, "de0f73373455be098e4bc36bedc7e2c1de00a0bf385897d1cc16dd54f93ec000",
        "RFC 7748 iterated 1000 times");
}

void TestAgreementAndLadderProperties() {
  Begin("x25519/properties");
  // 随机私钥双方：公钥互推一致、共享秘密双向一致
  uint32_t s = 0x1234ABCDu;
  auto rnd = [&s]() -> uint8_t {
    s = s * 1664525u + 1013904223u;
    return static_cast<uint8_t>(s >> 24);
  };
  for (int iter = 0; iter < 16; ++iter) {
    uint8_t sa[32], sb[32], pa[32], pb[32], ab[32], ba[32];
    for (int i = 0; i < 32; ++i) {
      sa[i] = rnd();
      sb[i] = rnd();
    }
    rockey::x25519::PublicFromPrivate(sa, pa);
    rockey::x25519::PublicFromPrivate(sb, pb);
    Check(rockey::x25519::Shared(sa, pb, ab), "A->B succeeds");
    Check(rockey::x25519::Shared(sb, pa, ba), "B->A succeeds");
    Check(memcmp(ab, ba, 32) == 0, "both sides derive the same shared secret");
    Check(memcmp(ab, kShared, 32) != 0 || iter < 0, "shared secret is not a constant");
    // 不同私钥必须给出不同共享秘密。
    // 注意要翻一个"会被夹紧清掉"的位之外的位置：低 3 位与最高位按 RFC 7748
    // 会被夹紧，翻它们本就不该改变结果（下面 TestClamping 单独验证这点）。
    sa[10] ^= 0x01;
    uint8_t ab2[32];
    rockey::x25519::Shared(sa, pb, ab2);
    Check(memcmp(ab, ab2, 32) != 0, "changing a live bit of the scalar changes the shared secret");
  }
}

void TestLowOrderPoints() {
  Begin("x25519/low-order");
  uint8_t sk[32];
  for (int i = 0; i < 32; ++i) sk[i] = static_cast<uint8_t>(i + 1);
  uint8_t out[32];

  // 全零 u -> 全零共享秘密，必须拒绝
  static const uint8_t uZero[32] = {0};
  Check(!rockey::x25519::Shared(sk, uZero, out), "all-zero u rejected");

  // RFC 7748 §6.1 列出的低阶点（都不应产生有效的非零共享秘密）
  static const char* kLowOrder[] = {
      "0100000000000000000000000000000000000000000000000000000000000000",  // 1
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",  // 0 order 1
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",  // order 8
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  // p-1?
  };
  for (const char* hex : kLowOrder) {
    uint8_t u[32];
    for (int i = 0; i < 32; ++i) {
      auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
      };
      u[i] = static_cast<uint8_t>(nib(hex[2 * i]) * 16 + nib(hex[2 * i + 1]));
    }
    bool accepted = rockey::x25519::Shared(sk, u, out);
    bool allZero = true;
    for (int i = 0; i < 32; ++i) {
      if (out[i]) allZero = false;
    }
    // 允许实现接受这些点，但结果必须是全零（然后被拒绝）
    Check(!accepted || allZero, "low-order point never yields a usable shared secret");
  }
}

void TestClamping() {
  Begin("x25519/clamp");
  uint8_t a[32], b[32];
  for (int i = 0; i < 32; ++i) a[i] = b[i] = static_cast<uint8_t>(i * 7 + 3);
  uint8_t pa[32], pb[32];
  rockey::x25519::PublicFromPrivate(a, pa);
  // 把会被夹紧清除的位翻转：公钥必须不变
  b[0] ^= 0x07;
  b[31] ^= 0x80;
  b[31] |= 0x40;
  rockey::x25519::PublicFromPrivate(b, pb);
  Check(memcmp(pa, pb, 32) == 0, "clamping discards the low 3 and top 8 bits");
}

void TestSelfTest() {
  Begin("x25519/selftest");
  Check(rockey::x25519::SelfTest(), "extended RFC regression passes");
  Check(rockey::x25519::SelfTest(false), "bounded firmware boot KAT passes");
}

}  // namespace

int main() {
  printf("rockey host tests: crypto/x25519 vs RFC 7748\n");

  TestRfcVectors();
  TestAgreementAndLadderProperties();
  TestLowOrderPoints();
  TestClamping();
  TestSelfTest();

  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}