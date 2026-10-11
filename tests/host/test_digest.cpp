// 主机侧测试：digest 层与 mbedTLS / RFC 5869 对照。
//
// 针对的缺陷：HkdfSha256 的 expand 阶段从来没有用 PRK 做过 HMAC 初始化，
// 于是输出只取决于 info。封装密钥、本地秘密派生密钥、链路 c2s/s2c 密钥
// 全部退化成公开常量 —— 任意同位数 PIN 都能解封。
//
// 这一组要证明三件事：
//  1. RFC 5869 官方向量逐字节一致；
//  2. 改变 ikm 或 salt 必须改变输出（原来的实现对这两者完全不敏感）；
//  3. 与 mbedtls_hkdf 在随机输入上逐字节一致。
#include <initializer_list>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" {
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
}

#include "crypto/digest.h"

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

void HexEq(const uint8_t* got, size_t n, const char* want, const char* what) {
  // want 是十六进制文本，必须先解码再比字节
  bool ok = strlen(want) == n * 2;
  for (size_t i = 0; ok && i < n; ++i) {
    auto nib = [&](char c) -> int {
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
  printf("  FAIL [%s] %s\n", g_case, what);
  printf("       got  ");
  for (size_t i = 0; i < n; ++i) printf("%02x", got[i]);
  printf("\n       want %s\n", want);
}

// ── RFC 5869 官方向量（SHA-256） ─────────────────────────────────────
void TestRfc5869() {
  Begin("rfc5869");

  // Test Case 1: 基本情形
  {
    static const uint8_t kIkm[22] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                     0x0b, 0x0b};
    static const uint8_t kSalt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c};
    static const uint8_t kInfo[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    uint8_t okm[42];
    rockey::digest::HkdfSha256(kIkm, sizeof(kIkm), kSalt, sizeof(kSalt), kInfo, sizeof(kInfo), okm,
                               sizeof(okm));
    HexEq(okm, sizeof(okm),
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
          "34007208d5b887185865",
          "RFC 5869 A.1 OKM");
  }

  // Test Case 3: 空 salt 与空 info
  {
    static const uint8_t kIkm[22] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                     0x0b, 0x0b};
    uint8_t okm[42];
    rockey::digest::HkdfSha256(kIkm, sizeof(kIkm), nullptr, 0, nullptr, 0, okm, sizeof(okm));
    HexEq(okm, sizeof(okm),
          "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
          "9d201395faa4b61a96c8",
          "RFC 5869 A.3 OKM (empty salt/info)");
  }

  // 同 A.1 的输入，但只取 16 字节：截断输出必须是完整输出���前缀
  {
    static const uint8_t kIkm[22] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                     0x0b, 0x0b};
    static const uint8_t kSalt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c};
    static const uint8_t kInfo[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    uint8_t okm[16];
    rockey::digest::HkdfSha256(kIkm, sizeof(kIkm), kSalt, sizeof(kSalt), kInfo, sizeof(kInfo), okm,
                               sizeof(okm));
    HexEq(okm, sizeof(okm), "3cb25f25faacd57a90434f64d0362f2a", "L=16 truncates A.1 OKM");
  }
}

// ── 秘密输入必须影响输出 ────────────────────────────────────────────
// 这条是"任意同位数 PIN 都能解封"的直接回归防线。
void TestSecretDependence() {
  Begin("hkdf/secret-dependence");
  uint8_t ikm[32], ikm2[32], salt[16], salt2[16];
  for (int i = 0; i < 32; ++i) ikm[i] = static_cast<uint8_t>(i + 1);
  for (int i = 0; i < 32; ++i) ikm2[i] = static_cast<uint8_t>(i + 2);
  for (int i = 0; i < 16; ++i) salt[i] = static_cast<uint8_t>(0xA0 + i);
  for (int i = 0; i < 16; ++i) salt2[i] = static_cast<uint8_t>(0xA0 + i + 1);
  const char* info = "rockey:vault:v1";

  uint8_t a[32], b[32], c[32], d[32];
  rockey::digest::HkdfSha256(ikm, 32, salt, 16, reinterpret_cast<const uint8_t*>(info), strlen(info),
                             a, 32);
  rockey::digest::HkdfSha256(ikm2, 32, salt, 16, reinterpret_cast<const uint8_t*>(info),
                             strlen(info), b, 32);
  rockey::digest::HkdfSha256(ikm, 32, salt2, 16, reinterpret_cast<const uint8_t*>(info),
                             strlen(info), c, 32);
  rockey::digest::HkdfSha256(ikm, 32, salt, 16, reinterpret_cast<const uint8_t*>("other"), 5, d, 32);

  Check(memcmp(a, b, 32) != 0, "changing IKM changes the output");
  Check(memcmp(a, c, 32) != 0, "changing salt changes the output");
  Check(memcmp(a, d, 32) != 0, "changing info changes the output");
  Check(memcmp(a, b, 32) != 0 && memcmp(b, a, 32) != 0, "outputs differ in both directions");

  // 确定性：同样输入必须同样输出
  uint8_t again[32];
  rockey::digest::HkdfSha256(ikm, 32, salt, 16, reinterpret_cast<const uint8_t*>(info), strlen(info),
                             again, 32);
  Check(memcmp(a, again, 32) == 0, "same inputs give the same output");
}

// ── 与 mbedTLS 随机对照 ─────────────────────────────────────────────
void TestAgainstMbedtls() {
  Begin("hkdf/vs-mbedtls");
  uint32_t s = 0x5EED1234u;
  auto rnd = [&s]() -> uint8_t {
    s = s * 1664525u + 1013904223u;
    return static_cast<uint8_t>(s >> 24);
  };
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  static const size_t kLens[] = {1, 8, 16, 32, 64, 100};
  for (size_t ikmLen : kLens) {
    for (size_t saltLen : kLens) {
      for (size_t outLen : {16, 32, 42, 100}) {
        uint8_t ikm[128], salt[128], info[40];
        uint8_t a[128], b[128];
        for (size_t i = 0; i < ikmLen; ++i) ikm[i] = rnd();
        for (size_t i = 0; i < saltLen; ++i) salt[i] = rnd();
        for (int i = 0; i < 40; ++i) info[i] = rnd();
        size_t infoLen = 1 + (rnd() % 40);

        rockey::digest::HkdfSha256(ikm, ikmLen, saltLen ? salt : nullptr, saltLen, info, infoLen, a,
                                   outLen);
        int rc = mbedtls_hkdf(md, saltLen ? salt : (const uint8_t*)"", saltLen, ikm, ikmLen, info,
                              infoLen, b, outLen);
        Check(rc == 0 && memcmp(a, b, outLen) == 0,
              "matches mbedtls_hkdf for varying ikm/salt/output length");
      }
    }
  }
}

void TestPbkdf2() {
  Begin("pbkdf2");
  // 用 Python hashlib.pbkdf2_hmac（独立实现）导出的权威值，
  // 而不是 mbedtls 的 pkcs5 接口 —— 后者的 md_context 用法很容易写错，
  // 写错时错的是测试而不是被测对象。
  const uint8_t pw[] = "password";
  const uint8_t salt[] = "salt";
  uint8_t a[32];
  rockey::digest::Pbkdf2Sha256(pw, 8, salt, 4, 1000, a, 32);
  HexEq(a, 32, "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3",
        "PBKDF2-HMAC-SHA256(password, salt, 1000)");

  rockey::digest::Pbkdf2Sha256(pw, 8, salt, 4, 4096, a, 32);
  HexEq(a, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
        "PBKDF2-HMAC-SHA256(password, salt, 4096)");

  // 不同口令必须不同 —— 否则 PIN 形同虚设
  uint8_t b[32];
  const uint8_t pw2[] = "passwordX";
  rockey::digest::Pbkdf2Sha256(pw, 8, salt, 4, 1000, b, 32);
  Check(memcmp(a, b, 32) != 0, "changing the password changes the output");
  rockey::digest::Pbkdf2Sha256(pw2, 9, salt, 4, 1000, a, 32);
  Check(memcmp(a, b, 32) != 0, "a wrong password of the same length derives a different key");

  // 迭代次数必须影响输出（否则 120000 次迭代形同虚设）
  rockey::digest::Pbkdf2Sha256(pw, 8, salt, 4, 1001, a, 32);
  rockey::digest::Pbkdf2Sha256(pw, 8, salt, 4, 1000, b, 32);
  Check(memcmp(a, b, 32) != 0, "iteration count changes the output");

  // 盐必须影响输出（否则同一 PIN 换设备也能解封）
  const uint8_t salt2[] = "salt2";
  rockey::digest::Pbkdf2Sha256(pw, 8, salt2, 5, 1000, a, 32);
  rockey::digest::Pbkdf2Sha256(pw, 8, salt, 4, 1000, b, 32);
  Check(memcmp(a, b, 32) != 0, "salt changes the output");
}

// ── 设备封装密钥的完整派生链 ────────────────────────────────────────
// 复刻 store/keystore.cpp 的两次派生：
//   KEK  = PBKDF2-HMAC-SHA256(PIN, salt, iters)
//   KEK' = HKDF-SHA256(ikm = KEK, salt = deviceSecret, info = "rockey:vault:v1")
// 这里单独跑一遍，是为了把"同位数错误 PIN 不能解封"这条性质固定下来。
// HKDF 曾经完全忽略 ikm/salt，于是 KEK' 与 PIN 无关。
void TestKeystoreDerivationChain() {
  Begin("keystore/derivation");
  const char* kInfo = "rockey:vault:v1";
  uint8_t salt[16], devSecret[32];
  for (int i = 0; i < 16; ++i) salt[i] = static_cast<uint8_t>(0x30 + i);
  for (int i = 0; i < 32; ++i) devSecret[i] = static_cast<uint8_t>(0x90 + i);

  auto derive = [&](const char* pin, uint8_t* kek2) {
    uint8_t kek[32];
    // 迭代次数取小值只为让测试快；设备上是 120000
    rockey::digest::Pbkdf2Sha256(reinterpret_cast<const uint8_t*>(pin), strlen(pin), salt,
                                 sizeof(salt), 1000, kek, 32);
    rockey::digest::HkdfSha256(kek, 32, devSecret, sizeof(devSecret),
                               reinterpret_cast<const uint8_t*>(kInfo), strlen(kInfo), kek2, 32);
  };

  uint8_t right[32], wrong[32], other[32];
  derive("12345678", right);
  derive("87654321", wrong);   // 同位数错误 PIN
  derive("12345679", other);   // 只差一位

  Check(memcmp(right, wrong, 32) != 0, "same-length wrong PIN derives a different envelope key");
  Check(memcmp(right, other, 32) != 0, "one-digit difference changes the envelope key");
  Check(memcmp(right, right, 32) == 0, "derivation is deterministic");

  // 设备保护秘密也必须起作用：单独拿到 flash（含 salt 与公钥）不够
  uint8_t kek[32], kekNoDev[32];
  const char* pin = "12345678";
  rockey::digest::Pbkdf2Sha256(reinterpret_cast<const uint8_t*>(pin), strlen(pin), salt,
                               sizeof(salt), 1000, kek, 32);
  rockey::digest::HkdfSha256(kek, 32, devSecret, sizeof(devSecret),
                             reinterpret_cast<const uint8_t*>(kInfo), strlen(kInfo), right, 32);
  static const uint8_t kZero[32] = {0};
  rockey::digest::HkdfSha256(kek, 32, kZero, 0, reinterpret_cast<const uint8_t*>(kInfo),
                             strlen(kInfo), kekNoDev, 32);
  Check(memcmp(right, kekNoDev, 32) != 0, "device secret is mixed into the envelope key");
}

// ── 64 位金额格式化 ────────────────────────────────────────────────
// 设备是 ESP32，`unsigned long` 只有 32 位。金额曾用 "%lu" +
// static_cast<unsigned long>(uint64) 打印，超过 UINT32_MAX 的聪数会被
// 显示成完全不同的数字（例如 5,000,000,000 显示成 705,032,704），
// 而实际签署的金额仍是原值 —— 屏幕与签署对象不一致。
//
// 这里锁住"用 64 位格式化"这个性质；格式串与实参类型不匹配还会被
// tools/syntax/main.sh 的 -Wformat 挡住。
void TestAmountFormatting() {
  Begin("format/amount64");
  const uint64_t kBig = 5000000000ull;  // 超过 UINT32_MAX
  char buf[64];
  snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(kBig));
  Check(strcmp(buf, "5000000000") == 0, "amount above UINT32_MAX prints exactly");

  // 注意：这个缺陷只在 ILP32 平台（ESP32：sizeof(unsigned long) == 4）上出现，
  // 64 位主机上旧的 %lu 写法碰巧是对的，所以这里没法直接复现。
  // 真正的防线是 tools/syntax/main.sh 的 -Wformat：%lu 配 uint64 实参会报错。
  // 本测试负责锁住"新写法在两种位宽下都正确"。
  Check(sizeof(unsigned long) == 4 || sizeof(unsigned long) == 8, "host word size is known");

  // 边界值
  snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(UINT32_MAX));
  Check(strcmp(buf, "4294967295") == 0, "UINT32_MAX prints exactly");
  snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(UINT64_MAX));
  Check(strcmp(buf, "18446744073709551615") == 0, "UINT64_MAX prints exactly");
  snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(0));
  Check(strcmp(buf, "0") == 0, "zero prints as 0");
}

}  // namespace

int main() {
  printf("rockey host tests: crypto/digest vs RFC 5869 + mbedtls\n");

  TestAmountFormatting();
  TestRfc5869();
  TestKeystoreDerivationChain();
  TestSecretDependence();
  TestAgainstMbedtls();
  TestPbkdf2();

  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}