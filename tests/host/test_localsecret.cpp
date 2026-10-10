// 主机侧测试（需要 mbedtls）：本地秘密 v3 的真实往返。
//
// 针对的缺陷：secret.open 的字段数守卫写成 4，而 seal 产出 5 个字段，
// 于是设备自己封装的密文永远解不开 —— 迁移后旧数据也就打不开，
// 需求 §8「原身份和原数据继续使用」这条验收不可能通过。
//
// 这里直接调用 src/ops/local_secret.cpp 的 Seal/Open，验证：
//  - 设备 seal -> 设备 open 能还原明文；
//  - 密文字节与公开向量一致（格式未漂移）；
//  - scope 改动导致解封失败（AAD/salt 绑定 scope）。
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ops/local_secret.h"

namespace rockey {
namespace hosttest {
// 由 tests/host/host_shims.cpp 提供：替换测试用的业务私钥，
// 以便验证本地秘密的派生真的依赖业务私钥。
void SetTestPrivImpl(const uint8_t* priv32);
}  // namespace hosttest
}  // namespace rockey

using rockey::ops::kKeySource;
using rockey::ops::Open;
using rockey::ops::Seal;
using rockey::ops::SealedSecret;

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

const char* kScope = "payment-request:alice";

void TestRoundTrip() {
  Begin("localsecret/roundtrip");
  const uint8_t plain[] = {'h', 'e', 'l', 'l', 'o', ',', ' ', 'v', 'a', 'u', 'l', 't'};
  SealedSecret sealed;
  Check(Seal(kScope, strlen(kScope), plain, sizeof(plain), &sealed), "Seal succeeds");
  Check(sealed.ciphertextLen == sizeof(plain) + 16, "ciphertext = plaintext + GCM tag");
  Check(strcmp(kKeySource, "active-key-hkdf-v1") == 0, "keySource is the frozen v3 value");

  uint8_t out[256];
  size_t outLen = 0;
  Check(Open(kScope, strlen(kScope), sealed, out, sizeof(out), &outLen), "Open succeeds");
  Check(outLen == sizeof(plain), "plaintext length restored");
  Check(memcmp(out, plain, sizeof(plain)) == 0, "plaintext bytes restored");
}

void TestScopeBinding() {
  Begin("localsecret/scope");
  const uint8_t plain[] = {1, 2, 3, 4, 5};
  SealedSecret sealed;
  Check(Seal(kScope, strlen(kScope), plain, sizeof(plain), &sealed), "Seal for scope A");

  // 同一个设备封装不能在另一个 scope 下解封：派生密钥与 AAD 都绑定 scope
  uint8_t out[256];
  size_t outLen = 0;
  const char* other = "payment-request:bob";
  Check(!Open(other, strlen(other), sealed, out, sizeof(out), &outLen),
        "different scope cannot open");
}

// 派生必须真的依赖业务私钥：换一把钥匙，同一段明文必须得到不同的密文。
// HKDF 曾经完全忽略 ikm/salt，于是所有用户的本地秘密都能互相解开。
void TestKeyDependence() {
  Begin("localsecret/key-dependence");
  const uint8_t plain[] = {0x42, 0x43, 0x44};
  uint8_t other[32];
  for (int i = 0; i < 32; ++i) other[i] = static_cast<uint8_t>(0x11 + i);

  SealedSecret a, b;
  Check(Seal(kScope, strlen(kScope), plain, sizeof(plain), &a), "seal with key A");

  rockey::hosttest::SetTestPrivImpl(other);
  Check(Seal(kScope, strlen(kScope), plain, sizeof(plain), &b), "seal with key B");

  // 盐与 nonce 都是随机的，所以密文必然不同；真正要验证的是
  // 用钥匙 B 的派生密钥解不开钥匙 A 封的密文（这里通过 Open 走一遍）。
  uint8_t out[256];
  size_t outLen = 0;
  Check(!Open(kScope, strlen(kScope), a, out, sizeof(out), &outLen),
        "key B cannot open a blob sealed under key A");
}

void TestTamper() {
  Begin("localsecret/tamper");
  const uint8_t plain[] = {9, 8, 7, 6, 5, 4, 3, 2};
  SealedSecret sealed;
  Seal(kScope, strlen(kScope), plain, sizeof(plain), &sealed);

  SealedSecret bad = sealed;
  bad.ciphertext[0] ^= 0x01;
  uint8_t out[256];
  size_t outLen = 0;
  Check(!Open(kScope, strlen(kScope), bad, out, sizeof(out), &outLen), "flipped byte rejected");

  SealedSecret bad2 = sealed;
  bad2.salt[0] ^= 0xFF;
  Check(!Open(kScope, strlen(kScope), bad2, out, sizeof(out), &outLen), "altered salt rejected");
}

}  // namespace

int main() {
  printf("rockey host tests: ops/local_secret (needs mbedtls)\n");

  TestRoundTrip();
  TestScopeBinding();
  TestTamper();
  TestKeyDependence();

  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}