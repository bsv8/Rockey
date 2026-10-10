// RIPEMD-160（HASH160 的后半段）。
//
// 实现说明（重要）：这里**不再自带手写轮函数**。原来那份自实现把右线移位表
// 误填成了 RIPEMD-128 的表，而自检因为只比对"源码里出现过的常量字符串"
// 而没有真正执行算法，于是一直显示通过。结果是设备算出的每一个
// HASH160、每一个 P2PKH 地址都是错的，而且不会有任何报错。
//
// 现在改为调用 ESP-IDF 自带的 mbedTLS RIPEMD-160：
//  - platformio.ini 本来就链接 mbedcrypto（SHA-256/HKDF/PBKDF2 都在用）；
//  - mbedtls/ripemd160.h 在 ESP-IDF 4.4 附带的 mbedtls 2.28 中可用；
//  - 若某个 SDK 配置禁用了它，会在编译期报错，而不是静默算错。
//
// 自检仍然保留，并且是真正执行算法后逐字节比对权威向量。
#include "crypto/ripemd160.h"

#include <string.h>

extern "C" {
#include "mbedtls/ripemd160.h"
}

namespace rockey {
namespace ripemd {

void Hash(const uint8_t* data, size_t len, uint8_t out[kDigestLen]) {
  mbedtls_ripemd160_context ctx;
  mbedtls_ripemd160_init(&ctx);
  mbedtls_ripemd160_starts(&ctx);
  if (len) mbedtls_ripemd160_update(&ctx, data, len);
  mbedtls_ripemd160_finish(&ctx, out);
  mbedtls_ripemd160_free(&ctx);
}

bool SelfTest() {
  static const char* kHex = "0123456789abcdef";
  struct Case {
    const char* in;
    const char* expect;
  };
  // ISO/IEC 10118-3 官方向量
  static const Case kCases[] = {
      {"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
      {"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
      {"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
      {"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
      {"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
      {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
       "b0e20b6e3116640286ed3a87a5713079b21f5189"},
      {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
       "9b752e45573d4b39f4dbd3323cab82bf63326bfb"},
  };
  for (const auto& c : kCases) {
    uint8_t d[20];
    char hex[41];
    Hash(reinterpret_cast<const uint8_t*>(c.in), strlen(c.in), d);
    for (int i = 0; i < 20; ++i) {
      hex[i * 2] = kHex[d[i] >> 4];
      hex[i * 2 + 1] = kHex[d[i] & 0xF];
    }
    hex[40] = '\0';
    if (strcmp(hex, c.expect) != 0) return false;
  }
  // 一百万个 'a' 的官方向量：分块喂入，覆盖多块与填充路径
  {
    static uint8_t buf[1000];
    memset(buf, 'a', sizeof(buf));
    mbedtls_ripemd160_context ctx;
    mbedtls_ripemd160_init(&ctx);
    mbedtls_ripemd160_starts(&ctx);
    for (int i = 0; i < 1000; ++i) mbedtls_ripemd160_update(&ctx, buf, sizeof(buf));
    uint8_t d[20];
    mbedtls_ripemd160_finish(&ctx, d);
    mbedtls_ripemd160_free(&ctx);
    const char* want = "52783243c1697bdbe16d37f97f68f08325dc1528";
    char hex[41];
    for (int i = 0; i < 20; ++i) {
      hex[i * 2] = kHex[d[i] >> 4];
      hex[i * 2 + 1] = kHex[d[i] & 0xF];
    }
    hex[40] = '\0';
    if (strcmp(hex, want) != 0) return false;
  }
  return true;
}

}  // namespace ripemd
}  // namespace rockey