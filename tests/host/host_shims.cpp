// 主机测试的最小替身：让 src/ 里依赖 Arduino / LittleFS / ESP-IDF 的模块
// 能在主机上编译运行。真实实现分别在 store/keystore.cpp、板级驱动与
// ESP-IDF 里。
//
// 提供：
//   - millis()：确定性递增，供 policy 的 createdMs 使用
//   - keystore::KeyStore::PrivateKey/PublicKey：可被测试替换的业务私钥
//   - log::Log::Write：丢弃（rand.cpp 会打日志）
//   - secp::SignDer / PubkeyFromPriv：占位（主机上 mbedtls 3.6 的
//     mbedtls_ecp_mul 与设备目标 2.28 行为不同，签名路径不在主机覆盖范围内）
#include <stdint.h>
#include <string.h>

#include "core/log.h"
#include "store/keystore.h"

unsigned long millis() {
  static unsigned long t = 1000;
  t += 1;
  return t;
}

namespace rockey {

namespace keystore {
// 本地秘密 v3 与密钥封装的派生输入都是业务私钥，所以这里必须给一把确定的
// 测试私钥（而不是 nullptr），否则派生结果无从比对。
static uint8_t g_testPriv[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
    0xe1};
static uint8_t g_pub[33] = {0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55,
                            0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D,
                            0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};

const uint8_t* KeyStore::PrivateKey() { return g_testPriv; }

uint8_t* KeyStore::PublicKey() { return g_pub; }

}  // namespace keystore

namespace hosttest {
// 让测试换一把业务私钥：本地秘密 v3 / 密钥封装的派生都依赖它，
// 必须能证明"换一把钥匙就换一份密文"。
void SetTestPrivImpl(const uint8_t* priv32) { memcpy(keystore::g_testPriv, priv32, 32); }

}  // namespace hosttest

void Log::Write(LogLevel, const char*, const char*, ...) {}
uint32_t Log::dropped_ = 0;

namespace secp {
// 主机上不覆盖签名路径：真实实现由固件自检与 tools/test-vectors/main.py 负责。
bool SignDer(const uint8_t* priv, const uint8_t digest[32], uint8_t* out, size_t* outLen) {
  (void)priv;
  (void)digest;
  (void)out;
  (void)outLen;
  return false;
}

bool PubkeyFromPriv(const uint8_t* priv, uint8_t* out33) {
  (void)priv;
  (void)out33;
  return false;
}
}  // namespace secp

}  // namespace rockey