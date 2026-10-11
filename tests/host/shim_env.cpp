// 主机侧运行环境替身：让 store/keystore.cpp、store/vault_fs.cpp 这些
// 依赖 Arduino / LittleFS / ESP-IDF 的**真实实现**能在主机上跑起来。
//
// 提供：
//   - LittleFS：内存文件系统（路径 -> 字节），rename/remove 语义对齐设备侧用法；
//   - millis()/delay()：确定性时钟；
//   - esp_random()/esp_fill_random()：确定性伪随机（可复现，不用于安全论证）；
//   - secp::PubkeyFromPriv/ValidatePriv/ValidatePubkey：用 mbedTLS 做**真实**
//     曲线运算。主机 mbedTLS 3.6 的 mbedtls_ecp_mul 必须传非空 RNG 才会工作
//     （设备目标 2.28 传 nullptr 即可），因此这里显式给一个确定性 RNG ——
//     这只是让主机能跑同一段调用路径，不改变设备端行为。
//   - Log::Write：丢弃。
//
// 这个文件只被 tests/host/test_keystore.cpp 链接；其它主机测试继续用
// host_shims.cpp，避免 KeyStore 的重复定义。
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <map>
#include <string>
#include <vector>

#include <LittleFS.h>

extern "C" {
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
}

#include "core/log.h"
#include "crypto/secp256k1.h"

// ── 确定性时钟 ──────────────────────────────────────────────────────
// 随机数由 tests/host/shim_esp_aes.cpp 提供（esp_random / esp_fill_random），
// 该文件还被 tools/test-vectors/main.py 的自检驱动单独链接，故不在此重复定义。
static unsigned long g_millis = 1000;
unsigned long millis() { return g_millis; }
unsigned long micros() { return g_millis * 1000; }
void delay(unsigned long ms) { g_millis += ms; }
void delayMicroseconds(unsigned int) {}

// ── 内存 LittleFS ───────────────────────────────────────────────────
namespace {

std::map<std::string, std::vector<uint8_t> > g_files;

}  // namespace

// 内存文件系统实例（头文件里是 extern 声明）
LittleFSClass LittleFS;

File::operator bool() const { return ok_; }
size_t File::write(const uint8_t* buf, size_t len) {
  if (!ok_ || mode_ != 'w') return 0;
  data_.insert(data_.end(), buf, buf + len);
  return len;
}
size_t File::read(uint8_t* buf, size_t len) {
  if (!ok_ || mode_ != 'r') return 0;
  size_t avail = data_.size() - pos_;
  size_t n = avail < len ? avail : len;
  memcpy(buf, data_.data() + pos_, n);
  pos_ += n;
  return n;
}
size_t File::size() const { return ok_ ? data_.size() : 0; }
void File::close() {
  if (ok_ && mode_ == 'w' && !path_.empty()) g_files[path_] = data_;
  ok_ = false;
}
bool File::rename(const char* to) {
  if (!ok_ || !to || path_.empty()) return false;
  std::map<std::string, std::vector<uint8_t> >::iterator it = g_files.find(path_);
  if (it == g_files.end()) return false;
  std::vector<uint8_t> blob = it->second;
  g_files.erase(it);
  g_files[std::string(to)] = blob;
  return true;
}

bool LittleFSClass::begin(bool, const char*, int, const char*) { return true; }
bool LittleFSClass::exists(const char* path) { return path && g_files.count(std::string(path)) > 0; }
bool LittleFSClass::mkdir(const char*) { return true; }
bool LittleFSClass::remove(const char* path) {
  if (!path) return false;
  return g_files.erase(std::string(path)) > 0;
}
bool LittleFSClass::rename(const char* from, const char* to) {
  if (!from || !to) return false;
  std::map<std::string, std::vector<uint8_t> >::iterator it = g_files.find(std::string(from));
  if (it == g_files.end()) return false;
  std::vector<uint8_t> blob = it->second;
  g_files.erase(it);
  g_files[std::string(to)] = blob;
  return true;
}
File LittleFSClass::open(const char* path, const char* mode) {
  File f;
  if (!path || !mode) return f;
  std::string p(path);
  if (mode[0] == 'r') {
    std::map<std::string, std::vector<uint8_t> >::iterator it = g_files.find(p);
    if (it == g_files.end()) return f;
    f.ok_ = true;
    f.mode_ = 'r';
    f.path_ = p;
    f.data_ = it->second;
  } else if (mode[0] == 'w') {
    f.ok_ = true;
    f.mode_ = 'w';
    f.path_ = p;
  }
  return f;
}

// ── 日志 ────────────────────────────────────────────────────────────
namespace rockey {
#if !defined(ROCKEY_HOST_UI_TEST)
void Log::Init() {}
void Log::Write(LogLevel, const char*, const char*, ...) {}
bool Log::Enabled(LogLevel) { return false; }
uint32_t Log::dropped_ = 0;
#endif
}  // namespace rockey

// ── secp256k1：真实曲线运算（mbedTLS 3.6 需要非空 RNG） ─────────────
namespace {

int DeterministicRng(void*, unsigned char* p, size_t n) {
  for (size_t i = 0; i < n; ++i) p[i] = static_cast<unsigned char>(0xA5 ^ (i * 31 + 7));
  return 0;
}

mbedtls_ecp_group* Group() {
  static mbedtls_ecp_group grp;
  static bool inited = false;
  if (!inited) {
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
    inited = true;
  }
  return &grp;
}

}  // namespace

namespace rockey {
namespace secp {

bool PubkeyFromPriv(const uint8_t priv[32], uint8_t pubCompressed[33]) {
  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi d;
  mbedtls_mpi_init(&d);
  mbedtls_mpi_read_binary(&d, priv, 32);
  int rc = mbedtls_ecp_mul(Group(), &Q, &d, &Group()->G, DeterministicRng, nullptr);
  bool ok = false;
  if (rc == 0) {
    size_t olen = 0;
    rc = mbedtls_ecp_point_write_binary(Group(), &Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, pubCompressed,
                                        33);
    ok = (rc == 0 && olen == 33);
  }
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  return ok;
}

bool ValidatePriv(const uint8_t priv[32]) {
  mbedtls_mpi d;
  mbedtls_mpi n;
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&n);
  mbedtls_mpi_read_binary(&d, priv, 32);
  static const uint8_t kOrderN[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6,
                                      0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
                                      0x41, 0x41};
  mbedtls_mpi_read_binary(&n, kOrderN, 32);
  bool ok = mbedtls_mpi_cmp_int(&d, 1) >= 0 && mbedtls_mpi_cmp_mpi(&d, &n) < 0;
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&n);
  return ok;
}

bool ValidatePubkey(const uint8_t pub[33]) {
  if (pub[0] != 0x02 && pub[0] != 0x03) return false;
  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);
  int rc = mbedtls_ecp_point_read_binary(Group(), &Q, pub, 33);
  if (rc == 0) rc = mbedtls_ecp_check_pubkey(Group(), &Q);
  mbedtls_ecp_point_free(&Q);
  return rc == 0;
}

// 签名路径不在主机覆盖范围内（设备端 mbedtls 2.28 与主机 3.6 行为不同），
// keystore 的主机测试不签名，因此这里保持占位。
bool SignDer(const uint8_t*, const uint8_t[32], uint8_t*, size_t*) { return false; }

}  // namespace secp
}  // namespace rockey
