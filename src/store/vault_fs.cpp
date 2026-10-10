#include "store/vault_fs.h"

#include <LittleFS.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "core/rockey_config.h"

#include "core/log.h"
#include "store/crc32.h"

namespace rockey {
namespace store {

const char* const kPathDevice = "/vault/dev.bin";
const char* const kPathKey = "/vault/key.bin";
const char* const kPathState = "/vault/state.bin";
const char* const kPathBackup = "/vault/backup.bin";
const char* const kPathMigration = "/vault/mig.bin";

namespace {

constexpr uint32_t kMagic = 0x524B5631u;  // "RKV1"
constexpr const char* kMount = "/rockey";
constexpr const char* kTmpSuffix = ".tmp";

bool g_ready = false;
// 测试固件只访问 /e2e 子目录；实际 LittleFS 和原子提交代码共用。
// 不格式化分区，也不读取/覆盖正式 /vault。路径由钱包内部给出，不接受 USB 路径。
std::string PhysicalPath(const char* path) {
#if defined(ROCKEY_E2E_ISOLATED)
  return std::string("/e2e") + path;
#else
  return path;
#endif
}

// 记录头（18 字节，小端，与平台无关）：
//   0  magic(4)  4 version(2)  6 generation(4)  10 crc32(4)  14 len(4)
constexpr size_t kHdrMagic = 0;
constexpr size_t kHdrVersion = 4;
constexpr size_t kHdrGeneration = 6;
constexpr size_t kHdrCrc = 10;
constexpr size_t kHdrLen = 14;

uint32_t ReadU32(const uint8_t* p) {
  uint32_t v;
  memcpy(&v, p, 4);
  return v;
}

// Paths must fit together with the temporary suffix. Truncating a path can
// overwrite or remove another record, including a private-key envelope.
bool ValidPath(const char* path) {
  return path && path[0] == '/' && strlen(path) + strlen(kTmpSuffix) < 128;
}

// Check the *whole* previous record without a 64KB RAM allocation. A fixed
// 1KB ReadRecord scratch used to reset the generation of larger policy banks.
bool PreviousGeneration(const char* path, uint32_t* generation) {
  File f = LittleFS.open(PhysicalPath(path).c_str(), "r");
  if (!f) return false;
  uint8_t hdr[kRecordHeaderLen];
  if (f.read(hdr, sizeof(hdr)) != sizeof(hdr)) { f.close(); return false; }
  const uint32_t len = ReadU32(hdr + kHdrLen), gen = ReadU32(hdr + kHdrGeneration);
  if (ReadU32(hdr + kHdrMagic) != kMagic || gen == 0 || len > kRecordPayloadMax
      || f.size() != kRecordHeaderLen + size_t(len)) { f.close(); return false; }
  uint8_t chunk[512];
  uint32_t crc = 0xFFFFFFFFu;
  size_t remaining = len;
  while (remaining) {
    const size_t count = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
    if (f.read(chunk, count) != count) { f.close(); return false; }
    crc = Crc32Extend(crc, chunk, count);
    remaining -= count;
  }
  f.close();
  if ((crc ^ 0xFFFFFFFFu) != ReadU32(hdr + kHdrCrc)) return false;
  *generation = gen;
  return true;
}

}  // namespace

bool Init() {
  if (g_ready) return true;
  if (!LittleFS.begin(false, kMount, 10, "rockey")) {
    RK_LOGE("fs", "LittleFS mount failed");
    return false;
  }
#if defined(ROCKEY_E2E_ISOLATED)
  if (!LittleFS.exists("/e2e") && !LittleFS.mkdir("/e2e")) return false;
#endif
  for (const char* dir : {"/vault", "/docs"}) {
    const auto physical=PhysicalPath(dir);
    if (!LittleFS.exists(physical.c_str()) && !LittleFS.mkdir(physical.c_str())) return false;
  }
  g_ready = true;
  RK_LOGI("fs", "vault fs ready");
  return true;
}

bool Available() { return g_ready; }

bool Exists(const char* path) { return g_ready && ValidPath(path) && LittleFS.exists(PhysicalPath(path).c_str()); }

bool ReadRecord(const char* path, uint8_t* out, size_t outCap, size_t* outLen,
                uint32_t* outGeneration) {
  if (!g_ready || !ValidPath(path) || (!out && outCap)) return false;
  File f = LittleFS.open(PhysicalPath(path).c_str(), "r");
  if (!f) return false;
  size_t total = f.size();
  if (total < kRecordHeaderLen) {
    f.close();
    return false;
  }
  uint8_t hdr[kRecordHeaderLen];
  if (f.read(hdr, kRecordHeaderLen) != kRecordHeaderLen) {
    f.close();
    return false;
  }
  uint32_t magic = ReadU32(hdr + kHdrMagic);
  uint32_t gen = ReadU32(hdr + kHdrGeneration);
  uint32_t crc = ReadU32(hdr + kHdrCrc);
  uint32_t len = ReadU32(hdr + kHdrLen);
  if (magic != kMagic || gen == 0 || len > kRecordPayloadMax || len > outCap || kRecordHeaderLen + size_t(len) != total) {
    f.close();
    return false;
  }
  size_t got = len ? f.read(out, len) : 0;
  f.close();
  if (got != len) return false;
  if (Crc32(out, len) != crc) {
    RK_LOGE("fs", "record crc mismatch");
    return false;
  }
  if (outLen) *outLen = len;
  if (outGeneration) *outGeneration = gen;
  return true;
}

bool WriteRecord(const char* path, uint16_t version, const uint8_t* payload, size_t len,
                 uint32_t* outGeneration) {
  if (!g_ready || !ValidPath(path) || len > kRecordPayloadMax || (!payload && len)) return false;
  uint32_t prev = 0;
  // Existing-but-corrupt is not a fresh record. Only explicit device erase may
  // remove it; a normal save must not silently reset the identity or ledger.
  if (LittleFS.exists(PhysicalPath(path).c_str()) && !PreviousGeneration(path, &prev)) return false;
  if (prev == UINT32_MAX) return false;

  uint8_t hdr[kRecordHeaderLen];
  memset(hdr, 0, sizeof(hdr));
  uint32_t magic = kMagic;
  uint32_t gen = prev + 1;
  uint32_t crc = Crc32(payload, len);
  uint32_t l = static_cast<uint32_t>(len);
  memcpy(hdr + kHdrMagic, &magic, 4);
  memcpy(hdr + kHdrVersion, &version, 2);
  memcpy(hdr + kHdrGeneration, &gen, 4);
  memcpy(hdr + kHdrCrc, &crc, 4);
  memcpy(hdr + kHdrLen, &l, 4);

  char tmpPath[128];
  snprintf(tmpPath, sizeof(tmpPath), "%s%s", path, kTmpSuffix);
  File f = LittleFS.open(PhysicalPath(tmpPath).c_str(), "w");
  if (!f) {
    RK_LOGE("fs", "open tmp failed");
    return false;
  }
  size_t w1 = f.write(hdr, kRecordHeaderLen);
  size_t w2 = len ? f.write(payload, len) : 0;
  f.close();
  if (w1 != kRecordHeaderLen || w2 != len) {
    LittleFS.remove(PhysicalPath(tmpPath).c_str());
    RK_LOGE("fs", "write tmp incomplete");
    return false;
  }
  if (!LittleFS.rename(PhysicalPath(tmpPath).c_str(), PhysicalPath(path).c_str())) {
    LittleFS.remove(PhysicalPath(tmpPath).c_str());
    RK_LOGE("fs", "rename failed");
    return false;
  }
  if (outGeneration) *outGeneration = gen;
  return true;
}

bool Remove(const char* path) {
  if (!g_ready || !ValidPath(path)) return false;
  char tmpPath[128];
  snprintf(tmpPath, sizeof(tmpPath), "%s%s", path, kTmpSuffix);
  // Removal is idempotent, but an existing file that cannot be removed must
  // propagate failure. Pending tmp records can contain the same secret as the
  // live record and must not survive a successful erase.
  if (LittleFS.exists(PhysicalPath(tmpPath).c_str()) && !LittleFS.remove(PhysicalPath(tmpPath).c_str())) return false;
  if (LittleFS.exists(PhysicalPath(path).c_str()) && !LittleFS.remove(PhysicalPath(path).c_str())) return false;
  return !LittleFS.exists(PhysicalPath(tmpPath).c_str()) && !LittleFS.exists(PhysicalPath(path).c_str());
}

bool ReadCounter(const char* path, uint32_t* value) {
  static uint8_t buf[16];
  size_t len = 0;
  uint32_t gen = 0;
  if (!ReadRecord(path, buf, sizeof(buf), &len, &gen)) return false;
  if (len != 4) return false;
  memcpy(value, buf, 4);
  return true;
}

bool WriteCounter(const char* path, uint32_t value) {
  return WriteRecord(path, 1, reinterpret_cast<const uint8_t*>(&value), sizeof(value), nullptr);
}

}  // namespace store
}  // namespace rockey
