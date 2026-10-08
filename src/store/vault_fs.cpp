#include "store/vault_fs.h"

#include <LittleFS.h>
#include <stdio.h>
#include <string.h>

#include "core/log.h"

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

uint16_t ReadU16(const uint8_t* p) {
  uint16_t v;
  memcpy(&v, p, 2);
  return v;
}

}  // namespace

bool Init() {
  if (g_ready) return true;
  if (!LittleFS.begin(false, kMount, 10, "spiffs")) {
    RK_LOGE("fs", "LittleFS mount failed");
    return false;
  }
  if (!LittleFS.exists("/vault")) LittleFS.mkdir("/vault");
  if (!LittleFS.exists("/docs")) LittleFS.mkdir("/docs");
  g_ready = true;
  RK_LOGI("fs", "vault fs ready");
  return true;
}

bool Available() { return g_ready; }

uint32_t Crc32(const uint8_t* data, size_t len) {
  static uint32_t table[256];
  static bool init = false;
  if (!init) {
    for (uint32_t i = 0; i < 256; ++i) {
      uint32_t c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      table[i] = c;
    }
    init = true;
  }
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; ++i) c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
  return c ^ 0xFFFFFFFFu;
}

bool Exists(const char* path) { return g_ready && LittleFS.exists(path); }

bool ReadRecord(const char* path, uint8_t* out, size_t outCap, size_t* outLen,
                uint32_t* outGeneration) {
  if (!g_ready) return false;
  File f = LittleFS.open(path, "r");
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
  if (magic != kMagic || len > outCap || kRecordHeaderLen + len != total) {
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
  if (!g_ready) return false;

  uint32_t prev = 0;
  {
    static uint8_t scratch[1024];
    size_t prevLen = 0;
    if (ReadRecord(path, scratch, sizeof(scratch), &prevLen, &prev)) {
      // 旧记录有效：generation 递增
    } else {
      prev = 0;
    }
  }

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
  File f = LittleFS.open(tmpPath, "w");
  if (!f) {
    RK_LOGE("fs", "open tmp failed");
    return false;
  }
  size_t w1 = f.write(hdr, kRecordHeaderLen);
  size_t w2 = len ? f.write(payload, len) : 0;
  f.close();
  if (w1 != kRecordHeaderLen || w2 != len) {
    LittleFS.remove(tmpPath);
    RK_LOGE("fs", "write tmp incomplete");
    return false;
  }
  if (!LittleFS.rename(tmpPath, path)) {
    LittleFS.remove(tmpPath);
    RK_LOGE("fs", "rename failed");
    return false;
  }
  if (outGeneration) *outGeneration = gen;
  return true;
}

bool Remove(const char* path) {
  if (!g_ready) return false;
  char tmpPath[128];
  snprintf(tmpPath, sizeof(tmpPath), "%s%s", path, kTmpSuffix);
  LittleFS.remove(tmpPath);
  return LittleFS.remove(path);
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