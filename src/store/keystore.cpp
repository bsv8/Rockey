#include "store/keystore.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "crypto/aead.h"
#include "crypto/digest.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "core/log.h"
#include "store/vault_fs.h"

namespace rockey {
namespace keystore {
namespace {

constexpr size_t kStateLen = 12;

// 记录 payload：pubkey(33) salt(16) nonce(12) ct(32) tag(16) digits(1) = 110
constexpr size_t kRecordPayloadLen = 33 + ROCKEY_KEYSTORE_SALT_LEN + ROCKEY_KEYSTORE_NONCE_LEN +
                                     32 + ROCKEY_KEYSTORE_TAG_LEN + 1;
constexpr size_t kSaltOff = 33;
constexpr size_t kNonceOff = kSaltOff + ROCKEY_KEYSTORE_SALT_LEN;
constexpr size_t kCtOff = kNonceOff + ROCKEY_KEYSTORE_NONCE_LEN;
constexpr size_t kTagOff = kCtOff + 32;
constexpr size_t kDigitsOff = kTagOff + ROCKEY_KEYSTORE_TAG_LEN;

constexpr const char* kKdfInfo = "rockey:vault:v1";
constexpr const char* kAadPrefix = "rockey:vault:v1|";

secure::SecretBytes<32> g_priv{};
uint8_t g_pub[33] = {0};
bool g_unlocked = false;
uint16_t g_digits = ROCKEY_PIN_DEFAULT_DIGITS;
uint32_t g_generation = 0;
bool g_ready = false;

// 失败状态记录：failCount(u32) waitRemainingMs(u32) paramsVersion(u16) reserved(u16)
//
// waitRemainingMs 是"本次失败要求等待的总时长"，跨重启保留。
// 不能存 millis() 时间戳：millis() 每次上电从 0 开始，存上次运行的时刻会让
// now-lastFail 回绕成一个巨大值，从而在每次重启后把未完成的等待直接抹掉 —
// 那正是"拔线恢复无限快速尝试"。设备没有可信时钟，所以这里只存时长，
// 等待进度在 RAM 里按本次启动的 millis() 推进（需求 §3）。
struct StateRec {
  uint32_t failCount;
  uint32_t waitRemainingMs;
  uint16_t paramsVersion;
  uint16_t reserved;
};

constexpr uint16_t kStateParamsVersion = 2;

bool g_stateCached = false;
StateRec g_state{0, 0, kStateParamsVersion, 0};
// 本次启动开始消耗剩余等待的时刻；纯 RAM，不落盘
uint32_t g_waitStartMs = 0;

bool LoadState() {
  if (!store::Init()) return false;
  // Cached waiting progress is volatile, but corruption must never turn the
  // persistent attempt counter into the default zero-attempt state.
  if (g_stateCached) {
    if (!store::Exists(store::kPathState)) return g_state.failCount == 0;
    uint8_t record[kStateLen]; size_t len = 0;
    return store::ReadRecord(store::kPathState, record, sizeof(record), &len, nullptr) && len == kStateLen;
  }
  uint8_t buf[kStateLen];
  size_t len = 0;
  if (store::ReadRecord(store::kPathState, buf, sizeof(buf), &len, nullptr) && len == kStateLen) {
    memcpy(&g_state.failCount, buf + 0, 4);
    memcpy(&g_state.waitRemainingMs, buf + 4, 4);
    memcpy(&g_state.paramsVersion, buf + 8, 2);
    memcpy(&g_state.reserved, buf + 10, 2);
    if (g_state.paramsVersion != kStateParamsVersion) {
      // 旧格式的第二个字段是时间戳，语义不同：保留计数，但按"完整等待"处理，
      // 取更保守的一侧，绝不因此缩短或取消等待。
      g_state.waitRemainingMs = KeyStore::WaitMsForFailure(g_state.failCount);
      g_state.paramsVersion = kStateParamsVersion;
    }
  } else {
    if (store::Exists(store::kPathState)) return false;
    g_state.failCount = 0;
    g_state.waitRemainingMs = 0;
    g_state.paramsVersion = kStateParamsVersion;
    g_state.reserved = 0;
  }
  g_waitStartMs = 0;  // 上电即从完整剩余时长开始
  g_stateCached = true;
  return true;
}

bool SaveState() {
  uint8_t buf[kStateLen];
  memset(buf, 0, sizeof(buf));
  memcpy(buf + 0, &g_state.failCount, 4);
  memcpy(buf + 4, &g_state.waitRemainingMs, 4);
  memcpy(buf + 8, &g_state.paramsVersion, 2);
  return store::WriteRecord(store::kPathState, g_state.paramsVersion, buf, sizeof(buf), nullptr);
}

void BuildAad(uint8_t out[], size_t* outLen, uint32_t generation, const uint8_t pub[33],
              uint8_t digits) {
  size_t prefix = strlen(kAadPrefix);
  memcpy(out, kAadPrefix, prefix);
  out[prefix] = ROCKEY_ENVELOPE_VERSION;
  out[prefix + 1] = static_cast<uint8_t>(generation >> 24);
  out[prefix + 2] = static_cast<uint8_t>(generation >> 16);
  out[prefix + 3] = static_cast<uint8_t>(generation >> 8);
  out[prefix + 4] = static_cast<uint8_t>(generation);
  memcpy(out + prefix + 5, pub, 33);
  out[prefix + 38] = digits;
  *outLen = prefix + 39;
}

// 读出已存记录里的公钥（不触碰内存里的会话状态）。
// 与 Info_() 分开：Info_() 会顺带刷新 g_pub/g_generation，而"能不能覆盖"
// 必须在提交之前判断，不能先把状态改掉。
bool ExistingPublicKey(uint8_t out[33]) {
  uint8_t rec[kRecordPayloadLen];
  size_t len = 0;
  uint32_t gen = 0;
  if (!store::ReadRecord(store::kPathKey, rec, sizeof(rec), &len, &gen)) return false;
  if (len != kRecordPayloadLen) return false;
  memcpy(out, rec, 33);
  return true;
}

}  // namespace

uint32_t KeyStore::WaitMsForFailure(uint32_t failCount) {
  if (failCount == 0) return 0;
  uint32_t wait = ROCKEY_PIN_FAIL_BASE_MS;
  for (uint32_t i = 1; i < failCount && wait < ROCKEY_PIN_FAIL_CAP_MS; ++i) {
    if (wait > ROCKEY_PIN_FAIL_CAP_MS / 2) {
      wait = ROCKEY_PIN_FAIL_CAP_MS;
      break;
    }
    wait *= 2;
  }
  if (wait > ROCKEY_PIN_FAIL_CAP_MS) wait = ROCKEY_PIN_FAIL_CAP_MS;
  return wait;
}

bool KeyStore::Init() {
  if (g_ready) return true;
  if (!store::Init()) return false;
  if (!LoadState()) { Lock(); return false; }
  Info info = Info_();
  if (!info.initialized && store::Exists(store::kPathKey)) { Lock(); return false; }
  if (info.initialized) {
    RK_LOGI("keystore", "key present, gen=%lu digits=%u", static_cast<unsigned long>(g_generation),
            g_digits);
  } else {
    RK_LOGI("keystore", "no key yet");
  }
  g_ready = true;
  return true;
}

bool KeyStore::DeviceSecret(uint8_t out[32]) {
  if (!store::Init()) return false;
  size_t len = 0;
  if (store::ReadRecord(store::kPathDevice, out, 32, &len, nullptr) && len == 32) return true;
  if (store::Exists(store::kPathDevice)) return false;
  // 首次生成
  rand::Fill(out, 32);
  return store::WriteRecord(store::kPathDevice, 1, out, 32, nullptr);
}

bool KeyStore::GenerateDeviceSecret() {
  uint8_t s[32];
  rand::Fill(s, 32);
  bool ok = store::WriteRecord(store::kPathDevice, 1, s, 32, nullptr);
  secure::Wipe(s, sizeof(s));
  return ok;
}

Info KeyStore::Info_() {
  Info info;
  if (!store::Available()) return info;
  uint8_t rec[kRecordPayloadLen];
  size_t len = 0;
  uint32_t gen = 0;
  if (store::ReadRecord(store::kPathKey, rec, sizeof(rec), &len, &gen) &&
      len == kRecordPayloadLen) {
    info.initialized = true;
    info.generation = gen;
    info.pinDigits = rec[kDigitsOff];
    memcpy(info.pubkey, rec, 33);
    g_generation = gen;
    g_digits = info.pinDigits;
    memcpy(g_pub, rec, 33);
  }
  return info;
}

// Presence is distinct from validity: a corrupt envelope still prevents a new key.
bool KeyStore::HasKey() { return store::Exists(store::kPathKey); }

Status KeyStore::WrapAndStore(const char* pinDigits, size_t pinLen, const uint8_t priv[32], bool trustedMigration) {
  if (!store::Init()) return Status::kIoError;
  uint8_t pub[33];
  if (!secp::PubkeyFromPriv(priv, pub)) return Status::kInvalidArg;

  // 单业务 Key：已有 Key 时只有**同一把**才允许重新封装（换 PIN、恢复、
  // 迁移补写都走这条）。不同 Key 一律拒绝 —— 换 Key 必须先显式擦除设备
  // （需求 §2）。少了这道检查，任何调用方都能静默替换设备上的身份，
  // 而公钥一换，Channel/本地秘密/迁移记录全部对不上。
  uint8_t existing[33];
  const bool readable = ExistingPublicKey(existing);
  if (!readable && store::Exists(store::kPathKey)) return Status::kCorrupt;
  if (!readable && !trustedMigration && store::Exists("/vault/vlp-migration.bin")) return Status::kCorrupt;
  if (readable && memcmp(existing, pub, 33) != 0) {
    RK_LOGW("keystore", "refusing to overwrite an existing key with a different key");
    return Status::kWrongKey;
  }

  secure::SecretBytes<32> devSecret{};
  if (!DeviceSecret(devSecret.data())) return Status::kIoError;

  uint8_t rec[kRecordPayloadLen];
  memset(rec, 0, sizeof(rec));
  memcpy(rec, pub, 33);
  rand::Fill(rec + kSaltOff, ROCKEY_KEYSTORE_SALT_LEN);
  rand::Fill(rec + kNonceOff, ROCKEY_KEYSTORE_NONCE_LEN);
  rec[kDigitsOff] = static_cast<uint8_t>(pinLen);

  const uint32_t previousGen = Info_().generation;
  if (previousGen == UINT32_MAX) return Status::kIoError;
  uint32_t nextGen = previousGen + 1;

  secure::SecretBytes<32> kek{};
  digest::Pbkdf2Sha256(reinterpret_cast<const uint8_t*>(pinDigits), pinLen, rec + kSaltOff,
                       ROCKEY_KEYSTORE_SALT_LEN, ROCKEY_PIN_KDF_ITERATIONS, kek.data(), 32);

  // KEK' = HKDF(ikm = KEK, salt = deviceSecret, info)
  secure::SecretBytes<32> kek2{};
  digest::HkdfSha256(kek.data(), 32, devSecret.data(), 32,
                     reinterpret_cast<const uint8_t*>(kKdfInfo), strlen(kKdfInfo), kek2.data(), 32);

  uint8_t aad[64];
  size_t aadLen = 0;
  BuildAad(aad, &aadLen, nextGen, pub, static_cast<uint8_t>(pinLen));

  if (!aead::Seal(kek2.data(), rec + kNonceOff, aad, aadLen, priv, 32, rec + kCtOff,
                        rec + kTagOff)) {
    return Status::kIoError;
  }

  uint32_t written = 0;
  bool ok = store::WriteRecord(store::kPathKey, ROCKEY_ENVELOPE_VERSION, rec, sizeof(rec),
                               &written);
  if (!ok) return Status::kIoError;

  g_generation = written;
  g_digits = static_cast<uint16_t>(pinLen);
  memcpy(g_pub, pub, 33);
  return Status::kOk;
}

Status KeyStore::SetPinAndWrap(const char* pinDigits, size_t pinLen, const uint8_t priv[32]) {
  if (!pinDigits || !priv || pinLen < ROCKEY_PIN_MIN_DIGITS || pinLen > ROCKEY_PIN_MAX_DIGITS) return Status::kInvalidArg;
  for (size_t i = 0; i < pinLen; ++i) {
    if (pinDigits[i] < '0' || pinDigits[i] > '9') return Status::kInvalidArg;
  }
  if (!store::Init()) return Status::kIoError;
  return WrapAndStore(pinDigits, pinLen, priv);
}

Status KeyStore::Unlock(const char* pinDigits, size_t pinLen) {
  // Re-authentication is also an unlock attempt. Clear the previous RAM key
  // before every early return, including waiting, I/O failure and wrong PIN.
  Lock();
  if (pinDigits == nullptr) return Status::kInvalidArg;
  if (!store::Init()) return Status::kIoError;
  if (!LoadState()) return Status::kIoError;

  uint32_t remain = WaitMsRemaining(millis());
  if (remain > 0) return Status::kNeedsWait;

  uint8_t rec[kRecordPayloadLen];
  size_t len = 0;
  uint32_t gen = 0;
  if (!store::ReadRecord(store::kPathKey, rec, sizeof(rec), &len, &gen) ||
      len != kRecordPayloadLen) {
    return store::Exists(store::kPathKey) ? Status::kCorrupt : Status::kNotInitialized;
  }
  if (pinLen != rec[kDigitsOff]) {
    return NoteUnlockFailure(millis()) ? Status::kWrongPin : Status::kIoError;
  }

  secure::SecretBytes<32> devSecret{};
  if (!DeviceSecret(devSecret.data())) return Status::kIoError;

  secure::SecretBytes<32> kek{};
  digest::Pbkdf2Sha256(reinterpret_cast<const uint8_t*>(pinDigits), pinLen, rec + kSaltOff,
                       ROCKEY_KEYSTORE_SALT_LEN, ROCKEY_PIN_KDF_ITERATIONS, kek.data(), 32);
  secure::SecretBytes<32> kek2{};
  digest::HkdfSha256(kek.data(), 32, devSecret.data(), 32,
                     reinterpret_cast<const uint8_t*>(kKdfInfo), strlen(kKdfInfo), kek2.data(), 32);

  uint8_t aad[64];
  size_t aadLen = 0;
  BuildAad(aad, &aadLen, gen, rec, rec[kDigitsOff]);

  Status st = Status::kWrongPin;
  if (aead::Open(kek2.data(), rec + kNonceOff, aad, aadLen, rec + kCtOff, 32, rec + kTagOff,
                       g_priv.data())) {
    // 再核对公钥与私钥一致，防止记录被部分篡改
    uint8_t pub[33];
    if (secp::PubkeyFromPriv(g_priv.data(), pub) && memcmp(pub, rec, 33) == 0) {
      st = Status::kOk;
    } else {
      g_priv.Clear();
      st = Status::kCorrupt;
    }
  }
  if (st != Status::kOk) {
    g_priv.Clear();
    return NoteUnlockFailure(millis()) ? st : Status::kIoError;
  }

  memcpy(g_pub, rec, 33);
  g_generation = gen;
  g_digits = rec[kDigitsOff];
  g_unlocked = true;
  if (!NoteUnlockSuccess()) { Lock(); return Status::kIoError; }
  return Status::kOk;
}

Status KeyStore::ChangePin(const char* oldPin, size_t oldLen, const char* newPin,
                           size_t newLen) {
  if (!IsUnlocked()) return Status::kLocked;
  if (newLen < ROCKEY_PIN_MIN_DIGITS || newLen > ROCKEY_PIN_MAX_DIGITS) return Status::kInvalidArg;
  if (!oldPin || !newPin) return Status::kInvalidArg;
  for (size_t i = 0; i < newLen; ++i) {
    if (newPin[i] < '0' || newPin[i] > '9') return Status::kInvalidArg;
  }
  // 旧 PIN 走同一持久失败计数/等待门禁；失败不保留已解锁的 RAM Key。
  Lock();
  const Status authenticated = Unlock(oldPin, oldLen);
  if (authenticated != Status::kOk) return authenticated;

  // 用当前（已验证的）私钥重新封装，失败不破坏旧记录：WrapAndStore 走 tmp+rename
  Status st = WrapAndStore(newPin, newLen, g_priv.data());
  return st;
}

void KeyStore::Lock() {
  g_priv.Clear();
  g_unlocked = false;
}

bool KeyStore::IsUnlocked() { return g_unlocked; }
const uint8_t* KeyStore::PrivateKey() { return g_unlocked ? g_priv.data() : nullptr; }
uint8_t* KeyStore::PublicKey() { return g_pub; }

uint32_t KeyStore::FailCount() {
  if (!LoadState()) return UINT32_MAX;
  return g_state.failCount;
}

uint32_t KeyStore::WaitMsRemaining(uint32_t nowMs) {
  if (!LoadState()) return ROCKEY_PIN_FAIL_CAP_MS;
  if (g_state.failCount == 0 || g_state.waitRemainingMs == 0) return 0;
  // 进度只在本次启动内推进；重启后从完整剩余时长重新计（保守方向）
  uint32_t elapsed = nowMs - g_waitStartMs;
  if (elapsed >= g_state.waitRemainingMs) return 0;
  return g_state.waitRemainingMs - elapsed;
}

bool KeyStore::NoteUnlockSuccess() {
  if (!LoadState()) return false;
  if (g_state.failCount == 0 && g_state.waitRemainingMs == 0) return true;
  g_state.failCount = 0;
  g_state.waitRemainingMs = 0;
  g_waitStartMs = 0;
  if (!SaveState()) { g_stateCached = false; Lock(); return false; }
  return true;
}

bool KeyStore::NoteUnlockFailure(uint32_t nowMs) {
  if (!LoadState()) return false;
  if (g_state.failCount < 0xFFFFFFFFu) g_state.failCount++;
  g_state.waitRemainingMs = KeyStore::WaitMsForFailure(g_state.failCount);
  g_waitStartMs = nowMs;
  if (!SaveState()) { g_stateCached = false; Lock(); return false; }
#if ROCKEY_PIN_FAIL_WIPE_THRESHOLD > 0
  if (g_state.failCount >= ROCKEY_PIN_FAIL_WIPE_THRESHOLD) {
    // 只有在明确确认后才启用；默认 0，不做自动擦除（需求 §3）
  }
#endif
  return true;
}

bool KeyStore::Erase(bool preserveMigration) {
  Lock();
  // Keep the migration recovery marker until every destructive step succeeds.
  // A partial erase is an error, never evidence that a new identity may be created.
  if (!store::Init() || !store::Remove(store::kPathBackup)
      || !store::Remove("/vault/vlp-policy.bin") || !store::Remove(store::kPathKey)
      || !store::Remove(store::kPathDevice) || !GenerateDeviceSecret()
      || !store::Remove(store::kPathState)) return false;
  g_state = StateRec{0, 0, kStateParamsVersion, 0};
  g_stateCached = true;
  g_waitStartMs = 0;
  if (!SaveState()) { g_stateCached = false; return false; }
  return preserveMigration || (store::Remove(store::kPathMigration)
      && store::Remove("/vault/vlp-import-meta.bin")
      && store::Remove("/vault/vlp-import-stage.bin")
      && store::Remove("/vault/vlp-migration.bin"));
}


// ── 设备外恢复备份 ──────────────────────────────────────────────────────
// 备份格式 v1（自足，不依赖旧设备的任何秘密材料）：
//   code  = base32(16 字节硬件随机)                    —— 用户离线抄写
//   key   = SHA256d("rockey:recovery:v1" || 0x00 || UTF8(code) || 0x00 || pubkey(33))
//   nonce = 12 字节随机
//   blob  = "RKB1" || version || pubkey(33) || nonce(12) || ct(32) || tag(16)
//
// 安全边界（必须如实告知用户）：恢复码等价于私钥，任何拿到它的人都能恢复该 Key。
// 这比"设备 + PIN"弱，界面与文档都要写清楚，不得包装成"更安全的备份"。
namespace {

constexpr char kB32[] = "abcdefghijklmnopqrstuvwxyz234567";
constexpr size_t kRecoveryCodeBytes = 16;
constexpr size_t kRecoveryCodeChars = 26;
constexpr size_t kRecoveryBlobLen = 4 + 1 + 33 + 12 + 32 + 16;
// AAD = version(1) || 0x000000(3) || pubkey(33)：把备份与具体公钥绑定
constexpr size_t kRecoveryAadLen = 1 + 3 + 33;

void BuildRecoveryAad(const uint8_t pub[33], uint8_t out[kRecoveryAadLen]) {
  out[0] = 1;
  out[1] = out[2] = out[3] = 0;
  memcpy(out + 4, pub, 33);
}

void Base32Encode16(const uint8_t in[16], char* out /* 26 chars */) {
  uint32_t bits = 0;
  int nbits = 0;
  size_t o = 0;
  for (size_t i = 0; i < 16; ++i) {
    bits = (bits << 8) | in[i];
    nbits += 8;
    while (nbits >= 5) {
      out[o++] = kB32[(bits >> (nbits - 5)) & 0x1F];
      nbits -= 5;
    }
  }
  if (nbits > 0) out[o++] = kB32[(bits << (5 - nbits)) & 0x1F];
  out[o] = '\0';
}

bool Base32Decode16(const char* in, size_t len, uint8_t out[16]) {
  if (len != kRecoveryCodeChars) return false;
  uint32_t bits = 0;
  int nbits = 0;
  size_t o = 0;
  for (size_t i = 0; i < len; ++i) {
    const char* p = strchr(kB32, in[i]);
    if (!p || in[i] == '\0') return false;
    bits = (bits << 5) | static_cast<uint32_t>(p - kB32);
    nbits += 5;
    if (nbits >= 8) {
      if (o >= 16) return false;
      out[o++] = static_cast<uint8_t>((bits >> (nbits - 8)) & 0xFF);
      nbits -= 8;
    }
  }
  return o == 16;
}

bool RecoveryKey(const char* code, const uint8_t pub[33], uint8_t out[32]) {
  static const char* kLabel = "rockey:recovery:v1";
  uint8_t buf[128];
  size_t n = 0;
  size_t l = strlen(kLabel);
  memcpy(buf, kLabel, l);
  n = l;
  buf[n++] = 0;
  size_t cl = strlen(code);
  memcpy(buf + n, code, cl);
  n += cl;
  buf[n++] = 0;
  memcpy(buf + n, pub, 33);
  n += 33;
  digest::Sha256d(buf, n, out);
  secure::Wipe(buf, sizeof(buf));
  return true;
}

}  // namespace

Status KeyStore::CreateRecoveryBackup(char* codeOut, size_t codeCap, uint8_t* backupOut,
                                      size_t* backupLen) {
  if (!IsUnlocked()) return Status::kLocked;
  if (codeCap < static_cast<size_t>(kRecoveryCodeChars) + 1 || !backupOut) {
    return Status::kInvalidArg;
  }
  uint8_t raw[kRecoveryCodeBytes];
  rand::Fill(raw, kRecoveryCodeBytes);
  Base32Encode16(raw, codeOut);

  uint8_t key[32];
  RecoveryKey(codeOut, g_pub, key);
  uint8_t nonce[12];
  rand::Fill(nonce, 12);
  static uint8_t blob[kRecoveryBlobLen];
  memcpy(blob, "RKB1", 4);
  blob[4] = 1;
  memcpy(blob + 5, g_pub, 33);
  memcpy(blob + 38, nonce, 12);
  uint8_t aad[kRecoveryAadLen];
  BuildRecoveryAad(g_pub, aad);
  if (!aead::Seal(key, nonce, aad, kRecoveryAadLen, g_priv.data(), 32, blob + 50, blob + 82)) {
    secure::Wipe(key, sizeof(key));
    secure::Wipe(raw, sizeof(raw));
    return Status::kIoError;
  }
  if (!store::WriteRecord(store::kPathBackup, 1, blob, kRecoveryBlobLen, nullptr)) {
    secure::Wipe(key, sizeof(key));
    secure::Wipe(raw, sizeof(raw));
    return Status::kIoError;
  }
  if (backupOut && backupLen && *backupLen >= kRecoveryBlobLen) {
    memcpy(backupOut, blob, kRecoveryBlobLen);
    *backupLen = kRecoveryBlobLen;
  }
  secure::Wipe(key, sizeof(key));
  secure::Wipe(raw, sizeof(raw));
  secure::Wipe(blob, sizeof(blob));
  return Status::kOk;
}

bool KeyStore::HasRecoveryBackup() { return store::Exists(store::kPathBackup); }

bool KeyStore::ReadRecoveryBackup(uint8_t* out, size_t cap, size_t* len) {
  if (!out || cap < kRecoveryBlobLen) return false;
  size_t got = 0;
  if (!store::ReadRecord(store::kPathBackup, out, cap, &got, nullptr)) return false;
  if (got != kRecoveryBlobLen) return false;
  if (memcmp(out, "RKB1", 4) != 0 || out[4] != 1) return false;
  if (len) *len = got;
  return true;
}

Status KeyStore::RestoreFromBackup(const char* code, const uint8_t* backup, size_t backupLen,
                                   const char* newPinDigits, size_t newPinLen) {
  if (!code || !backup) return Status::kInvalidArg;
  if (backupLen != kRecoveryBlobLen || memcmp(backup, "RKB1", 4) != 0 || backup[4] != 1) {
    return Status::kCorrupt;
  }
  if (HasKey()) {
    // 已有 Key 时只允许恢复同一 Key，避免静默替换身份
    Info info = Info_();
    if (memcmp(backup + 5, info.pubkey, 33) != 0) return Status::kWrongKey;
  }
  uint8_t raw[kRecoveryCodeBytes];
  if (!Base32Decode16(code, strlen(code), raw)) return Status::kInvalidArg;
  uint8_t key[32];
  RecoveryKey(code, backup + 5, key);
  static uint8_t priv[32];
  uint8_t aad[kRecoveryAadLen];
  BuildRecoveryAad(backup + 5, aad);
  bool ok = aead::Open(key, backup + 38, aad, kRecoveryAadLen, backup + 50, 32, backup + 82, priv);
  secure::Wipe(key, sizeof(key));
  secure::Wipe(raw, sizeof(raw));
  if (!ok) {
    secure::Wipe(priv, sizeof(priv));
    return Status::kWrongPin;  // 恢复码错误
  }
  uint8_t derived[33];
  if (!secp::PubkeyFromPriv(priv, derived) || memcmp(derived, backup + 5, 33) != 0) {
    secure::Wipe(priv, sizeof(priv));
    return Status::kCorrupt;
  }
  Status st = WrapAndStore(newPinDigits, newPinLen, priv);
  secure::Wipe(priv, sizeof(priv));
  if (st != Status::kOk) return st;
  // 恢复成功后清除设备上的旧备份材料，避免旧密文残留
  store::Remove(store::kPathBackup);
  memcpy(g_pub, derived, 33);
  return Status::kOk;
}

#if defined(ROCKEY_DEV_TEST_KEY)
Status KeyStore::DevInjectTestKey(const char* pinDigits, size_t pinLen) {
  // 开发固件专用公开测试私钥（xprv 结构的末 32 字节，见 test-vectors/dev-test-key.json）
  static const uint8_t kDevTestPriv[32] = {
      0x18, 0xE1, 0x4A, 0x8B, 0xF5, 0x0F, 0x1E, 0x2A, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
      0x77, 0x88, 0x99, 0x77};
  if (!secp::ValidatePriv(kDevTestPriv)) return Status::kInvalidArg;
  return SetPinAndWrap(pinDigits, pinLen, kDevTestPriv);
}
#endif

}  // namespace keystore
}  // namespace rockey
