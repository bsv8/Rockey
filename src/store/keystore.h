// 单业务密钥的设备封装与 PIN 解锁。
//
// 冻结格式 v1（docs/冻结/密钥封装.md）：
//   KEK   = PBKDF2-HMAC-SHA256(UTF8(PIN), salt = <设备随机 16B>, iters = 120000, 32B)
//   KEK'  = HKDF-SHA256(ikm = KEK, salt = <设备保护秘密 32B>, info = "rockey:vault:v1", 32B)
//   nonce = AES-256-GCM 随机 12B
//   AAD   = "rockey:vault:v1|" || version(u8) || generation(u32be) || pubkey(33) || pinDigits(u8)
//   ct    = AES-256-GCM(KEK', nonce, AAD, priv32)
//
// 语义要点：
//  - 设备保护秘密单独存一份文件，单独拿到 flash 也解不开封装（仍非安全芯片级）；
//  - PIN 只经实体按钮进入，不接受主机提供的 PIN；
//  - 公钥放进 AAD，攻击者不能把封装换到别的公钥上；
//  - 已有 Key 的设备拒绝不同 Key 覆盖，除非设备擦除；
//  - 失败计数跨重启保存，递增等待，拔线不能恢复无限快速尝试。
#ifndef ROCKEY_STORE_KEYSTORE_H
#define ROCKEY_STORE_KEYSTORE_H

#include <stdint.h>
#include <stddef.h>

#include "core/rockey_config.h"
#include "crypto/secure.h"

namespace rockey {
namespace keystore {

enum class Status : uint8_t {
  kOk,
  kNotInitialized,
  kLocked,
  kWrongPin,
  kNeedsWait,
  kCorrupt,
  kWrongKey,
  kIoError,
  kInvalidArg,
};

struct Info {
  bool initialized = false;
  uint16_t pinDigits = ROCKEY_PIN_DEFAULT_DIGITS;
  uint32_t generation = 0;
  uint8_t pubkey[33] = {0};
};

class KeyStore {
 public:
  static bool Init();
  static Info Info_();
  static bool HasKey();

  // 设置 PIN（首次设置或修改）。newPinDigits 只接受数字文本。
  static Status SetPinAndWrap(const char* pinDigits, size_t pinLen,
                              const uint8_t priv[32]);
  // 解锁；成功后私钥只在本对象内短暂存在，Lock() 立即清零。
  static Status Unlock(const char* pinDigits, size_t pinLen);
  static void Lock();
  static bool IsUnlocked();
  // 仅在解锁状态下有效，返回内部缓冲指针；不得写出固件。
  static const uint8_t* PrivateKey();
  static uint8_t* PublicKey();

  // 更换 PIN：需要旧 PIN 已解锁，失败/断电不破坏旧封装。
  static Status ChangePin(const char* oldPin, size_t oldLen, const char* newPin, size_t newLen);

  // 失败计数与等待
  static uint32_t FailCount();
  static uint32_t WaitMsRemaining(uint32_t nowMs);
  static void NoteUnlockSuccess();
  static void NoteUnlockFailure(uint32_t nowMs);

  static uint32_t WaitMsForFailure(uint32_t failCount);

  // 设备擦除（需要 UI 独立物理确认后调用）
  static bool Erase();
  static bool GenerateDeviceSecret();

  // ── 设备外恢复备份 ────────────────────────────────────────────
  // 备份自足：用户抄写一次性恢复码，恢复码直接作为封装密钥的输入材料，
  // 因此拿到恢复码 = 拿到私钥，这一点在界面上必须明确告知，不能暗示更安全。
  static constexpr size_t kRecoveryCodeChars = 26;  // base32，无 padding
  static constexpr size_t kRecoveryBackupMax = 160;
  // 生成恢复码并把备份写入 /vault/backup.bin；恢复码只在本次调用后由界面显示一次
  static Status CreateRecoveryBackup(char* codeOut, size_t codeCap, uint8_t* backupOut,
                                     size_t* backupLen);
  // 用恢复码 + 备份在当前设备恢复同一 Key，并设置新的 PIN
  static Status RestoreFromBackup(const char* code, const uint8_t* backup, size_t backupLen,
                                  const char* newPinDigits, size_t newPinLen);
  static bool HasRecoveryBackup();
  static bool ReadRecoveryBackup(uint8_t* out, size_t cap, size_t* len);

  // 开发固件专用：注入公开测试密钥（发布构建不包含）
  static Status DevInjectTestKey(const char* pinDigits, size_t pinLen);

 private:
  static Status LoadRecord(uint8_t* rec, size_t recCap, size_t* recLen);
  static Status WrapAndStore(const char* pinDigits, size_t pinLen, const uint8_t priv[32]);
  static bool DeviceSecret(uint8_t out[32]);
};

}  // namespace keystore
}  // namespace rockey

#endif  // ROCKEY_STORE_KEYSTORE_H