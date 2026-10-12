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
//  - 失败计数与"本次失败应等待的时长"跨重启保存，递增等待。设备没有可信时钟，
//    所以落盘的是时长而不是时间戳：拔线重上电仍要等满，只是失败计数继续递增，
//    不存在"拔线恢复无限快速尝试"的路径。
#ifndef ROCKEY_STORE_KEYSTORE_H
#define ROCKEY_STORE_KEYSTORE_H

#include <stdint.h>
#include <stddef.h>

#include "core/rockey_config.h"
#include "crypto/secure.h"

namespace rockey {
namespace vlp { class ProvisionKeys; }
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

enum class BsvNetwork : uint8_t { Main = 0, Test = 1 };
struct Info {
  BsvNetwork bsvNetwork = BsvNetwork::Main;
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
                              const uint8_t priv[32], BsvNetwork network);
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
  static bool NoteUnlockSuccess();
  static bool NoteUnlockFailure(uint32_t nowMs);

  static uint32_t WaitMsForFailure(uint32_t failCount);

  // 设备擦除（需要 UI 独立物理确认后调用）
  // A private migration controller preserves its public recovery marker while
  // physically erasing the key, then durably records the erase outcome.
  static bool Erase(bool preserveMigration = false);
  static bool GenerateDeviceSecret();

  // 开发固件专用：注入公开测试密钥（发布构建不包含）
  static Status DevInjectTestKey(const char* pinDigits, size_t pinLen);

 private:
  friend class rockey::vlp::ProvisionKeys;
  static Status LoadRecord(uint8_t* rec, size_t recCap, size_t* recLen);
  static Status WrapAndStore(const char* pinDigits, size_t pinLen, const uint8_t priv[32], BsvNetwork network, bool trustedMigration = false);
  static bool DeviceSecret(uint8_t out[32]);
};

}  // namespace keystore
}  // namespace rockey

#endif  // ROCKEY_STORE_KEYSTORE_H
