// 脱敏日志：发布固件中禁止出现 Key、PIN、派生密钥、解封明文。
//
// 规则（需求 §2 / RK-09）：
//  1. 默认关闭；LOG_LEVEL 由构建档位决定，发布为 1（仅致命错误）。
//  2. 不提供"打印任意缓冲区"的接口；只提供打印长度与前缀指纹的接口。
//  3. 任何 key/pin/derived/plaintext 字段的日志调用一律被 ifdef 掉，
//     由 scripts/check_release_build.py 静态检查。
#ifndef ROCKEY_CORE_LOG_H
#define ROCKEY_CORE_LOG_H

#include <stdint.h>
#include <stddef.h>

#ifndef LOG_LEVEL
#define LOG_LEVEL 1
#endif

namespace rockey {

enum class LogLevel : uint8_t { kNone = 0, kError = 1, kWarn = 2, kInfo = 3, kDebug = 4 };

// 只输出长度与不可逆短指纹，便于定位"是否同一份材料"，不泄露内容。
class Fingerprint {
 public:
  static Fingerprint Of(const uint8_t* data, size_t len);
  // 输出 "fp=<4 hex>" 形式写入调用方缓冲（不含秘密）
  void Format(char* out, size_t outLen) const;

 private:
  uint16_t fp_ = 0;
  uint8_t len_ = 0;
};

class Log {
 public:
  static void Init();
  static void Write(LogLevel level, const char* tag, const char* fmt, ...);
  static bool Enabled(LogLevel level);
  static uint32_t dropped() { return dropped_; }
  static void PrintBanner();

 private:
  static uint32_t dropped_;
};

}  // namespace rockey

#if LOG_LEVEL >= 1
#define RK_LOGE(tag, ...) ::rockey::Log::Write(::rockey::LogLevel::kError, tag, __VA_ARGS__)
#else
#define RK_LOGE(tag, ...) ((void)0)
#endif

#if LOG_LEVEL >= 2
#define RK_LOGW(tag, ...) ::rockey::Log::Write(::rockey::LogLevel::kWarn, tag, __VA_ARGS__)
#else
#define RK_LOGW(tag, ...) ((void)0)
#endif

#if LOG_LEVEL >= 3
#define RK_LOGI(tag, ...) ::rockey::Log::Write(::rockey::LogLevel::kInfo, tag, __VA_ARGS__)
#define RK_LOGD(tag, ...) ::rockey::Log::Write(::rockey::LogLevel::kDebug, tag, __VA_ARGS__)
#else
#define RK_LOGI(tag, ...) ((void)0)
#define RK_LOGD(tag, ...) ((void)0)
#endif

#endif  // ROCKEY_CORE_LOG_H