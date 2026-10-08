// 授权决定状态机（需求 §5）。
//
// 三态：未决定 / 会话允许 / 会话否决。本次允许或拒绝只是当前请求的结果，
// 不留下持续授权。持续决定绑定：业务 Key、设备运行、连接、主机三个世代、
// App 会话、操作版本、协议、对象、方向与限额；Channel 允许不覆盖付款、
// 私钥导出、任意摘要或另一协议。
//
// 规则：
//  - 持续否决匹配优先于执行，且直接返回拒绝、不反复弹窗；
//  - 用户可取消任一持续决定，取消后回到未决定并推进 decisionRevision；
//  - 撤销后旧队列请求不可执行：执行前再复核；
//  - 持续决定不落盘；PIN 失败计数与迁移状态才落盘。
#ifndef ROCKEY_POLICY_POLICY_H
#define ROCKEY_POLICY_POLICY_H

#include <stdint.h>
#include <stddef.h>

#include "core/rockey_config.h"

namespace rockey {
namespace policy {

enum class Category : uint8_t {
  kSystem = 0,
  kIdentity = 1,
  kTransaction = 2,
  kChannel = 3,
  kLocalSecret = 4,
  kContent = 5,
  kEvidence = 6,
  kMigration = 7,
};

// 匹配键里的方向/协议等维度
enum class Direction : uint8_t { kNone = 0, kInbound = 1, kOutbound = 2 };

constexpr uint32_t kMaxSessionDecisions = 8;

struct MatchKey {
  uint8_t category = 0;
  uint8_t operation = 0;       // 稳定的小整数 operation id
  uint8_t protocol = 0;        // 0 = 无协议
  uint8_t direction = 0;       // Direction
  uint8_t objectHash[16] = {0};  // 对象摘要（公钥/地址/消息摘要的前 16 字节）
  uint32_t sessionId = 0;
  uint8_t sessionEpoch = 0;
  uint32_t walletGeneration = 0;
  uint32_t backendGeneration = 0;
  uint32_t hostRunGeneration = 0;
};

enum class Decision : uint8_t { kUndecided = 0, kAllowOnce = 1, kDenyOnce = 2, kAllowSession = 3, kDenySession = 4 };

struct SessionDecision {
  bool active = false;
  Decision decision = Decision::kUndecided;
  MatchKey key{};
  uint32_t usedCount = 0;
  uint32_t maxCount = 0;   // 0 = 不限次数（仍受会话/连接约束）
  uint64_t budgetSats = 0; // 0 = 不限
  uint32_t createdMs = 0;
  uint8_t category = 0;
  char label[40] = {0};
};

enum class EvalResult : uint8_t {
  kNeedUser,     // 未决定，弹窗
  kAllowed,      // 命中会话允许
  kDenied,       // 命中会话否决（不再弹窗）
  kExhausted,    // 命中但超出限额，必须重新授权
};

class Policy {
 public:
  static void BeginSession(uint32_t deviceRunId, uint32_t sessionId, uint8_t epoch);
  // 锁定、断线、重启、会话关闭、迁移：清空全部持续决定
  static void ClearAll();
  static void ClearSession(uint32_t sessionId);
  static uint32_t decisionRevision();

  static EvalResult Evaluate(const MatchKey& key, uint8_t category, const char* label);
  // 本次允许/拒绝：仅影响本次，不写入持续决定
  static void RecordOnce(Direction direction);
  // 会话允许/否决由设备菜单调用
  static bool GrantSession(const MatchKey& key, uint8_t category, const char* label, uint32_t maxCount,
                           uint64_t budgetSats);
  static bool DenySession(const MatchKey& key, uint8_t category, const char* label);
  static bool CancelSession(uint32_t index);
  static bool CancelAll();

  static uint8_t Count();
  static bool Get(uint8_t index, SessionDecision* out);
  static const SessionDecision* LastOneShot();

  // 执行前复核：撤销后旧请求必须失败
  static bool Revalidate(const MatchKey& key);

 private:
  static int Find(const MatchKey& key);
  static bool SameScope(const MatchKey& a, const MatchKey& b);

  static SessionDecision s_[kMaxSessionDecisions];
  static uint8_t s_count_;
  static uint32_t s_revision_;
  static uint32_t s_deviceRunId_;
  static uint32_t s_sessionId_;
  static uint8_t s_epoch_;
  static Decision s_lastOnce_;
  static bool s_haveOnce_;
};

}  // namespace policy
}  // namespace rockey

#endif  // ROCKEY_POLICY_POLICY_H