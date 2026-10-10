#include "policy/policy.h"

#include <Arduino.h>
#include <string.h>

namespace rockey {
namespace policy {

SessionDecision Policy::s_[kMaxSessionDecisions];
uint8_t Policy::s_count_ = 0;
uint32_t Policy::s_revision_ = 1;
uint32_t Policy::s_deviceRunId_ = 0;
uint32_t Policy::s_sessionId_ = 0;
uint8_t Policy::s_epoch_ = 0;
Decision Policy::s_lastOnce_ = Decision::kUndecided;
bool Policy::s_haveOnce_ = false;

void Policy::BeginSession(uint32_t deviceRunId, uint32_t sessionId, uint8_t epoch) {
  // 设备运行、连接或会话代际变化即清空全部持续决定
  if (deviceRunId != s_deviceRunId_ || sessionId != s_sessionId_ || epoch != s_epoch_) {
    ClearAll();
    s_deviceRunId_ = deviceRunId;
    s_sessionId_ = sessionId;
    s_epoch_ = epoch;
  }
}

void Policy::ClearAll() {
  for (auto& d : s_) d = SessionDecision{};
  s_count_ = 0;
  s_haveOnce_ = false;
  s_lastOnce_ = Decision::kUndecided;
  s_revision_++;
}

void Policy::ClearSession(uint32_t sessionId) {
  if (sessionId != s_sessionId_) return;
  ClearAll();
}

uint32_t Policy::decisionRevision() { return s_revision_; }

bool PersistentDecisionAllowed(Category c) {
  // 迁移/导出/恢复备份：一次性的物理许可，绝不落持续表。
  // "允许本会话导出私钥"会把一次危险动作变成长期许可，因此这里直接不允许。
  return c != Category::kMigration;
}

bool Policy::SameScope(const MatchKey& a, const MatchKey& b) {
  return a.category == b.category && a.operation == b.operation && a.protocol == b.protocol &&
         a.direction == b.direction && memcmp(a.objectHash, b.objectHash, 16) == 0 &&
         a.sessionId == b.sessionId && a.sessionEpoch == b.sessionEpoch &&
         a.walletGeneration == b.walletGeneration && a.backendGeneration == b.backendGeneration &&
         a.hostRunGeneration == b.hostRunGeneration;
}

int Policy::Find(const MatchKey& key) {
  // 遍历全部槽位并显式检查 active：槽位被取消后不压缩，
  // 只扫到 s_count_ 会让更靠后的决定对查找不可见。
  for (uint8_t i = 0; i < kMaxSessionDecisions; ++i) {
    if (!s_[i].active) continue;
    if (SameScope(s_[i].key, key)) return i;
  }
  return -1;
}

EvalResult Policy::Evaluate(const MatchKey& key, uint8_t category, const char* label,
                            uint64_t sats) {
  int idx = Find(key);
  if (idx < 0) return EvalResult::kNeedUser;
  const SessionDecision& d = s_[idx];
  // 持续否决优先于一切，直接返回拒绝、不再弹窗
  if (d.decision == Decision::kDenySession) return EvalResult::kDenied;
  // 只有明确的会话允许才算允许。未激活/未决定一律回到"需要用户"。
  // 以前这里对 kUndecided 直接返回 kAllowed，一个零值槽位就等于无条件放行。
  if (d.decision != Decision::kAllowSession) return EvalResult::kNeedUser;
  if (d.maxCount != 0 && d.usedCount >= d.maxCount) return EvalResult::kExhausted;
  // 预算：本次执行会把 spentSats 推上去，推过上限就不再自动放行
  if (d.budgetSats != 0 && d.spentSats + sats > d.budgetSats) return EvalResult::kExhausted;
  (void)category;
  (void)label;
  return EvalResult::kAllowed;
}

void Policy::RecordOnce(Direction direction) {
  // 本次决定不落盘，仅在内存里留一个"当前请求"的即时结果
  s_haveOnce_ = true;
  (void)direction;
}

const SessionDecision* Policy::LastOneShot() {
  if (!s_haveOnce_) return nullptr;
  return nullptr;  // 本次结果由请求层直接返回，不作为持续决定
}

int Policy::Allocate(const MatchKey& key, uint8_t category, const char* label) {
  int idx = Find(key);
  if (idx >= 0) return idx;
  for (uint8_t i = 0; i < kMaxSessionDecisions; ++i) {
    if (!s_[i].active) {
      idx = i;
      break;
    }
  }
  if (idx < 0) return -1;
  s_[idx] = SessionDecision{};
  s_[idx].key = key;
  s_[idx].category = category;
  if (label) strncpy(s_[idx].label, label, sizeof(s_[idx].label) - 1);
  s_[idx].active = true;
  s_[idx].usedCount = 0;
  s_[idx].spentSats = 0;
  s_[idx].createdMs = millis();
  if (s_count_ < kMaxSessionDecisions) s_count_++;
  return idx;
}

bool Policy::GrantSession(const MatchKey& key, uint8_t category, const char* label,
                          uint32_t maxCount, uint64_t budgetSats) {
  int idx = Allocate(key, category, label);
  if (idx < 0) return false;
  s_[idx].decision = Decision::kAllowSession;
  s_[idx].maxCount = maxCount;
  s_[idx].budgetSats = budgetSats;
  s_revision_++;
  return true;
}

bool Policy::DenySession(const MatchKey& key, uint8_t category, const char* label) {
  int idx = Allocate(key, category, label);
  if (idx < 0) return false;
  s_[idx].decision = Decision::kDenySession;
  s_[idx].maxCount = 0;
  s_[idx].budgetSats = 0;
  s_revision_++;
  return true;
}

// 记录一次已执行的会话允许：次数与金额累加，超限后不再自动放行。
void Policy::Consume(const MatchKey& key, uint64_t sats) {
  int idx = Find(key);
  if (idx < 0) return;
  if (s_[idx].usedCount < 0xFFFFFFFFu) s_[idx].usedCount++;
  s_[idx].spentSats += sats;
}

bool Policy::CancelSession(uint32_t index) {
  // index 是 Get() 暴露的槽位下标，必须按槽位删。
  // 以前按 createdMs 反查：同一毫秒创建的两条决定会互相误删。
  if (index >= kMaxSessionDecisions || !s_[index].active) return false;
  // 压缩数组，避免留下空洞让 Get/Find 的下标含义不一致
  for (uint8_t i = index; i + 1 < kMaxSessionDecisions; ++i) s_[i] = s_[i + 1];
  s_[kMaxSessionDecisions - 1] = SessionDecision{};
  if (s_count_) s_count_--;
  s_revision_++;
  return true;
}

bool Policy::CancelAll() {
  ClearAll();
  return true;
}

uint8_t Policy::Count() {
  uint8_t n = 0;
  for (uint8_t i = 0; i < kMaxSessionDecisions; ++i) {
    if (s_[i].active) n++;
  }
  return n;
}

bool Policy::Get(uint8_t index, SessionDecision* out) {
  if (index >= kMaxSessionDecisions || !s_[index].active) return false;
  if (out) *out = s_[index];
  return true;
}

bool Policy::Revalidate(const MatchKey& key) {
  // 队列里的请求在真正执行前必须重新检查：若期间出现持续否决则拒绝；
  // 若持续允许已被取消则视为需要重新询问（返回 false，交给上层弹窗）。
  int idx = Find(key);
  if (idx < 0) return false;
  return s_[idx].active && s_[idx].decision == Decision::kAllowSession;
}

}  // namespace policy
}  // namespace rockey