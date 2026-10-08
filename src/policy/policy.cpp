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

bool Policy::SameScope(const MatchKey& a, const MatchKey& b) {
  return a.category == b.category && a.operation == b.operation && a.protocol == b.protocol &&
         a.direction == b.direction && memcmp(a.objectHash, b.objectHash, 16) == 0 &&
         a.sessionId == b.sessionId && a.sessionEpoch == b.sessionEpoch &&
         a.walletGeneration == b.walletGeneration && a.backendGeneration == b.backendGeneration &&
         a.hostRunGeneration == b.hostRunGeneration;
}

int Policy::Find(const MatchKey& key) {
  for (uint8_t i = 0; i < s_count_; ++i) {
    if (SameScope(s_[i].key, key)) return i;
  }
  return -1;
}

EvalResult Policy::Evaluate(const MatchKey& key, uint8_t category, const char* label) {
  int idx = Find(key);
  if (idx < 0) return EvalResult::kNeedUser;
  const SessionDecision& d = s_[idx];
  if (d.decision == Decision::kDenySession) return EvalResult::kDenied;
  if (d.decision == Decision::kAllowSession) {
    if (d.maxCount != 0 && d.usedCount >= d.maxCount) return EvalResult::kExhausted;
    if (d.budgetSats != 0 && d.budgetSats < 1) return EvalResult::kExhausted;
  }
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

bool Policy::GrantSession(const MatchKey& key, uint8_t category, const char* label,
                          uint32_t maxCount, uint64_t budgetSats) {
  int idx = Find(key);
  if (idx < 0) {
    for (uint8_t i = 0; i < kMaxSessionDecisions; ++i) {
      if (!s_[i].active) {
        idx = i;
        break;
      }
    }
    if (idx < 0) return false;
    s_[idx] = SessionDecision{};
    s_[idx].key = key;
    s_[idx].category = category;
    if (label) {
      strncpy(s_[idx].label, label, sizeof(s_[idx].label) - 1);
    }
    if (s_count_ < kMaxSessionDecisions) s_count_++;
  }
  s_[idx].active = true;
  s_[idx].decision = Decision::kAllowSession;
  s_[idx].maxCount = maxCount;
  s_[idx].budgetSats = budgetSats;
  s_[idx].usedCount = 0;
  s_[idx].createdMs = millis();
  s_revision_++;
  return true;
}

bool Policy::DenySession(const MatchKey& key, uint8_t category, const char* label) {
  int idx = Find(key);
  if (idx < 0) {
    for (uint8_t i = 0; i < kMaxSessionDecisions; ++i) {
      if (!s_[i].active) {
        idx = i;
        break;
      }
    }
    if (idx < 0) return false;
    s_[idx] = SessionDecision{};
    s_[idx].key = key;
    s_[idx].category = category;
    if (label) strncpy(s_[idx].label, label, sizeof(s_[idx].label) - 1);
    if (s_count_ < kMaxSessionDecisions) s_count_++;
  }
  s_[idx].active = true;
  s_[idx].decision = Decision::kDenySession;
  s_[idx].maxCount = 0;
  s_[idx].budgetSats = 0;
  s_[idx].usedCount = 0;
  s_[idx].createdMs = millis();
  s_revision_++;
  return true;
}

bool Policy::CancelSession(uint32_t index) {
  if (index >= s_count_) return false;
  for (uint8_t i = 0; i < kMaxSessionDecisions; ++i) {
    if (s_[i].active && s_[i].createdMs == s_[index].createdMs) {
      s_[i] = SessionDecision{};
      s_revision_++;
      if (s_count_) s_count_--;
      return true;
    }
  }
  return false;
}

bool Policy::CancelAll() {
  ClearAll();
  return true;
}

uint8_t Policy::Count() { return s_count_; }

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
  return s_[idx].decision == Decision::kAllowSession;
}

}  // namespace policy
}  // namespace rockey