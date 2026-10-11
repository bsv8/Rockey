#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>
namespace rockey::vlp {
struct Approval {
  enum State { Pending, Denied, Once, Raise, AllowSession, DenySession } state=Pending;
  uint64_t limit=0;
  bool pin_verified=false;
};
struct Review {
  std::string operation,channel,owner;
  std::vector<std::pair<std::string,std::string>> facts;
  bool can_raise=false;
  uint64_t minimum_limit=0;
  bool can_remember=false;
  bool requires_pin=false;
  bool creates_pin=false;
};
// Only firmware button handling may produce Approval. There is no USB field
// that supplies a PIN verification or an approve/deny boolean.
struct ApprovalUI {
  virtual void automatically_approved(const Review&) {}
  virtual void begin(const Review&)=0;
  virtual Approval decision()=0;
  virtual void clear()=0;
  virtual ~ApprovalUI()=default;
};
} // namespace rockey::vlp
