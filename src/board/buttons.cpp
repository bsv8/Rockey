#include "board/buttons.h"
#include "board/board.h"

#include <Arduino.h>

namespace rockey {
namespace {
constexpr uint8_t kPin[3] = {Board::kPinBtnA, Board::kPinBtnB, Board::kPinBtnC};
}  // namespace

void Buttons::Init(const BtnConfig& cfg) {
  cfg_ = cfg;
  for (int i = 0; i < 3; ++i) {
    pinMode(kPin[i], INPUT_PULLUP);
    slots_[i] = Slot{};
    slots_[i].raw = digitalRead(kPin[i]) != LOW;
    slots_[i].stable = slots_[i].raw;
    slots_[i].changeMs = millis();
  }
  gate_ = false;
}

void Buttons::Poll(uint32_t nowMs) {
  for (int i = 0; i < 3; ++i) {
    Slot& s = slots_[i];
    bool level = digitalRead(kPin[i]) != LOW;  // true = 松开
    if (level != s.raw) {
      s.raw = level;
      s.changeMs = nowMs;
      continue;
    }
    if (s.raw == s.stable) continue;
    if (nowMs - s.changeMs < cfg_.debounceMs) continue;

    s.stable = s.raw;
    if (gate_) continue;  // 栅栏期间不产生按压事件

    if (!s.stable) {
      // 按下
      s.downMs = nowMs;
      s.longFired = false;
      s.repeatPending = false;
      s.repeatMs = cfg_.repeatStartMs;
      s.repeatNextMs = nowMs + cfg_.longPressMs + cfg_.repeatStartMs;
    } else {
      // 松开
      s.event = s.longFired ? BtnEvent::kRelease : BtnEvent::kShortPress;
      s.eventPending = true;
      s.repeatPending = false;
    }
  }
}

BtnEvent Buttons::NextEvent(Btn btn, uint32_t nowMs) {
  Slot& s = slots_[static_cast<int>(btn)];
  if (gate_) return BtnEvent::kNone;

  if (!s.stable && !s.longFired && (nowMs - s.downMs) >= cfg_.longPressMs) {
    s.longFired = true;
    s.event = BtnEvent::kLongPress;
    s.eventPending = true;
    s.repeatPending = true;
  }
  if (s.repeatPending && !s.stable && nowMs >= s.repeatNextMs) {
    s.repeatPending = false;
    s.event = BtnEvent::kHoldRepeat;
    s.eventPending = true;
    // 速度渐进但封顶
    s.repeatMs = s.repeatMs > cfg_.repeatMinMs + 40
                     ? static_cast<uint16_t>(s.repeatMs - 30)
                     : cfg_.repeatMinMs;
    s.repeatNextMs = nowMs + s.repeatMs;
  }

  if (s.eventPending) {
    s.eventPending = false;
    BtnEvent e = s.event;
    s.event = BtnEvent::kNone;
    return e;
  }
  return BtnEvent::kNone;
}

bool Buttons::IsDown(Btn btn) const { return !slots_[static_cast<int>(btn)].stable; }
bool Buttons::AnyDown() const {
  for (int i = 0; i < 3; ++i) {
    if (!slots_[i].stable) return true;
  }
  return false;
}

void Buttons::ArmReleaseGate() {
  gate_ = true;
  for (int i = 0; i < 3; ++i) {
    slots_[i].longFired = false;
    slots_[i].repeatPending = false;
    slots_[i].eventPending = false;
    slots_[i].event = BtnEvent::kNone;
  }
}

bool Buttons::GateSatisfied() const {
  for (int i = 0; i < 3; ++i) {
    if (!slots_[i].stable) return false;
  }
  return true;
}

bool Buttons::GateActive() const { return gate_ && !GateSatisfied(); }

void Buttons::ClearGateIfSatisfied() {
  if (gate_ && GateSatisfied()) gate_ = false;
}

}  // namespace rockey