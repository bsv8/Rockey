// 三实体按钮：去抖、短按/长按/按住重复，以及换页松键栅栏。
//
// 对应需求 §3 / §6.2：
//  - 短按、长按、按住连续调整三者互斥，一个按压只产生一个短按或一个长按；
//  - 页面切换后必须先松键才接受新按压，避免上一页的长按延续到新页面误确认；
//  - 松键栅栏期间不产生任何事件，但按键状态仍被跟踪，栅栏一解除即可工作。
#ifndef ROCKEY_BOARD_BUTTONS_H
#define ROCKEY_BOARD_BUTTONS_H

#include <stdint.h>

namespace rockey {

enum class Btn : uint8_t { kA = 0, kB = 1, kC = 2, kCount = 3 };

enum class BtnEvent : uint8_t {
  kNone,
  kShortPress,  // 按下到松开短于长按阈值
  kLongPress,   // 达到长按阈值，仅一次；确认页据此开始长按进度
  kHoldRepeat,  // 长按后的连续重复（速度封顶）
  kRelease,     // 松开（长按/重复之后也发出一次）
};

struct BtnConfig {
  uint16_t debounceMs = 25;
  uint16_t longPressMs = 550;
  uint16_t repeatStartMs = 400;   // 长按后首次重复延迟
  uint16_t repeatMinMs = 110;     // 连续调整速度上限
  uint16_t repeatMaxMs = 400;
};

class Buttons {
 public:
  void Init(const BtnConfig& cfg);
  void Poll(uint32_t nowMs);                 // 主循环调用，采集去抖后的电平
  BtnEvent NextEvent(Btn btn, uint32_t nowMs);  // 取出一次事件
  bool IsDown(Btn btn) const;
  bool AnyDown() const;

  // 松键栅栏：要求所有按钮松开后才重新接受按压
  void ArmReleaseGate();
  bool GateSatisfied() const;   // 已全部松开
  bool GateActive() const;      // 仍处于栅栏状态
  void ClearGateIfSatisfied();

  const BtnConfig& config() const { return cfg_; }

 private:
  struct Slot {
    bool raw = true;        // 原始（未去抖）电平，true = 松开
    bool stable = true;
    uint32_t changeMs = 0;
    uint32_t downMs = 0;
    bool longFired = false;
    bool repeatPending = false;
    uint32_t repeatNextMs = 0;
    uint16_t repeatMs = 0;
    bool eventPending = false;
    BtnEvent event = BtnEvent::kNone;
  };

  BtnConfig cfg_{};
  Slot slots_[3]{};
  bool gate_ = false;
};

}  // namespace rockey

#endif  // ROCKEY_BOARD_BUTTONS_H