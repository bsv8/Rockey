// M5Stack Core BASIC v2.7 板级定义。
//
// 冻结依据：docs/冻结/硬件清单.md（ESP32-D0WDQ6 / ILI9341 320x240 /
// 三实体按钮 GPIO39/38/37 / USB 转串口 CP2104 / 无 PSRAM）。
#ifndef ROCKEY_BOARD_BOARD_H
#define ROCKEY_BOARD_BOARD_H

#include <stdint.h>

namespace rockey {

struct Board {
  // ── 引脚 ──────────────────────────────────────────────────────
  static constexpr uint8_t kPinBtnA = 39;
  static constexpr uint8_t kPinBtnB = 38;
  static constexpr uint8_t kPinBtnC = 37;
  static constexpr uint8_t kPinBacklight = 32;
  static constexpr uint8_t kPinSda = 21;
  static constexpr uint8_t kPinScl = 22;

  // ── 屏幕 ──────────────────────────────────────────────────────
  static constexpr int16_t kScreenW = 320;
  static constexpr int16_t kScreenH = 240;
  static constexpr uint8_t kRotation = 1;

  // ── 布局 ──────────────────────────────────────────────────────
  static constexpr int16_t kHeaderH = 26;
  static constexpr int16_t kFooterH = 30;
  static constexpr int16_t kContentY = kHeaderH;
  static constexpr int16_t kContentH = kScreenH - kHeaderH - kFooterH;
  static constexpr int16_t kFooterY = kScreenH - kFooterH;

  // ── 电源 ──────────────────────────────────────────────────────
  // 标准配置没有接入物理 VBUS 信号，串口活跃度只用于通讯会话，
  // 电池/关机由用户与硬件处理，不采集电量。协议失活只撤销会话，通电期间不自动锁定。
  static constexpr uint32_t kUsbSerialBaud = 115200;

  static bool Init();
  static void BacklightOn();
  static void BacklightOff();
  static void SetBacklight(uint8_t duty);  // 0-255
  static uint32_t FreeHeap();
#if defined(ROCKEY_DEV_BUTTON_API)
  static uint32_t DevSerialErrors();
#endif
  static const char* BoardName();
};

}  // namespace rockey

#endif  // ROCKEY_BOARD_BOARD_H
