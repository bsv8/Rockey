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
  static constexpr uint8_t kPinVbatAdc = 35;  // ADC1_CH7，经分压
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
  // BASIC v2.7 无 PMIC / 无 VBUS 感知线：USB 在位由传输层活跃度判断，
  // 电量由 ADC 分压估算。失活锁定一律走协议层 liveness 超时。
  static constexpr uint32_t kUsbSerialBaud = 115200;

  static bool Init();
  static void BacklightOn();
  static void BacklightOff();
  static void SetBacklight(uint8_t duty);  // 0-255
  static uint16_t BatteryMilliVolt();
  // 仅供 UI 指示电量；不作为任何授权或时效依据（无可信时钟）
  static uint8_t BatteryPercent();
  static uint32_t FreeHeap();
  static const char* BoardName();
};

}  // namespace rockey

#endif  // ROCKEY_BOARD_BOARD_H