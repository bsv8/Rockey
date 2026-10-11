#include "board/board.h"
#include "board/display.h"
#include "core/rockey_config.h"

#include <Arduino.h>

namespace rockey {
#if defined(ROCKEY_DEV_BUTTON_API)
namespace { volatile uint32_t serial_errors = 0; }
uint32_t Board::DevSerialErrors() { return serial_errors; }
#endif

bool Board::Init() {
  // 一个 VLP 分片可超过默认 256-byte UART RX 缓冲。屏幕绘制与原子
  // Flash 提交期间也要容纳已在传输的帧，避免截断密文后心跳超时。
  Serial.setRxBufferSize(8192);
  Serial.begin(kUsbSerialBaud);
  Serial.setRxFIFOFull(16);
#if defined(ROCKEY_DEV_BUTTON_API)
  Serial.onReceiveError([](hardwareSerial_error_t error) { serial_errors |= uint32_t(1) << unsigned(error); });
#endif
  // 当前实测 CP2104 设备使用 115200；板型名称不代表 USB 桥的实际版本。
  Display::Init();
  Display::SetBacklightCore(255);
  return true;
}

void Board::BacklightOn() { SetBacklight(255); }
void Board::BacklightOff() { SetBacklight(0); }

void Board::SetBacklight(uint8_t duty) { Display::SetBacklightCore(duty); }

uint32_t Board::FreeHeap() { return ESP.getFreeHeap(); }

const char* Board::BoardName() { return "m5stack-core-basic-v2.7"; }

}  // namespace rockey
