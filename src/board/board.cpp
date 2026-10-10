#include "board/board.h"
#include "board/display.h"

#include <Arduino.h>

namespace rockey {
#if defined(ROCKEY_DEV_BUTTON_API)
namespace { volatile uint32_t serial_errors = 0; }
uint32_t Board::DevSerialErrors() { return serial_errors; }
#endif

bool Board::Init() {
  pinMode(kPinVbatAdc, INPUT);
  analogSetPinAttenuation(kPinVbatAdc, ADC_11db);
  // 一个 VLP 分片可超过默认 256-byte UART RX 缓冲。屏幕绘制与原子
  // Flash 提交期间也要容纳已在传输的帧，避免截断密文后心跳超时。
  Serial.setRxBufferSize(8192);
  Serial.begin(kUsbSerialBaud);
  Serial.setRxFIFOFull(16);
#if defined(ROCKEY_DEV_BUTTON_API)
  Serial.onReceiveError([](hardwareSerial_error_t error) { serial_errors |= uint32_t(1) << unsigned(error); });
#endif
  // BASIC v2.7 的 USB 桥是 CP2104：115200 是唯一稳定点，不尝试热插拔枚举。
  Display::Init();
  Display::SetBacklightCore(255);
  return true;
}

void Board::BacklightOn() { SetBacklight(255); }
void Board::BacklightOff() { SetBacklight(0); }

void Board::SetBacklight(uint8_t duty) { Display::SetBacklightCore(duty); }

uint16_t Board::BatteryMilliVolt() {
  // 分压比 2:1（100k/100k），ADC 满量程约 3100mV @ 11dB
  uint32_t mv = analogReadMilliVolts(kPinVbatAdc);
  uint32_t battery = mv * 2;
  return static_cast<uint16_t>(battery > 60000 ? 60000 : battery);
}

uint8_t Board::BatteryPercent() {
  uint16_t mv = BatteryMilliVolt();
  if (mv <= 3400) return 0;
  if (mv >= 4200) return 100;
  // 2.8V-4.2V 线性近似，仅用于电量图标
  return static_cast<uint8_t>((mv - 3400) * 100 / 800);
}

uint32_t Board::FreeHeap() { return ESP.getFreeHeap(); }

const char* Board::BoardName() { return "m5stack-core-basic-v2.7"; }

}  // namespace rockey
