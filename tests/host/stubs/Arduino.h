// 主机侧语法检查用的 Arduino 替身。
//
// 目的只有一个：让 src/ 里的真实实现能在没有 ESP32 工具链的机器上做
// -fsyntax-only 检查，从而抓到窄化转换、缺成员、拼错枚举这类编译期错误。
// 这里的定义不参与真机构建，也不代表任何运行时行为。
#ifndef ROCKEY_STUB_ARDUINO_H
#define ROCKEY_STUB_ARDUINO_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long millis();
unsigned long micros();
void delay(unsigned long ms);
void delayMicroseconds(unsigned int us);
void pinMode(uint8_t pin, uint8_t mode);
void digitalWrite(uint8_t pin, uint8_t value);
int digitalRead(uint8_t pin);
int analogRead(uint8_t pin);
void analogWrite(uint8_t pin, int value);
void analogSetPinAttenuation(uint8_t pin, uint8_t att);
uint32_t analogReadMilliVolts(uint8_t pin);

// ADC 衰减枚举：对应 esp32-hal-adc.h 的 adc_attenuation_t。
// 真机构建时以此处的取值为准，改动必须回填到板级冻结记录。
#define ADC_11db 3

class EspClass {
 public:
  uint32_t getFreeHeap();
  uint32_t getMinFreeHeap();
  uint32_t getHeapSize();
  void restart();
};

extern EspClass ESP;

#define INPUT 0
#define OUTPUT 1
#define INPUT_PULLUP 2
#define LOW 0
#define HIGH 1

class SerialStub {
 public:
  void begin(unsigned long baud);
  // Signature-only host compile surface; actual UART behavior is checked on ESP32.
  size_t setRxBufferSize(size_t size);
  bool setRxFIFOFull(uint8_t threshold);
  int available();
  int read();
  int readBytes(uint8_t* buf, size_t len);
  size_t write(const uint8_t* buf, size_t len);
  size_t print(const char* s);
  size_t println(const char* s);
};

extern SerialStub Serial;

// Arduino-ESP32 里 Serial1/Serial2 的类型；替身下用 SerialStub 顶替
class HardwareSerial {
 public:
  explicit HardwareSerial(int uartNum = 0);
  SerialStub& ref();
};

#endif  // ROCKEY_STUB_ARDUINO_H
