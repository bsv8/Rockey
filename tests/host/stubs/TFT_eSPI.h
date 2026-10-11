// TFT_eSPI 的最小替身，只为语法检查。成员签名对齐 display.cpp 的用法。
#ifndef ROCKEY_STUB_TFT_ESPI_H
#define ROCKEY_STUB_TFT_ESPI_H

#include <stdint.h>

#include <Arduino.h>

class TFT_eSPI {
 public:
  void init();
  void setRotation(uint8_t r);
  int16_t width() const;
  int16_t height() const;
  void fillScreen(uint16_t c);
  void fillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t c);
  void drawRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t c);
  void drawPixel(int16_t x, int16_t y, uint16_t c);
  void setTextColor(uint16_t fg, uint16_t bg);
  void setTextFont(uint8_t f);
  void drawChar(uint16_t c, int32_t x, int32_t y);
  void drawChar(int32_t x, int32_t y, uint16_t c, uint32_t fg, uint32_t bg, uint8_t size);
};

#endif  // ROCKEY_STUB_TFT_ESPI_H
