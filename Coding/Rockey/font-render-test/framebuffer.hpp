#pragma once
// Software framebuffer for the actual product renderer. Only the TFT output
// surface is replaced; decoding, font lookup, placement and clipping stay real.
#include <TFT_eSPI.h>
#include "board/display.h"
#include "../device-ui/presentation.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
static unsigned long fullScreenRedraws = 0;
static unsigned long fullScreenFills = 0;
static void (*onFullScreenClear)() = nullptr;
static std::array<unsigned char, 320 * 240> pixels;
static std::array<uint16_t, 320 * 240> colors;
static void point(int x, int y, uint16_t color) {
  if (x >= 0 && y >= 0 && x < 320 && y < 240) {
    pixels[y * 320 + x] = color ? 255 : 0;
    colors[y * 320 + x] = color;
  }
}
void TFT_eSPI::init() {}
void TFT_eSPI::setRotation(uint8_t) {}
int16_t TFT_eSPI::width() const { return 320; }
int16_t TFT_eSPI::height() const { return 240; }
void TFT_eSPI::fillScreen(uint16_t c) { if(onFullScreenClear)onFullScreenClear(); ++fullScreenRedraws; pixels.fill(c ? 255 : 0); colors.fill(c); }
void TFT_eSPI::fillRect(int16_t x,int16_t y,int16_t w,int16_t h,uint16_t c) {
  if(x==0&&y==0&&w==320&&h==240)++fullScreenFills;
  for (int row=y; row<y+h; ++row) for (int col=x; col<x+w; ++col) point(col,row,c);
}
void TFT_eSPI::drawRect(int16_t x,int16_t y,int16_t w,int16_t h,uint16_t c) {
  for(int i=0;i<w;++i){point(x+i,y,c);point(x+i,y+h-1,c);}
  for(int i=0;i<h;++i){point(x,y+i,c);point(x+w-1,y+i,c);}
}
void TFT_eSPI::drawPixel(int16_t x,int16_t y,uint16_t c) { point(x,y,c); }
void TFT_eSPI::setTextColor(uint16_t,uint16_t) {}
void TFT_eSPI::setTextFont(uint8_t) {}
void TFT_eSPI::drawChar(uint16_t,int32_t,int32_t) { std::abort(); }
void TFT_eSPI::drawChar(int32_t,int32_t,uint16_t,uint32_t,uint32_t,uint8_t) { std::abort(); }
void analogWrite(uint8_t,int) {}
