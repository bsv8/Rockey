// 无图片、无新字库、无全屏缓冲；启动绘制不依赖存储、USB 或密码学初始化。
#pragma once
#include <cstring>
#include "board/display.h"

namespace rockey::ui {
inline void DrawBootPoster() {
  Display::FillScreen(color::kBlack);
  // 不透明底纹先画，后续文字只画前景，投影不会被字形背景擦除。
  Display::Frame({14, 14, 292, 212}, color::kDim);
  for (int i = 0; i < 8; ++i)
    Display::HLine(220 + i * 5, 36 + i * 5, 46 - i * 3, color::kDarkGray);
  Display::DrawAsciiArt(FontRole::kMono, 30, 32, "PRIVATE BY DESIGN", color::kGray, 1);
  const Font* font = FontGet(FontRole::kMono);
  const int unit = font->backend == FontBackend::kTable
      ? Display::MeasureText(FontRole::kMono, "ROCKEY", 6) : 36;
  const int x = (320 - unit * 3 - 7) / 2;
  for (int offset = 6; offset >= 2; --offset)
    Display::DrawAsciiArt(FontRole::kMono, x + offset, 76 + offset,
                           "ROCKEY", color::kDarkGray, 3, 7);
  Display::DrawAsciiArt(FontRole::kMono, x, 76, "ROCKEY", color::kCyan, 3, 7);
  Display::HLine(30, 139, 260, color::kCyan);
  Display::HLine(30, 142, 80, color::kDarkGray);
  Display::DrawAsciiArt(FontRole::kMono, 30, 155, "HARDWARE WALLET", color::kWhite, 1);
  Display::DrawAsciiArt(FontRole::kMono, 30, 195, "STARTING / SELF CHECK", color::kGray, 1);
  Display::Fill({277, 199, 6, 6}, color::kCyan);
}

// 设置、重复确认、解锁共用同一轮盘。当前位直接绘制 cursor，
// 避免字符数组偏移或长度错误导致按键有效但屏幕始终显示 0。
inline void DrawPinRow(uint8_t digits, uint8_t entered, uint8_t cursor,
                       const char* pin, int y, bool cursorOnly=false) {
  if (!digits) return;
  const int step = (320 - 40) / digits;
  const int height = FontLineHeight(FontRole::kSmall);
  for (uint8_t i = 0; i < digits; ++i) {
    if(cursorOnly&&i!=entered)continue;
    const Rect cell{16 + i * step, y, step - 4, height};
    const bool current = i == entered;
    const char digit = current ? static_cast<char>('0' + cursor)
                              : (i < entered ? pin[i] : ' ');
    Display::Fill(cell, color::kBlack);
    if (current) Display::Frame(cell, color::kYellow);
    Display::DrawTextIn(cell, FontRole::kSmall, &digit, 1,
                       current ? color::kYellow : color::kWhite,
                       color::kBlack, TextAlign::kCenter, VAlign::kMiddle);
  }
}
}  // namespace rockey::ui
