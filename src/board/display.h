// 屏幕绘制：直接写面板，按脏区重绘（无全屏缓冲），为 320x240 / 4MB 无 PSRAM
// 的 BASIC v2.7 保留 RAM。
#ifndef ROCKEY_BOARD_DISPLAY_H
#define ROCKEY_BOARD_DISPLAY_H

#include <stdint.h>
#include <stddef.h>

#include "ui/font.h"

namespace rockey {

struct Rect {
  int16_t x = 0, y = 0, w = 0, h = 0;
  bool Contains(int16_t px, int16_t py) const {
    return px >= x && px < x + w && py >= y && py < y + h;
  }
  Rect Intersect(const Rect& o) const;
};

namespace color {
constexpr uint16_t kBlack = 0x0000;
constexpr uint16_t kWhite = 0xFFFF;
constexpr uint16_t kRed = 0xF800;
constexpr uint16_t kGreen = 0x07E0;
constexpr uint16_t kBlue = 0x001F;
constexpr uint16_t kYellow = 0xFFE0;
constexpr uint16_t kCyan = 0x07FF;
constexpr uint16_t kMagenta = 0xF81F;
constexpr uint16_t kOrange = 0xFD20;
constexpr uint16_t kGray = 0x8410;
constexpr uint16_t kDarkGray = 0x4208;
constexpr uint16_t kDim = 0x2104;
}  // namespace color

enum class TextAlign : uint8_t { kLeft, kCenter, kRight };
enum class VAlign : uint8_t { kTop, kMiddle, kBottom };

class Display {
 public:
  static void Init();
  static void SetBacklightCore(uint8_t duty);
  static int16_t Width();
  static int16_t Height();

  static void Fill(const Rect& r, uint16_t c);
  static void Frame(const Rect& r, uint16_t c);
  static void HLine(int16_t x, int16_t y, int16_t w, uint16_t c);
  static void VLine(int16_t x, int16_t y, int16_t h, uint16_t c);
  static void FillScreen(uint16_t c);

  // 文本绘制。y 为行盒顶部。返回绘制宽度。裁剪到 clip（默认整屏）。
  static int DrawText(FontRole role, int16_t x, int16_t y, const char* s, size_t len,
                      uint16_t fg, uint16_t bg, const Rect* clip = nullptr);
  static int MeasureText(FontRole role, const char* s, size_t len);

  // 行盒内按对齐方式绘制
  static void DrawTextIn(const Rect& box, FontRole role, const char* s, size_t len, uint16_t fg,
                         uint16_t bg, TextAlign hAlign, VAlign vAlign);

  // 进度条（长按确认进度）
  static void DrawProgress(const Rect& box, uint8_t percent, uint16_t fg, uint16_t bg);

  // 圆角感列表焦点标记
  static void DrawFocusMark(int16_t x, int16_t y, int16_t h, uint16_t c);
};

// 全局绘制裁剪（阅读页滚动窗口用）
void DisplaySetClip(const Rect& r);
void DisplayClearClip();

}  // namespace rockey

#endif  // ROCKEY_BOARD_DISPLAY_H