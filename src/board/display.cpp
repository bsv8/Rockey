#include "board/display.h"

#include <TFT_eSPI.h>

namespace rockey {

Rect Rect::Intersect(const Rect& o) const {
  Rect r;
  int16_t x0 = x > o.x ? x : o.x;
  int16_t y0 = y > o.y ? y : o.y;
  int16_t x1 = (x + w) < (o.x + o.w) ? (x + w) : (o.x + o.w);
  int16_t y1 = (y + h) < (o.y + o.h) ? (y + h) : (o.y + o.h);
  r.x = x0;
  r.y = y0;
  r.w = x1 > x0 ? static_cast<int16_t>(x1 - x0) : 0;
  r.h = y1 > y0 ? static_cast<int16_t>(y1 - y0) : 0;
  return r;
}

namespace {

TFT_eSPI tft;
Rect g_clip;
Rect g_screen;
bool g_clipSet = false;

// 内置 ASCII 字库走 TFT_eSPI
void DrawBuiltin(uint8_t fontId, int16_t x, int16_t yTop, uint16_t cp, uint16_t fg, uint16_t bg,
                 const Rect& clip) {
  // TFT_eSPI 内置字库以左上为原点、行高 8/16
  int16_t h = (fontId == 4) ? 19 : (fontId == 2 ? 14 : 10);
  int16_t w = (fontId == 4) ? 12 : (fontId == 2 ? 10 : 6);
  if (!clip.Contains(x, yTop) && !clip.Contains(x, yTop + h - 1)) return;
  tft.setTextColor(fg, bg);
  tft.setTextFont(fontId);
  tft.drawChar(static_cast<uint16_t>(cp), x, yTop);
}

void DrawTableGlyph(const TableFont* tf, const TableGlyph& g, int16_t penX, int16_t lineTop,
                    uint16_t fg, uint16_t bg, const Rect& clip) {
  int16_t baselineY = static_cast<int16_t>(lineTop + tf->baseline);
  int16_t gx = static_cast<int16_t>(penX + g.xOffset);
  int16_t gy = static_cast<int16_t>(baselineY - g.yOffset);

  // 先擦净整个前进盒，避免残影；这也是"缺字"能被看见的方式
  Rect cell{penX, lineTop, g.xAdvance, static_cast<int16_t>(tf->yAdvance)};
  Rect vis = cell.Intersect(clip);
  if (vis.w > 0 && vis.h > 0) tft.fillRect(vis.x, vis.y, vis.w, vis.h, bg);

  for (uint8_t row = 0; row < g.height; ++row) {
    int16_t py = static_cast<int16_t>(gy + row);
    if (py < clip.y || py >= clip.y + clip.h) continue;
    for (uint8_t col = 0; col < g.width; ++col) {
      uint32_t bit = g.bitOffset + static_cast<uint32_t>(row) * g.width + col;
      if (bit >= g.bitOffset + g.bitLen) break;
      uint8_t byte = tf->bitmap[bit >> 3];
      bool on = (byte & (0x80u >> (bit & 7))) != 0;
      int16_t px = static_cast<int16_t>(gx + col);
      if (!on) continue;
      if (px < clip.x || px >= clip.x + clip.w) continue;
      tft.drawPixel(px, py, fg);
    }
  }
}

// 缺字占位：一个方框，明确表示"此处字库无此码位"
void DrawMissingMark(int16_t penX, int16_t lineTop, int advance, int16_t baselineY,
                     uint16_t fg, uint16_t bg, const Rect& clip) {
  Rect cell{penX, lineTop, advance, 0};
  cell.h = static_cast<int16_t>(advance);
  Rect vis = cell.Intersect(clip);
  if (vis.w > 0 && vis.h > 0) tft.fillRect(vis.x, vis.y, vis.w, vis.h, bg);
  int16_t x0 = static_cast<int16_t>(penX + advance / 4);
  int16_t x1 = static_cast<int16_t>(penX + advance - advance / 4 - 1);
  int16_t y0 = static_cast<int16_t>(baselineY - advance / 2);
  int16_t y1 = static_cast<int16_t>(baselineY + advance / 4);
  Rect box;
  box.x = x0;
  box.y = y0;
  box.w = static_cast<int16_t>(x1 - x0 + 1);
  box.h = static_cast<int16_t>(y1 - y0 + 1);
  Rect bv = box.Intersect(clip);
  if (bv.w > 0 && bv.h > 0) tft.drawRect(bv.x, bv.y, bv.w, bv.h, fg);
  Rect hline;
  hline.x = x0;
  hline.y = static_cast<int16_t>((y0 + y1) / 2);
  hline.w = static_cast<int16_t>(x1 - x0 + 1);
  hline.h = 1;
  Rect hv = hline.Intersect(clip);
  if (hv.w > 0) tft.fillRect(hv.x, hv.y, hv.w, 1, fg);
}

int AdvanceOne(FontRole role, uint32_t cp, int16_t* advanceOut) {
  const Font* f = FontGet(role);
  if (f->backend == FontBackend::kTable) {
    const TableGlyph* g = FontLookup(role, cp);
    if (g) { *advanceOut = g->xAdvance; return 1; }
    *advanceOut = f->table->missingAdvance;
    return 0;
  }
  if (cp >= 32 && cp <= 126) { *advanceOut = f->builtinId == 4 ? 12 : (f->builtinId == 2 ? 10 : 6); return 1; }
  *advanceOut = 12;
  return 0;
}

}  // namespace

void Display::Init() {
  tft.init();
  tft.setRotation(1);  // M5Stack Core BASIC v2.7：320x240 横屏
  tft.fillScreen(color::kBlack);
  g_screen = Rect{0, 0, tft.width(), tft.height()};
  g_clip = g_screen;
  g_clipSet = false;
}

void Display::SetBacklightCore(uint8_t duty) {
  if (duty > 255) duty = 255;
  analogWrite(32, duty);
}

int16_t Display::Width() { return tft.width(); }
int16_t Display::Height() { return tft.height(); }

void Display::Fill(const Rect& r, uint16_t c) {
  Rect v = g_clipSet ? r.Intersect(g_clip) : r;
  if (v.w > 0 && v.h > 0) tft.fillRect(v.x, v.y, v.w, v.h, c);
}

void Display::Frame(const Rect& r, uint16_t c) {
  if (r.w <= 0 || r.h <= 0) return;
  Rect v = g_clipSet ? r.Intersect(g_clip) : r;
  if (v.w <= 0 || v.h <= 0) return;
  tft.drawRect(v.x, v.y, v.w, v.h, c);
}

void Display::HLine(int16_t x, int16_t y, int16_t w, uint16_t c) { Fill(Rect{x, y, w, 1}, c); }
void Display::VLine(int16_t x, int16_t y, int16_t h, uint16_t c) { Fill(Rect{x, y, 1, h}, c); }
void Display::FillScreen(uint16_t c) { tft.fillScreen(c); }

int Display::DrawText(FontRole role, int16_t x, int16_t y, const char* s, size_t len, uint16_t fg,
                      uint16_t bg, const Rect* clip) {
  Rect c = clip ? (g_clipSet ? clip->Intersect(g_clip) : *clip) : (g_clipSet ? g_clip : g_screen);
  const Font* f = FontGet(role);
  int16_t penX = x;
  int16_t baselineY = static_cast<int16_t>(y + FontAscent(role));
  size_t i = 0;
  while (i < len && s[i]) {
    uint32_t cp = static_cast<uint8_t>(s[i]);
    size_t adv = 1;
    if (cp >= 0xF0) adv = 4;
    else if (cp >= 0xE0) adv = 3;
    else if (cp >= 0xC0) adv = 2;
    if (i + adv > len) break;

    int16_t a = 0;
    bool has = AdvanceOne(role, cp, &a) != 0;
    if (has) {
      if (f->backend == FontBackend::kTable) {
        const TableGlyph* g = FontLookup(role, cp);
        DrawTableGlyph(f->table, *g, penX, y, fg, bg, c);
      } else {
        DrawBuiltin(f->builtinId, penX, y, static_cast<uint16_t>(cp), fg, bg, c);
      }
    } else {
      DrawMissingMark(penX, y, a, baselineY, fg, bg, c);
    }
    penX = static_cast<int16_t>(penX + a);
    i += adv;
  }
  return penX - x;
}

int Display::MeasureText(FontRole role, const char* s, size_t len) {
  int w = 0;
  size_t i = 0;
  while (i < len && s[i]) {
    uint32_t cp = static_cast<uint8_t>(s[i]);
    size_t adv = 1;
    if (cp >= 0xF0) adv = 4;
    else if (cp >= 0xE0) adv = 3;
    else if (cp >= 0xC0) adv = 2;
    if (i + adv > len) break;
    int16_t a = 0;
    AdvanceOne(role, cp, &a);
    w += a;
    i += adv;
  }
  return w;
}

void Display::DrawTextIn(const Rect& box, FontRole role, const char* s, size_t len, uint16_t fg,
                         uint16_t bg, TextAlign hAlign, VAlign vAlign) {
  int lh = FontLineHeight(role);
  int16_t y = box.y;
  if (vAlign == VAlign::kMiddle) y = static_cast<int16_t>(box.y + (box.h - lh) / 2);
  else if (vAlign == VAlign::kBottom) y = static_cast<int16_t>(box.y + box.h - lh);
  int w = MeasureText(role, s, len);
  int16_t x = box.x;
  if (hAlign == TextAlign::kCenter) x = static_cast<int16_t>(box.x + (box.w - w) / 2);
  else if (hAlign == TextAlign::kRight) x = static_cast<int16_t>(box.x + box.w - w);
  DrawText(role, x, y, s, len, fg, bg, &box);
}

void Display::DrawProgress(const Rect& box, uint8_t percent, uint16_t fg, uint16_t bg) {
  Fill(box, bg);
  if (percent > 100) percent = 100;
  int16_t inner = static_cast<int16_t>((static_cast<int32_t>(box.w) * percent) / 100);
  if (inner > 0) Fill(Rect{box.x, box.y, inner, box.h}, fg);
  Frame(box, fg);
}

void Display::DrawFocusMark(int16_t x, int16_t y, int16_t h, uint16_t c) {
  Fill(Rect{x, y, 3, h}, c);
}

void DisplaySetClip(const Rect& r) {
  g_clip = r.Intersect(g_screen);
  g_clipSet = true;
}

void DisplayClearClip() {
  g_clip = g_screen;
  g_clipSet = false;
}

}  // namespace rockey