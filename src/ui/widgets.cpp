#include "ui/widgets.h"

#include <stdio.h>
#include <string.h>

#include "i18n/i18n.h"

#include "ui/text.h"

namespace rockey {
namespace ui {
namespace {

Rect HeaderRect() { return Rect{0, 0, Board::kScreenW, Board::kHeaderH}; }
Rect FooterRect() { return Rect{0, Board::kFooterY, Board::kScreenW, Board::kFooterH}; }
Rect ContentRect() {
  return Rect{0, Board::kContentY, Board::kScreenW, Board::kContentH};
}

}  // namespace

void DrawHeader(const char* title, const char* rightHint) {
  Rect r = HeaderRect();
  Display::Fill(r, color::kDim);
  int h = FontLineHeight(FontRole::kSmall);
  Rect titleBox{r.x + 4, r.y, r.w - 8, r.h};
  Display::DrawTextIn(titleBox, FontRole::kSmall, title, title ? strlen(title) : 0, color::kWhite,
                      color::kDim, TextAlign::kLeft, VAlign::kMiddle);
  if (rightHint && rightHint[0]) {
    Rect hintBox{r.x + r.w - 120, r.y, 116, r.h};
    Display::DrawTextIn(hintBox, FontRole::kSmall, rightHint, strlen(rightHint), color::kCyan,
                        color::kDim, TextAlign::kRight, VAlign::kMiddle);
  }
  Display::HLine(0, r.y + r.h - 1, r.w, color::kBlue);
  (void)h;
}

void DrawFooter(const char* leftLabel, const char* midLabel, const char* rightLabel) {
  Rect r = FooterRect();
  Display::Fill(r, color::kBlack);
  Display::HLine(0, r.y, r.w, color::kDarkGray);
  int cell = r.w / 3;
  const char* labels[3] = {leftLabel, midLabel, rightLabel};
  for (int i = 0; i < 3; ++i) {
    Rect cellRect{static_cast<int16_t>(r.x + i * cell), r.y, static_cast<int16_t>(cell - 2), r.h};
    TextAlign a = i == 0 ? TextAlign::kLeft : (i == 1 ? TextAlign::kCenter : TextAlign::kRight);
    Display::DrawTextIn(cellRect, FontRole::kSmall, labels[i], labels[i] ? strlen(labels[i]) : 0,
                        color::kGray, color::kBlack, a, VAlign::kMiddle);
  }
}

void DrawFooterLockHint(bool showLock) {
  if (showLock) {
    DrawFooter(i18n::T(i18n::Str::kMenuLock), i18n::T(i18n::Str::kCancel),
               i18n::T(i18n::Str::kBack));
  } else {
    DrawFooter(nullptr, nullptr, nullptr);
  }
}

void DrawMenu(const MenuView& m, bool visible) {
  Rect r = ContentRect();
  int lh = FontLineHeight(FontRole::kSmall);
  int itemH = lh + 6;
  uint8_t shown = visible ? m.count : (m.count > 6 ? 6 : m.count);
  int totalH = shown * itemH;
  int y0 = r.y + (r.h - totalH) / 2;
  for (uint8_t i = 0; i < shown; ++i) {
    uint8_t idx = i;
    Rect ir{10, static_cast<int16_t>(y0 + i * itemH), static_cast<int16_t>(r.w - 20),
            static_cast<int16_t>(itemH)};
    bool sel = idx == m.selected;
    Display::Fill(ir, sel ? color::kDarkGray : color::kBlack);
    if (sel) Display::DrawFocusMark(ir.x, ir.y + 2, static_cast<int16_t>(ir.h - 4), color::kYellow);
    const char* label = m.items[idx];
    // 焦点项使用 "› " 前缀，默认焦点永远是第一项"继续阅读"（由调用方保证顺序）
    char buf[80];
    size_t n = 0;
    if (sel) {
      buf[n++] = '>';
      buf[n++] = ' ';
    }
    size_t l = strlen(label);
    if (n + l < sizeof(buf)) {
      memcpy(buf + n, label, l);
      n += l;
    }
    buf[n] = '\0';
    Display::DrawTextIn(Rect{static_cast<int16_t>(ir.x + 10), ir.y,
                             static_cast<int16_t>(ir.w - 12), static_cast<int16_t>(ir.h)},
                        FontRole::kSmall, buf, n, sel ? color::kWhite : color::kGray,
                        sel ? color::kDarkGray : color::kBlack, TextAlign::kLeft, VAlign::kMiddle);
  }
  if (m.count > shown) {
    char more[24];
    snprintf(more, sizeof(more), "+%u", static_cast<unsigned>(m.count - shown));
    Display::DrawTextIn(Rect{10, static_cast<int16_t>(y0 + shown * itemH), r.w - 20, lh},
                        FontRole::kSmall, more, strlen(more), color::kDarkGray, color::kBlack,
                        TextAlign::kRight, VAlign::kTop);
  }
}

bool MenuNavigate(MenuView& m, Btn btn, BtnEvent ev, uint8_t visibleCount) {
  if (m.count == 0) return false;
  uint8_t span = visibleCount && visibleCount < m.count ? visibleCount : m.count;
  switch (ev) {
    case BtnEvent::kShortPress:
    case BtnEvent::kHoldRepeat:
    case BtnEvent::kLongPress:
      if (btn == Btn::kC) {
        m.selected = static_cast<uint8_t>((m.selected + 1) % span);
        return true;
      }
      if (btn == Btn::kA) {
        m.selected = static_cast<uint8_t>((m.selected + span - 1) % span);
        return true;
      }
      if (btn == Btn::kB) return true;  // B 短按 = 打开
      break;
    default:
      break;
  }
  return false;
}

void DrawKeyValue(const Rect& area, const char* label, const char* value, uint8_t row) {
  int lh = FontLineHeight(FontRole::kSmall);
  int y = area.y + row * (lh + 2);
  Display::DrawTextIn(Rect{area.x + 4, static_cast<int16_t>(y), 84, static_cast<int16_t>(lh)},
                      FontRole::kSmall, label, label ? strlen(label) : 0, color::kGray, color::kBlack,
                      TextAlign::kLeft, VAlign::kTop);
  char tmp[96];
  bool miss = false;
  size_t n = TextEllipsize(FontRole::kSmall, value, strlen(value), area.w - 96, tmp, sizeof(tmp),
                           &miss);
  Display::DrawTextIn(Rect{area.x + 92, static_cast<int16_t>(y), static_cast<int16_t>(area.w - 96),
                           static_cast<int16_t>(lh)},
                      FontRole::kSmall, tmp, n, miss ? color::kYellow : color::kWhite, color::kBlack,
                      TextAlign::kLeft, VAlign::kTop);
}

void DrawNotice(const char* text, uint16_t c) {
  Rect r = ContentRect();
  int lh = FontLineHeight(FontRole::kSmall);
  Display::DrawTextIn(Rect{r.x + 12, r.y + 8, r.w - 24, lh * 2}, FontRole::kSmall, text,
                      strlen(text), c, color::kBlack, TextAlign::kCenter, VAlign::kTop);
}

void DrawHexBlock(const Rect& area, const char* hex, bool mono) {
  FontRole role = mono ? FontRole::kMono : FontRole::kSmall;
  int lh = FontLineHeight(role);
  size_t len = strlen(hex);
  size_t perLine = 32;
  uint8_t line = 0;
  for (size_t i = 0; i < len && line < 8; i += perLine) {
    char buf[40];
    size_t n = 0;
    for (size_t k = i; k < i + perLine && k < len; ++k) buf[n++] = hex[k];
    buf[n] = '\0';
    int y = area.y + line * (lh + 1);
    Display::DrawTextIn(Rect{area.x + 6, static_cast<int16_t>(y), area.w - 12,
                             static_cast<int16_t>(lh)},
                        role, buf, n, color::kWhite, color::kBlack, TextAlign::kLeft, VAlign::kTop);
    line++;
  }
}

void DrawSummary(const ops::ReviewDoc& doc, uint8_t scrollLine, uint8_t visibleLines) {
  Rect r = ContentRect();
  int lh = FontLineHeight(FontRole::kSmall);
  int y = r.y + 2 - static_cast<int>(scrollLine) * (lh + 1);
  uint8_t shown = 0;
  for (uint8_t i = 0; i < doc.summaryCount && shown < visibleLines; ++i) {
    Rect row{r.x + 6, static_cast<int16_t>(y), static_cast<int16_t>(r.w - 12),
            static_cast<int16_t>(lh)};
    char val[80];
    bool miss = false;
    size_t n = TextEllipsize(FontRole::kSmall, doc.summary[i].value, strlen(doc.summary[i].value),
                             row.w - 96, val, sizeof(val), &miss);
    Display::DrawTextIn(Rect{row.x, row.y, 92, static_cast<int16_t>(lh)}, FontRole::kSmall,
                        doc.summary[i].label,
                        strlen(doc.summary[i].label), color::kGray, color::kBlack, TextAlign::kLeft,
                        VAlign::kTop);
    Display::DrawTextIn(Rect{static_cast<int16_t>(row.x + 96), row.y,
                             static_cast<int16_t>(row.w - 96), static_cast<int16_t>(lh)},
                        FontRole::kSmall, val, n, miss ? color::kYellow : color::kWhite,
                        color::kBlack, TextAlign::kLeft, VAlign::kTop);
    y += lh + 1;
    shown++;
  }
}

void DrawBatteryIndicator() {
  uint8_t pct = Board::BatteryPercent();
  Rect r{Board::kScreenW - 30, 4, 24, 12};
  Display::Frame(r, color::kGray);
  Display::Fill(Rect{static_cast<int16_t>(r.x + r.w), static_cast<int16_t>(r.y + 4), 2, 4},
                color::kGray);
  int w = static_cast<int>((r.w - 4) * pct / 100);
  uint16_t c = pct > 20 ? color::kGreen : color::kRed;
  Display::Fill(Rect{static_cast<int16_t>(r.x + 2), static_cast<int16_t>(r.y + 2),
                     static_cast<int16_t>(w), static_cast<int16_t>(r.h - 4)},
                c);
}

// ── Reader ─────────────────────────────────────────────────────────
void Reader::Clear() {
  doc_ = nullptr;
  lineCount_ = 0;
  topLine_ = 0;
  dirty_ = true;
}

void Reader::Load(const ops::ReviewDoc* doc) {
  doc_ = doc;
  topLine_ = 0;
  savedTop_ = 0;
  dirty_ = true;
  Rebuild();
}

void Reader::Rebuild() {
  lineCount_ = 0;
  if (!doc_ || doc_->textLen == 0) {
    dirty_ = false;
    return;
  }
  const char* t = doc_->text;
  size_t len = doc_->textLen;
  int width = Board::kScreenW - 12;
  size_t pos = 0;
  while (pos < len && lineCount_ < kMaxReaderLines) {
    size_t end = 0;
    bool over = false;
    TextWrapLine(FontRole::kBody, t + pos, len - pos, width, &end, &over);
    if (end == 0) end = 1;
    lineStart_[lineCount_] = static_cast<uint16_t>(pos);
    lineEnd_[lineCount_] = static_cast<uint16_t>(pos + end);
    lineCount_++;
    pos += end;
  }
  if (lineCount_ > 0) {
    lineStart_[lineCount_] = static_cast<uint16_t>(len);
    lineEnd_[lineCount_] = static_cast<uint16_t>(len);
  }
  dirty_ = false;
}

int Reader::ChapterLine(uint8_t chapter) {
  if (!doc_ || chapter >= doc_->chapterCount) return 0;
  size_t target = doc_->chapterOffset[chapter];
  for (int i = 0; i < lineCount_; ++i) {
    if (lineStart_[i] >= target) return i;
  }
  return lineCount_ > 0 ? lineCount_ - 1 : 0;
}

void Reader::ScrollToChapter(uint8_t idx) {
  if (!doc_) return;
  topLine_ = ChapterLine(idx);
  if (topLine_ > lineCount_ - 1) topLine_ = lineCount_ > 0 ? lineCount_ - 1 : 0;
}

uint8_t Reader::Chapter() const {
  if (!doc_ || doc_->chapterCount == 0) return 0;
  uint8_t best = 0;
  // 用当前顶行的字节位置反查所属章节
  if (lineCount_ == 0) return 0;
  uint16_t cur = lineStart_[topLine_ < lineCount_ ? topLine_ : 0];
  for (uint8_t i = 0; i < doc_->chapterCount; ++i) {
    if (doc_->chapterOffset[i] <= cur) {
      best = i;
    } else {
      break;
    }
  }
  return best;
}

uint8_t Reader::ChapterCount() const { return doc_ ? doc_->chapterCount : 0; }

void Reader::Scroll(int lines) {
  if (!doc_) return;
  if (dirty_) Rebuild();
  int maxTop = lineCount_ - 1;
  if (maxTop < 0) maxTop = 0;
  topLine_ += lines;
  if (topLine_ < 0) topLine_ = 0;
  if (topLine_ > maxTop) topLine_ = maxTop;
}

bool Reader::AtEnd() const { return lineCount_ == 0 || topLine_ >= lineCount_ - 1; }

void Reader::SavePosition() { savedTop_ = topLine_; }
void Reader::RestorePosition() { topLine_ = savedTop_; }

void Reader::Draw(int16_t x, int16_t y, int16_t w, int16_t h) {
  if (!doc_) return;
  if (dirty_) Rebuild();
  DisplaySetClip(Rect{x, y, w, h});
  int lh = FontLineHeight(FontRole::kBody);
  int rows = h / lh;
  if (rows < 1) rows = 1;
  for (int i = 0; i < rows; ++i) {
    int li = topLine_ + i;
    if (li < 0 || li >= lineCount_) break;
    uint16_t s = lineStart_[li];
    uint16_t e = lineEnd_[li];
    if (e <= s) continue;
    Display::DrawText(FontRole::kBody, static_cast<int16_t>(x + 6), static_cast<int16_t>(y + i * lh),
                      doc_->text + s, static_cast<size_t>(e - s), color::kWhite, color::kBlack);
  }
  DisplayClearClip();
}

// ── HoldConfirm ────────────────────────────────────────────────────
void HoldConfirm::Reset() {
  armed_ = false;
  fired_ = false;
  armedMs_ = 0;
}

void HoldConfirm::Update(const Buttons& btn, uint32_t now, bool enabled) {
  if (!enabled) {
    Reset();
    return;
  }
  if (!armed_ && btn.IsDown(Btn::kB)) {
    armed_ = true;
    armedMs_ = now;
    fired_ = false;
  }
  if (armed_ && !btn.IsDown(Btn::kB)) {
    armed_ = false;
  }
  if (armed_ && (now - armedMs_) >= kHoldConfirmMs) {
    fired_ = true;
  }
}

uint8_t HoldConfirm::Percent(uint32_t now) const {
  if (!armed_) return 0;
  uint32_t dt = now - armedMs_;
  if (dt >= kHoldConfirmMs) return 100;
  return static_cast<uint8_t>(dt * 100 / kHoldConfirmMs);
}

bool HoldConfirm::Fired() const { return fired_; }

void HoldConfirm::Draw(const Rect& box, uint32_t now, bool enabled) {
  const char* label = enabled ? i18n::T(i18n::Str::kSumHoldConfirm)
                              : i18n::T(i18n::Str::kSumNoMore);
  int lh = FontLineHeight(FontRole::kSmall);
  Display::DrawTextIn(Rect{box.x, box.y, box.w, static_cast<int16_t>(lh)}, FontRole::kSmall, label,
                      strlen(label),
                      enabled ? color::kWhite : color::kDarkGray, color::kBlack, TextAlign::kCenter,
                      VAlign::kTop);
  Rect bar{static_cast<int16_t>(box.x + 10), static_cast<int16_t>(box.y + lh + 4),
           static_cast<int16_t>(box.w - 20), 10};
  if (!enabled) {
    Display::DrawProgress(bar, 0, color::kDarkGray, color::kBlack);
    return;
  }
  Display::DrawProgress(bar, Percent(now), color::kYellow, color::kBlack);
}

}  // namespace ui
}  // namespace rockey