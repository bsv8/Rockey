// 屏幕构件：页头、页脚、菜单、长文阅读器、长按确认。
//
// 交互骨架固定为：概览 → 关键摘要/警告 → 可选长文 → 决策菜单 → 允许确认。
// A/C 浏览，B 打开/提交；普通菜单 B 长按返回，确认页 B 长按执行。
// 换页后先要求松键（由 Buttons 的 release gate 保证），长按不会延续到新页面。
#ifndef ROCKEY_UI_WIDGETS_H
#define ROCKEY_UI_WIDGETS_H

#include <stdint.h>
#include <stddef.h>

#include "board/board.h"
#include "board/buttons.h"
#include "board/display.h"
#include "ops/review.h"

namespace rockey {
namespace ui {

// ── 页头 / 页脚 ────────────────────────────────────────────────────
void DrawHeader(const char* title, const char* rightHint);
void DrawFooter(const char* leftLabel, const char* midLabel, const char* rightLabel);
void DrawFooterLockHint(bool showLock);

// ── 菜单 ───────────────────────────────────────────────────────────
constexpr uint8_t kMaxMenuItems = 8;

struct MenuView {
  const char* items[kMaxMenuItems];
  uint8_t count = 0;
  uint8_t selected = 0;
  const char* title = nullptr;
  void Add(const char* s) {
    if (count < kMaxMenuItems) items[count++] = s;
  }
};

void DrawMenu(const MenuView& m, bool visible);
// 处理 A/C 浏览与 B 打开；返回 true 表示 B 被短按
bool MenuNavigate(MenuView& m, Btn btn, BtnEvent ev, uint8_t visibleCount);

// ── 关键摘要 ───────────────────────────────────────────────────────
void DrawSummary(const ops::ReviewDoc& doc, uint8_t scrollLine, uint8_t visibleLines);

// ── 长文阅读器 ─────────────────────────────────────────────────────
constexpr int kMaxReaderLines = 512;

class Reader {
 public:
  void Load(const ops::ReviewDoc* doc);
  void Clear();
  bool Loaded() const { return doc_ != nullptr; }
  void Scroll(int lines);
  void ScrollToChapter(uint8_t idx);
  void Draw(int16_t x, int16_t y, int16_t w, int16_t h);
  uint8_t Chapter() const;
  uint8_t ChapterCount() const;
  int Line() const { return topLine_; }
  void SavePosition();
  void RestorePosition();
  bool AtEnd() const;
  const ops::ReviewDoc* doc() const { return doc_; }

 private:
  void Rebuild();
  int ChapterLine(uint8_t chapter);

  const ops::ReviewDoc* doc_ = nullptr;
  uint16_t lineStart_[kMaxReaderLines] = {0};
  uint16_t lineEnd_[kMaxReaderLines] = {0};
  int lineCount_ = 0;
  int topLine_ = 0;
  int savedTop_ = 0;
  bool dirty_ = true;
};

// ── 长按确认 ───────────────────────────────────────────────────────
// 必须由"新的按下/长按动作"触发：短按不会确认，进度可见，
// 取消或过期会清空按键状态。
constexpr uint16_t kHoldConfirmMs = 900;

class HoldConfirm {
 public:
  void Reset();
  void Update(const Buttons& btn, uint32_t now, bool enabled);
  bool Armed() const { return armed_; }
  uint8_t Percent(uint32_t now) const;
  bool Fired() const;
  void Draw(const Rect& box, uint32_t now, bool enabled);
  bool Expired(uint32_t now) const { return armed_ && (now - armedMs_) > kHoldConfirmMs * 3; }

 private:
  bool armed_ = false;
  uint32_t armedMs_ = 0;
  bool fired_ = false;
};

// ── 小组件 ─────────────────────────────────────────────────────────
void DrawKeyValue(const Rect& area, const char* label, const char* value, uint8_t row);
void DrawNotice(const char* text, uint16_t color);
void DrawHexBlock(const Rect& area, const char* hex, bool mono);
void DrawBatteryIndicator();

}  // namespace ui
}  // namespace rockey

#endif  // ROCKEY_UI_WIDGETS_H