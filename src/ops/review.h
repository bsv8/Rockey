// 评审文档：设备自己生成的固定模板 + 可选外部正文。
//
// 关键点（需求 §6）：
//  - 标题、章节、按钮文案全部来自固件固定模板，外部文本不能伪造它们；
//  - 外部正文只出现在标记为"外部"的章节内，经过 UTF-8 清洗与上限裁剪；
//  - 关键摘要与重大警告标记为必经（bit0 / bit1），但滚动到底不作为授权证据。
#ifndef ROCKEY_OPS_REVIEW_H
#define ROCKEY_OPS_REVIEW_H

#include <stdint.h>
#include <stddef.h>

#include "core/rockey_config.h"
#include "i18n/i18n.h"
#include "ui/text.h"

namespace rockey {
namespace ops {

constexpr uint8_t kChapterRequired = 0x01;   // 关键摘要：必经
constexpr uint8_t kChapterWarning = 0x02;    // 重大警告
constexpr uint8_t kChapterExternal = 0x04;   // 来自外部文本

enum class Risk : uint8_t {
  kNone = 0,
  kPaysYou,
  kPaysOther,
  kUnverifiedInputs,
  kFeeHigh,
  kUnknownScript,
  kPrivateChannel,
  kExternalIssuer,
  kTimeUnverified,
  kNoEvidence,
};

i18n::Str RiskString(Risk r);

struct SummaryLine {
  char label[26];
  char value[74];
};

struct ReviewDoc {
  char title[48] = {0};
  char subject[80] = {0};   // 完整对象标识（公钥/地址 hex）
  char text[ROCKEY_MAX_DOC_BYTES] = {0};
  size_t textLen = 0;
  uint16_t chapterOffset[ROCKEY_MAX_CHAPTERS] = {0};
  uint8_t chapterCount = 0;
  uint8_t chapterFlags[ROCKEY_MAX_CHAPTERS] = {0};
  SummaryLine summary[8];
  uint8_t summaryCount = 0;
  Risk risks[8];
  uint8_t riskCount = 0;
  bool hasExternalText = false;
  SanitizeStats extStats{};
  uint32_t missingGlyphCp = 0;
  bool hasMissingGlyph = false;

  void Reset() { *this = ReviewDoc{}; }

  // 追加一个章节（title + body），返回 false 表示超出上限
  bool AddChapter(const char* title, uint8_t flags);
  void AppendText(const char* s);
  void AppendLine(const char* s);
  bool AddSummary(const char* label, const char* value);
  void AddRisk(Risk r);
  // 外部文本：清洗后追加为独立章节
  bool AppendExternal(const char* title, const char* body, size_t len);
  void Finish();
};

}  // namespace ops
}  // namespace rockey

#endif  // ROCKEY_OPS_REVIEW_H