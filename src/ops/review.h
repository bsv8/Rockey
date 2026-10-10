// 评审文档：设备自己生成的固定模板 + 实际字段。
//
// 关键点（需求 §6，2026-10-09 收窄后）：
//  - 标题、章节、按钮文案全部来自固件固定模板，主机文本不能伪造它们；
//  - 设备只展示**实际操作的基础事实**：谁（完整公钥/地址）、对象、金额、
//    范围、限额与"不包含"；不展示业务长文、信用评价或 Markdown；
//  - 主机给出的实际字段（purpose/protocol/scope/fileName）进文档前必须经过
//    UTF-8 清洗、长度上限与缺字检测，缺字在阅读页可见（RK-05）；
//  - 关键摘要与重大警告标记为必经（bit0 / bit1），滚动到底不作为授权证据。
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

enum class Risk : uint8_t {
  kNone = 0,
  kPaysYou,
  kPaysOther,
  kUnverifiedInputs,
  kFeeHigh,
  kUnknownScript,
  kPrivateChannel,
  kContentDigestHostComputed,
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
  // 必须经过的关键摘要/重大警告的总量（章节数 + 风险条数）。
  // 确认前必须逐项看过；详细长文不计入（需求 6.2）。
  uint16_t requiredTotal = 0;
  // 实际字段里出现的第一个问题码位（缺字或被清洗掉的字符）。
  // 界面据此显示"缺字 U+xxxx"，不静默替换后继续。
  uint32_t missingGlyphCp = 0;
  bool hasMissingGlyph = false;

  void Reset() { *this = ReviewDoc{}; }

  // 追加一个章节（title + body），返回 false 表示超出上限
  bool AddChapter(const char* title, uint8_t flags);
  void AppendText(const char* s);
  void AppendLine(const char* s);
  bool AddSummary(const char* label, const char* value);
  void AddRisk(Risk r);
  // 主机文本字段进文档前的统一处理：清洗 + 上限 + 缺字记录。
  // 外部正文整章不进设备（信用/Markdown 归 Keymaster），这里只针对
  // 实际参与签名对象的字段（purpose/protocol/scope/fileName）。
  void NoteDynamicText(const char* cleaned, size_t len, const SanitizeStats& stats);
  void Finish();
};

}  // namespace ops
}  // namespace rockey

#endif  // ROCKEY_OPS_REVIEW_H