#include "ops/review.h"

#include <stdio.h>
#include <string.h>

namespace rockey {
namespace ops {
namespace {
void SafeCopy(char* dst, size_t cap, const char* src) {
  if (!src) {
    dst[0] = '\0';
    return;
  }
  strncpy(dst, src, cap - 1);
  dst[cap - 1] = '\0';
}
}  // namespace

i18n::Str RiskString(Risk r) {
  switch (r) {
    case Risk::kPaysYou: return i18n::Str::kRiskPaysYou;
    case Risk::kPaysOther: return i18n::Str::kRiskPaysOther;
    case Risk::kUnverifiedInputs: return i18n::Str::kRiskUnverifiedInputs;
    case Risk::kFeeHigh: return i18n::Str::kRiskFeeHigh;
    case Risk::kUnknownScript: return i18n::Str::kRiskUnknownScript;
    case Risk::kPrivateChannel: return i18n::Str::kRiskPrivateChannel;
    case Risk::kContentDigestHostComputed: return i18n::Str::kContentDigestByHost;
    default: return i18n::Str::kNone;
  }
}

void ReviewDoc::AppendText(const char* s) {
  if (!s) return;
  size_t n = strlen(s);
  if (textLen + n >= sizeof(text)) n = sizeof(text) - textLen - 1;
  memcpy(text + textLen, s, n);
  textLen += n;
  text[textLen] = '\0';
}

void ReviewDoc::AppendLine(const char* s) {
  AppendText(s);
  AppendText("\n");
}

bool ReviewDoc::AddChapter(const char* title, uint8_t flags) {
  if (chapterCount >= ROCKEY_MAX_CHAPTERS) return false;
  chapterOffset[chapterCount] = static_cast<uint16_t>(textLen);
  chapterFlags[chapterCount] = flags;
  chapterCount++;
  if (title && title[0]) {
    AppendLine(title);
    AppendLine("");
  }
  return true;
}

bool ReviewDoc::AddSummary(const char* label, const char* value) {
  if (summaryCount >= 8) return false;
  SafeCopy(summary[summaryCount].label, sizeof(summary[summaryCount].label), label);
  SafeCopy(summary[summaryCount].value, sizeof(summary[summaryCount].value), value);
  summaryCount++;
  return true;
}

void ReviewDoc::AddRisk(Risk r) {
  if (r == Risk::kNone || riskCount >= 8) return;
  for (uint8_t i = 0; i < riskCount; ++i) {
    if (risks[i] == r) return;
  }
  risks[riskCount++] = r;
}

// 主机文本字段进文档前的统一登记：记录第一个问题码位（缺字或被清洗掉的
// 字符），供阅读页脚显示"缺字 U+xxxx"。
// 外部正文整章不进设备（信用长文/Markdown 归 Keymaster），所以这里不再有
// "追加外部章节"的入口 —— 设备只审实际签名对象自带的字段。
void ReviewDoc::NoteDynamicText(const char* cleaned, size_t len, const SanitizeStats& stats) {
  if (!cleaned || len == 0) return;
  uint32_t miss = 0;
  if (!FontCoversUtf8(FontRole::kBody, cleaned, len, &miss)) {
    hasMissingGlyph = true;
    if (!missingGlyphCp) missingGlyphCp = miss;
  }
  if (stats.haveFirstBad && !missingGlyphCp) missingGlyphCp = stats.firstBadCp;
}

void ReviewDoc::Finish() {
  text[textLen] = '\0';
  // 门禁总量 = 必经章节数 + 风险条数 + "不包含"一项
  requiredTotal = static_cast<uint16_t>(chapterCount) + riskCount + 1u;
}

}  // namespace ops
}  // namespace rockey