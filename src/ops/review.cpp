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
    case Risk::kExternalIssuer: return i18n::Str::kRiskExternalIssuer;
    case Risk::kTimeUnverified: return i18n::Str::kRiskTimeUnverified;
    case Risk::kNoEvidence: return i18n::Str::kNoEvidenceShort;
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

bool ReviewDoc::AppendExternal(const char* title, const char* body, size_t len) {
  if (!body || len == 0) return false;
  static char clean[ROCKEY_MAX_DYNAMIC_TEXT * 2];
  SanitizeStats st;
  SanitizeResult sr = SanitizeUtf8(body, len, clean, sizeof(clean), ROCKEY_MAX_DYNAMIC_TEXT, &st);
  extStats = st;
  if (st.haveFirstBad) missingGlyphCp = st.firstBadCp;
  AddChapter(title, kChapterExternal);
  if (sr == SanitizeResult::kReplaced || sr == SanitizeResult::kInvalid) {
    AppendLine(i18n::T(i18n::Str::kReadStripped));
    AppendLine("");
  }
  if (sr == SanitizeResult::kOverLimit) {
    AppendLine(i18n::T(i18n::Str::kReadTruncated));
    AppendLine("");
  }
  uint32_t miss = 0;
  if (!FontCoversUtf8(FontRole::kBody, clean, strlen(clean), &miss)) {
    hasMissingGlyph = true;
    missingGlyphCp = miss;
  }
  AppendLine(clean);
  hasExternalText = true;
  return true;
}

void ReviewDoc::Finish() {
  text[textLen] = '\0';
}

}  // namespace ops
}  // namespace rockey