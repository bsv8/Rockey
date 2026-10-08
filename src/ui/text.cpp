#include "ui/text.h"

#include <string.h>

namespace rockey {
namespace {

bool IsBidiOrInvisible(uint32_t cp) {
  // 双向覆盖/嵌入/隔离、零宽、BOM、软连字符、对象替换符
  if (cp >= 0x202A && cp <= 0x202E) return true;
  if (cp >= 0x2066 && cp <= 0x2069) return true;
  if (cp >= 0x200B && cp <= 0x200F) return true;
  if (cp == 0xFEFF || cp == 0x00AD || cp == 0xFFFC || cp == 0xFFFD) return true;
  // 孤立成对符号：LRE/RLE/LRO/RLO/PDF/LRI/RLI/FSI/PDI
  if (cp >= 0x202A && cp <= 0x202E) return true;
  if (cp == 0x2066 || cp == 0x2067 || cp == 0x2068 || cp == 0x2069) return true;
  return false;
}

bool IsDisallowedControl(uint32_t cp) {
  if (cp == '\n' || cp == '\t' || cp == ' ') return false;
  if (cp < 0x20) return true;
  if (cp >= 0x7F && cp <= 0x9F) return true;      // DEL + C1
  if (cp == 0x2028 || cp == 0x2029) return true;   // 行/段分隔符按换行处理之外拒绝
  return false;
}

bool IsNoncharacter(uint32_t cp) {
  if (cp >= 0xFDD0 && cp <= 0xFDEF) return true;
  if ((cp & 0xFFFE) == 0xFFFE) return true;
  return false;
}

size_t Utf8Encode(uint32_t cp, char* out) {
  if (cp < 0x80) {
    out[0] = static_cast<char>(cp);
    return 1;
  }
  if (cp < 0x800) {
    out[0] = static_cast<char>(0xC0 | (cp >> 6));
    out[1] = static_cast<char>(0x80 | (cp & 0x3F));
    return 2;
  }
  if (cp < 0x10000) {
    out[0] = static_cast<char>(0xE0 | (cp >> 12));
    out[1] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out[2] = static_cast<char>(0x80 | (cp & 0x3F));
    return 3;
  }
  out[0] = static_cast<char>(0xF0 | (cp >> 18));
  out[1] = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
  out[2] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
  out[3] = static_cast<char>(0x80 | (cp & 0x3F));
  return 4;
}

int AdvanceOf(FontRole role, uint32_t cp) {
  if (!FontHasGlyph(role, cp)) return -1;
  int a = FontAdvance(role, cp);
  return a < 0 ? -1 : a;
}

int FallbackAdvance(FontRole role) {
  // 缺字占位宽度与正文字高等宽，保证布局稳定且用户看得见"缺字"
  int h = FontLineHeight(role);
  return h > 0 ? h : 12;
}

}  // namespace

size_t Utf8Next(const char* s, size_t len, size_t i, uint32_t* cpOut, DecodeStatus* st) {
  DecodeStatus local = DecodeStatus::kOk;
  if (!st) st = &local;
  *st = DecodeStatus::kOk;
  if (i >= len) { *cpOut = 0; *st = DecodeStatus::kTruncated; return 0; }
  uint8_t b0 = static_cast<uint8_t>(s[i]);
  uint32_t cp;
  size_t need;
  if (b0 < 0x80) { cp = b0; need = 1; }
  else if (b0 < 0xC2) { cp = 0xFFFD; need = 1; *st = DecodeStatus::kInvalid; }
  else if (b0 < 0xE0) { cp = b0 & 0x1Fu; need = 2; }
  else if (b0 < 0xF0) { cp = b0 & 0x0Fu; need = 3; }
  else if (b0 < 0xF5) { cp = b0 & 0x07u; need = 4; }
  else { cp = 0xFFFD; need = 1; *st = DecodeStatus::kInvalid; }

  if (*st == DecodeStatus::kInvalid) { *cpOut = cp; return 1; }
  if (i + need > len) { *cpOut = 0xFFFD; *st = DecodeStatus::kTruncated; return 1; }
  for (size_t k = 1; k < need; ++k) {
    uint8_t b = static_cast<uint8_t>(s[i + k]);
    if ((b & 0xC0) != 0x80) { *cpOut = 0xFFFD; *st = DecodeStatus::kInvalid; return 1; }
    cp = (cp << 6) | (b & 0x3Fu);
  }
  // 过长编码、代理项、超出 BMP 一律拒绝
  if ((need == 3 && cp < 0x800) || (need == 4 && cp < 0x10000) || (cp >= 0xD800 && cp <= 0xDFFF) ||
      cp > 0x10FFFF) {
    *cpOut = 0xFFFD;
    *st = DecodeStatus::kInvalid;
    return 1;
  }
  *cpOut = cp;
  return need;
}

SanitizeResult SanitizeUtf8(const char* src, size_t srcLen, char* dst, size_t dstCap,
                            size_t maxCodepoints, SanitizeStats* stats) {
  SanitizeStats local;
  if (!stats) stats = &local;
  *stats = local;
  if (dstCap == 0) return SanitizeResult::kInvalid;

  size_t out = 0;
  size_t i = 0;
  uint32_t seen = 0;
  bool overLimit = false;
  bool invalid = false;

  auto note = [&](uint32_t bad) {
    stats->replacedCount++;
    if (!stats->haveFirstBad) { stats->firstBadCp = bad; stats->haveFirstBad = true; }
  };

  while (i < srcLen) {
    uint32_t cp;
    DecodeStatus st;
    size_t adv = Utf8Next(src, srcLen, i, &cp, &st);
    if (adv == 0) break;
    i += adv;

    if (st != DecodeStatus::kOk) {
      invalid = true;
      note(cp ? cp : 0xFFFDu);
    } else if (IsDisallowedControl(cp)) {
      stats->controlDropped++;
      note(cp);
      continue;
    } else if (IsBidiOrInvisible(cp)) {
      stats->bidiDropped++;
      note(cp);
      continue;
    } else if (IsNoncharacter(cp)) {
      note(cp);
      continue;
    } else if (cp > 0xFFFF) {
      // 设备只排 BMP（无 shaping/RTL 验收）
      note(cp);
      continue;
    }

    if (seen >= maxCodepoints) { overLimit = true; break; }
    seen++;
    stats->codepoints = seen;

    size_t need = Utf8Encode(cp, dst + out);
    if (out + need + 1 > dstCap) { overLimit = true; break; }
    out += need;
  }

  dst[out] = '\0';
  stats->truncated = overLimit;
  if (overLimit) return SanitizeResult::kOverLimit;
  if (invalid) return SanitizeResult::kInvalid;
  if (stats->replacedCount) return SanitizeResult::kReplaced;
  return SanitizeResult::kClean;
}

int TextWidth(FontRole role, const char* text, size_t len, bool* missingFound) {
  int w = 0;
  bool missing = false;
  size_t i = 0;
  while (i < len && text[i]) {
    uint32_t cp;
    DecodeStatus st;
    size_t adv = Utf8Next(text, len, i, &cp, &st);
    if (adv == 0) break;
    i += adv;
    if (st != DecodeStatus::kOk) { missing = true; w += FallbackAdvance(role); continue; }
    int aw = AdvanceOf(role, cp);
    if (aw < 0) { missing = true; w += FallbackAdvance(role); continue; }
    w += aw;
  }
  if (missingFound) *missingFound = missing;
  return w;
}

size_t TextEllipsize(FontRole role, const char* s, size_t len, int maxWidth, char* dst,
                     size_t dstCap, bool* truncated) {
  if (truncated) *truncated = false;
  if (dstCap == 0) return 0;
  const char* ell = "…";
  int ellW = TextWidth(role, ell, 3, nullptr);
  int w = 0;
  size_t i = 0;
  size_t lastFit = 0;
  while (i < len && s[i]) {
    uint32_t cp;
    DecodeStatus st;
    size_t adv = Utf8Next(s, len, i, &cp, &st);
    if (adv == 0) break;
    int aw = AdvanceOf(role, cp);
    if (aw < 0) aw = FallbackAdvance(role);
    if (w + aw > maxWidth - ellW) break;
    w += aw;
    i += adv;
    lastFit = i;
  }
  if (i >= len) {
    size_t n = lastFit < dstCap - 1 ? lastFit : dstCap - 1;
    memcpy(dst, s, n);
    dst[n] = '\0';
    return n;
  }
  size_t out = lastFit;
  for (const char* p = ell; *p; ++p) {
    if (out + 1 >= dstCap) break;
    dst[out++] = *p;
  }
  dst[out] = '\0';
  if (truncated) *truncated = true;
  return out;
}

size_t TextWrapLine(FontRole role, const char* s, size_t len, int maxWidth, size_t* outEnd,
                    bool* oversize) {
  if (oversize) *oversize = false;
  int w = 0;
  size_t i = 0;
  size_t lastBoundary = 0;
  int lastBoundaryW = 0;
  while (i < len && s[i]) {
    uint32_t cp;
    DecodeStatus st;
    size_t adv = Utf8Next(s, len, i, &cp, &st);
    if (adv == 0) break;
    int aw = AdvanceOf(role, cp);
    if (aw < 0) aw = FallbackAdvance(role);
    if (i > 0 && w + aw > maxWidth) {
      if (lastBoundary > 0) { if (outEnd) *outEnd = lastBoundary; return lastBoundary; }
      if (oversize) *oversize = true;
      if (outEnd) *outEnd = i + adv;
      return i + adv;
    }
    w += aw;
    i += adv;
    lastBoundary = i;
    lastBoundaryW = w;
  }
  (void)lastBoundaryW;
  if (outEnd) *outEnd = i;
  return i;
}

}  // namespace rockey