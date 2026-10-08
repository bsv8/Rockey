#include "ui/font.h"

#include <TFT_eSPI.h>
#include <string.h>

#if defined(ROCKEY_FONT_TABLE)
#include "i18n/fonts/rockey_fonts.h"
#endif

namespace rockey {
namespace {

#if defined(ROCKEY_FONT_TABLE)
const Font kFonts[static_cast<int>(FontRole::kCount)] = {
    {FontBackend::kTable, &gfx_rockey_title, 0},
    {FontBackend::kTable, &gfx_rockey_body, 0},
    {FontBackend::kTable, &gfx_rockey_small, 0},
    {FontBackend::kTable, &gfx_rockey_mono_small, 0},
    {FontBackend::kTable, &gfx_rockey_mono_large, 0},
};
#else
// 仅内置 ASCII：正文/标题使用较大的内置字库
const Font kFonts[static_cast<int>(FontRole::kCount)] = {
    {FontBackend::kBuiltin, nullptr, 4},  // kTitle
    {FontBackend::kBuiltin, nullptr, 2},  // kBody
    {FontBackend::kBuiltin, nullptr, 1},  // kSmall
    {FontBackend::kBuiltin, nullptr, 1},  // kMono
    {FontBackend::kBuiltin, nullptr, 2},  // kMonoLarge
};
#endif

int BuiltinAscent(uint8_t id) {
  switch (id) {
    case 4: return 19;
    case 2: return 10;
    default: return 8;
  }
}

}  // namespace

const Font* FontGet(FontRole role) {
  int i = static_cast<int>(role);
  if (i < 0 || i >= static_cast<int>(FontRole::kCount)) i = 0;
  return &kFonts[i];
}

int FontLineHeight(FontRole role) {
  const Font* f = FontGet(role);
  if (f->backend == FontBackend::kTable) return f->table->yAdvance;
  return BuiltinAscent(f->builtinId) + 4;
}

int FontAscent(FontRole role) {
  const Font* f = FontGet(role);
  if (f->backend == FontBackend::kTable) return f->table->baseline;
  return BuiltinAscent(f->builtinId);
}

const TableGlyph* FontLookup(FontRole role, uint32_t cp) {
  const Font* f = FontGet(role);
  if (f->backend != FontBackend::kTable) return nullptr;
  const TableFont* t = f->table;
  if (t->count == 0) return nullptr;
  uint32_t lo = 0, hi = t->count;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    if (t->glyphs[mid].cp == cp) return &t->glyphs[mid];
    if (t->glyphs[mid].cp < cp) lo = mid + 1;
    else hi = mid;
  }
  return nullptr;
}

int FontAdvance(FontRole role, uint32_t cp) {
  const Font* f = FontGet(role);
  if (f->backend == FontBackend::kTable) {
    const TableGlyph* g = FontLookup(role, cp);
    if (g) return g->xAdvance;
    if (cp == '\n' || cp == ' ') return f->table->yAdvance / 2;
    return f->table->missingAdvance;
  }
  if (cp < 32 || cp > 126) return -1;
  return f->builtinId == 4 ? 12 : (f->builtinId == 2 ? 10 : 6);
}

bool FontHasGlyph(FontRole role, uint32_t cp) {
  const Font* f = FontGet(role);
  if (f->backend == FontBackend::kTable) return FontLookup(role, cp) != nullptr;
  return cp >= 32 && cp <= 126;
}

bool FontCoversUtf8(FontRole role, const char* text, size_t len, uint32_t* firstMissing) {
  size_t i = 0;
  while (i < len && text[i]) {
    uint32_t cp = static_cast<uint8_t>(text[i]);
    size_t adv = 1;
    if (cp >= 0xF0) adv = 4;
    else if (cp >= 0xE0) adv = 3;
    else if (cp >= 0xC0) adv = 2;
    if (!FontHasGlyph(role, cp)) {
      if (firstMissing) *firstMissing = cp;
      return false;
    }
    i += adv;
  }
  return true;
}

const char* FontRoleName(FontRole role) {
  switch (role) {
    case FontRole::kTitle:     return "ui-title";
    case FontRole::kBody:      return "ui-body";
    case FontRole::kSmall:     return "ui-small";
    case FontRole::kMono:      return "mono-small";
    case FontRole::kMonoLarge: return "mono-large";
    default:                   return "?";
  }
}

}  // namespace rockey