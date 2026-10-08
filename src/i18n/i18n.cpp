#include "i18n/i18n.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>


#if defined(ROCKEY_LANG_EN)
#define ROCKEY_LANG_COL 1
#define ROCKEY_LANG_TAG "en"
#define ROCKEY_LANG_SELF "English"
#elif defined(ROCKEY_LANG_ZH_HANS)
#define ROCKEY_LANG_COL 2
#define ROCKEY_LANG_TAG "zh-Hans"
#define ROCKEY_LANG_SELF "简体中文"
#elif defined(ROCKEY_LANG_ZH_HANT)
#define ROCKEY_LANG_COL 3
#define ROCKEY_LANG_TAG "zh-Hant"
#define ROCKEY_LANG_SELF "繁體中文"
#elif defined(ROCKEY_LANG_ZH_HK)
#define ROCKEY_LANG_COL 4
#define ROCKEY_LANG_TAG "zh-Hk"
#define ROCKEY_LANG_SELF "繁體中文（香港）"
#elif defined(ROCKEY_LANG_JA)
#define ROCKEY_LANG_COL 5
#define ROCKEY_LANG_TAG "ja"
#define ROCKEY_LANG_SELF "日本語"
#else
#error "必须用 ROCKEY_LANG_* 选择一种语言"
#endif

#if (ROCKEY_LANG_COL < 1) || (ROCKEY_LANG_COL > 5)
#error "ROCKEY_LANG_COL 越界"
#endif

namespace rockey {
namespace i18n {
namespace {

const char* const kTable[] = {
#define ROCKEY_STR_PICK(id, en, zh_hans, zh_hant, zh_hk, ja) \
  [ROCKEY_LANG_COL == 1 ? (int)Str::id : 0] = en,
#define ROCKEY_STR_PICK2(id, en, zh_hans, zh_hant, zh_hk, ja) \
  [ROCKEY_LANG_COL == 2 ? (int)Str::id : 0] = zh_hans,
#define ROCKEY_STR_PICK3(id, en, zh_hans, zh_hant, zh_hk, ja) \
  [ROCKEY_LANG_COL == 3 ? (int)Str::id : 0] = zh_hant,
#define ROCKEY_STR_PICK4(id, en, zh_hans, zh_hant, zh_hk, ja) \
  [ROCKEY_LANG_COL == 4 ? (int)Str::id : 0] = zh_hk,
#define ROCKEY_STR_PICK5(id, en, zh_hans, zh_hant, zh_hk, ja) \
  [ROCKEY_LANG_COL == 5 ? (int)Str::id : 0] = ja,
#if ROCKEY_LANG_COL == 1
    ROCKEY_STRING_TABLE(ROCKEY_STR_PICK)
#elif ROCKEY_LANG_COL == 2
    ROCKEY_STRING_TABLE(ROCKEY_STR_PICK2)
#elif ROCKEY_LANG_COL == 3
    ROCKEY_STRING_TABLE(ROCKEY_STR_PICK3)
#elif ROCKEY_LANG_COL == 4
    ROCKEY_STRING_TABLE(ROCKEY_STR_PICK4)
#else
    ROCKEY_STRING_TABLE(ROCKEY_STR_PICK5)
#endif
#undef ROCKEY_STR_PICK
#undef ROCKEY_STR_PICK2
#undef ROCKEY_STR_PICK3
#undef ROCKEY_STR_PICK4
#undef ROCKEY_STR_PICK5
};

const char* const kIds[] = {
#define ROCKEY_ID(id, en, zh_hans, zh_hant, zh_hk, ja) #id,
    ROCKEY_STRING_TABLE(ROCKEY_ID)
#undef ROCKEY_ID
};

}  // namespace

const char* T(Str s) {
  size_t i = static_cast<size_t>(s);
  if (i >= static_cast<size_t>(Str::kCount)) return "";
  const char* p = kTable[i];
  return p ? p : "";
}

size_t Format(char* dst, size_t dstCap, Str s, ...) {
  if (dstCap == 0) return 0;
  va_list ap;
  va_start(ap, s);
  int n = vsnprintf(dst, dstCap, T(s), ap);
  va_end(ap);
  if (n < 0) {
    dst[0] = '\0';
    return 0;
  }
  return static_cast<size_t>(n) < dstCap ? static_cast<size_t>(n) : dstCap - 1;
}

const char* LangTag() { return ROCKEY_LANG_TAG; }
const char* LangDisplayName() { return ROCKEY_LANG_SELF; }

const char* GlyphSetName() {
#if defined(ROCKEY_GLYPH_SET_UI)
  return "ui";
#elif defined(ROCKEY_GLYPH_SET_FULL)
  return "full";
#else
  return "common";
#endif
}

const char* FontProfileName() {
#if defined(ROCKEY_FONT_TABLE)
  return "fusion-pixel";
#else
  return "builtin-ascii";
#endif
}

uint16_t StringCount() { return static_cast<uint16_t>(Str::kCount); }

Str StrFromId(const char* id) {
  if (!id) return Str::kCount;
  for (uint16_t i = 0; i < static_cast<uint16_t>(Str::kCount); ++i) {
    if (strcmp(kIds[i], id) == 0) return static_cast<Str>(i);
  }
  return Str::kCount;
}

}  // namespace i18n
}  // namespace rockey