// 多语言访问层。语言在编译期由 ROCKEY_LANG_* 决定，一个固件只编入一种语言
// 加小型拉丁/数字字库（需求 §7）。
#ifndef ROCKEY_I18N_I18N_H
#define ROCKEY_I18N_I18N_H

#include <stdint.h>
#include <stddef.h>

#include "i18n/strings.h"

namespace rockey {
namespace i18n {

enum class Str : uint16_t {
#define ROCKEY_STR_ENTRY(id, en, zh_hans, zh_hant, zh_hk, ja) id,
  ROCKEY_STRING_TABLE(ROCKEY_STR_ENTRY)
#undef ROCKEY_STR_ENTRY
      kCount
};

// 该 id 的原文（格式串）
const char* T(Str s);
// 带 printf 参数的格式化
size_t Format(char* dst, size_t dstCap, Str s, ...);
const char* LangTag();          // "en" / "zh-Hans" / ...
const char* LangDisplayName();  // 语言自述名
const char* GlyphSetName();
const char* FontProfileName();
uint16_t StringCount();
Str StrFromId(const char* id);  // kCount 表示不存在

}  // namespace i18n
}  // namespace rockey

#endif  // ROCKEY_I18N_I18N_H