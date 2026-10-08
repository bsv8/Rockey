// 位图字库访问层。
//
// Rockey 自己的光栅化器 + 统一字库格式，因此能报告缺字、精确控制背景擦除与
// 裁剪，不依赖 TFT_eSPI 字库内部约定。字库生成器 tools/genfont.py 从固定版本
// 的字体确定性产出 TableFont（见 src/i18n/fonts/MANIFEST.md）。
//
// 两种后端：
//   kTable  —— 生成的字体（Noto CJK / Fusion Pixel / 生成的 ASCII）
//   kBuiltin—— TFT_eSPI 内置 ASCII 字库（仅 ASCII，用于 en 档位）
#ifndef ROCKEY_UI_FONT_H
#define ROCKEY_UI_FONT_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {

// 单个字形描述；按码位升序排列，查找用二分。
struct TableGlyph {
  uint32_t cp;        // 码位
  uint32_t bitOffset; // 在 bitmap 中的位偏移（行内 MSB 在左，行宽补齐到字节）
  uint16_t bitLen;
  uint8_t xAdvance;   // 前进宽度（含左右边距）
  int8_t xOffset;     // 字形左边界相对光标
  uint8_t yOffset;    // 字形顶相对基线上移
  uint8_t width;      // 位图列数
  uint8_t height;     // 位图行数（= yOffset + descender）
};

struct TableFont {
  const TableGlyph* glyphs;
  uint16_t count;
  const uint8_t* bitmap;
  uint8_t yAdvance;
  uint8_t baseline;
  uint8_t xHeight;
  uint8_t missingAdvance;  // 缺字占位宽度（用于显式显示"缺字"）
};

enum class FontBackend : uint8_t { kTable, kBuiltin };

struct Font {
  FontBackend backend = FontBackend::kTable;
  const TableFont* table = nullptr;
  uint8_t builtinId = 1;  // TFT_eSPI 内置字库编号 1..8
};

enum class FontRole : uint8_t {
  kTitle,      // 页面标题
  kBody,       // 正文（长文阅读）
  kSmall,      // 标签、摘要、菜单
  kMono,       // 地址/公钥/哈希（小）
  kMonoLarge,  // 地址/公钥（大）
  kCount
};

const Font* FontGet(FontRole role);
int FontLineHeight(FontRole role);
int FontAscent(FontRole role);
int FontAdvance(FontRole role, uint32_t cp);   // -1 表示缺字
const TableGlyph* FontLookup(FontRole role, uint32_t cp);
bool FontHasGlyph(FontRole role, uint32_t cp);
bool FontCoversUtf8(FontRole role, const char* text, size_t len, uint32_t* firstMissing);
const char* FontRoleName(FontRole role);

}  // namespace rockey

#endif  // ROCKEY_UI_FONT_H