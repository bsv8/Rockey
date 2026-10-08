// UTF-8 解析、清洗与折行。
//
// 对应需求 §6.3「内容可信边界」与协议草案 §7：
//  - 只接受有效 UTF-8、BMP 码位；
//  - 拒绝 C0/C1 控制字符（保留 \n \t）、双向覆盖/隔离、零宽与 BOM、
//    非字符与代理项；
//  - 外部文本缺字要显式可见，不能静默替换后当作已核验名字；
//  - 折行只在 UTF-8 字符边界发生。
#ifndef ROCKEY_UI_TEXT_H
#define ROCKEY_UI_TEXT_H

#include <stdint.h>
#include <stddef.h>

#include "ui/font.h"

namespace rockey {

enum class DecodeStatus : uint8_t { kOk, kTruncated, kInvalid };

// 解码一个码点；返回消耗字节数（无效时返回 1 并给出 U+FFFD）。
size_t Utf8Next(const char* s, size_t len, size_t i, uint32_t* cp, DecodeStatus* st);

enum class SanitizeResult : uint8_t {
  kClean,        // 原样通过
  kReplaced,     // 有码位被替换/丢弃
  kOverLimit,    // 超过字节或码位上限，剩余部分被丢弃
  kInvalid,      // 输入本身无法解释
};

struct SanitizeStats {
  uint32_t replacedCount = 0;
  uint32_t firstBadCp = 0;
  bool haveFirstBad = false;
  uint32_t controlDropped = 0;
  uint32_t bidiDropped = 0;
  uint32_t codepoints = 0;
  bool truncated = false;
};

// 把 src 清洗进 dst（dstCap 含结尾 NUL）。超长内容被截断且置 truncated。
SanitizeResult SanitizeUtf8(const char* src, size_t srcLen, char* dst, size_t dstCap,
                            size_t maxCodepoints, SanitizeStats* stats);

// 单行像素宽度；missingFound 置位表示存在缺字（宽度按全角占位计算）。
int TextWidth(FontRole role, const char* text, size_t len, bool* missingFound);

// 把 s 截断到 maxWidth 像素内（不折行，超出加省略号）。不修改入参。
size_t TextEllipsize(FontRole role, const char* s, size_t len, int maxWidth, char* dst,
                     size_t dstCap, bool* truncated);

// 折行：在像素宽度与 UTF-8 边界上切分。*outEnd 指向行末字节偏移。
// 若单个码点宽于 maxWidth，仍至少取 1 个码点并置 oversize=true。
size_t TextWrapLine(FontRole role, const char* s, size_t len, int maxWidth, size_t* outEnd,
                    bool* oversize);

}  // namespace rockey

#endif  // ROCKEY_UI_TEXT_H