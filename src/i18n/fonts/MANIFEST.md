# Rockey 字体清单

> 本文件由 `tools/genfont.py` 生成，记录每次构建实际编入的字库。

- 生成时间来源：构建脚本（不写入时间戳以保持可重复构建）
- LANG：`ja`
- FONT_PROFILE：`fusion-pixel`
- GLYPH_SET：`common`
- 文案表 `src/i18n/strings.h` sha256：`8e688e71ac7292eaf9adbc96904a6922204c3a8b81a6370062180e6b02cef78a`
- 固定 UI 文案条数：198

## 字体来源

| 键 | 文件 | 字节 | sha256 | 许可证 |
| --- | --- | --- | --- | --- |
| `fp-mono-latin` | fusion-pixel-12px-monospaced-latin.otf | 4928652 | `d48931d0f47d1ffaba5d6965e2de6a65c0683948faba640d8f2d393a9577d58b` | OFL-1.1 |
| `fp-prop-latin` | fusion-pixel-12px-proportional-latin.otf | 4938652 | `9847709e8e09e9b8b060a96c3df61a16509c65910dbbcb8ca14eab923641be8f` | OFL-1.1 |

许可证全文随源文件保存在 `tools/fontsrc/licenses`（SIL Open Font License 1.1）。

## 实际编入的字形

| 字体@字号 | 文件 | 码位 | 字形数 | 位图字节 |
| --- | --- | --- | --- | --- |
| `fp-mono-latin@12` | fusion-pixel-12px-monospaced-latin.otf | 12px | 427 | 6003 |
| `fp-mono-latin@24` | fusion-pixel-12px-monospaced-latin.otf | 24px | 427 | 24335 |
| `fp-prop-latin@12` | fusion-pixel-12px-proportional-ja.otf | 12px | 427 | 6100 |
| `fp-prop-latin@24` | fusion-pixel-12px-proportional-ja.otf | 24px | 331 | 20870 |

位图合计 57308 字节（随固件存放在 flash，不占 RAM）。

## 缺字报告

固定 UI 文案缺字数为 0（否则生成器直接失败，构建不会继续）。
动态文本缺字会在设备上以方框显示，并可长按查看码点，见 `ui/screen_reader.cpp`。
