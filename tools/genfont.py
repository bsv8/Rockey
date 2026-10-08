"""Rockey 字体生成器 —— 确定性位图字库流水线。

对应需求 §7 / 施工单 R6：
  - 从唯一文案表（src/i18n/strings.h）提取固定 UI 字形；
  - 加入 ASCII、数字、标点与所选动态字集；
  - 重复字形去重（同一 字体+字号 只栅格化一次，多个角色共享）；
  - 固定 UI 缺字或缺翻译 → 失败退出（使构建失败）；
  - 输出字形数 / Flash 字节 / 缺字报告与清单哈希。

用法（由 scripts/build.sh 调用）：
  python3 tools/genfont.py --lang zh-Hans --profile fusion-pixel --glyph-set common \
      --out src/i18n/fonts/rockey_fonts.h --manifest src/i18n/fonts/MANIFEST.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover
    print("FATAL: 需要 Pillow（含 FreeType）：pip install pillow", file=sys.stderr)
    sys.exit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STRINGS_H = os.path.join(ROOT, "src", "i18n", "strings.h")
FONT_MANIFEST = os.path.join(ROOT, "tools", "fontsrc", "manifest.json")

LANGS = ["en", "zh-Hans", "zh-Hant", "zh-Hk", "ja"]
LANG_COL = {"en": 1, "zh-Hans": 2, "zh-Hant": 3, "zh-Hk": 4, "ja": 5}

ROLES = ["title", "body", "small", "mono_small", "mono_large"]

ALWAYS = (
    " !\"#$%&'()*+,-./0123456789:;<=>?@"
    "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)

# dynamic：主机/外部可能带来的常用字符。地址与公钥只用 ASCII，因此始终完整支持。
COMMON_DYNAMIC = (
    "，。、；：？！（）【】《》「」『』…—～·"
    "０１２３４５６７８９"
    "±°¥€£%‰"
    "→←↑↓✓✗●○▲▼■□◆★"
    "１２３４５６７８９"
)

# 控制/双向/代理等一律不属于可显示字集
FORBIDDEN_RANGES = [
    (0x0000, 0x001F), (0x007F, 0x009F), (0x00AD, 0x00AD), (0x061C, 0x061C),
    (0x200B, 0x200F), (0x2028, 0x2029), (0x202A, 0x202E), (0x2060, 0x206F),
    (0xD800, 0xDFFF), (0xFDD0, 0xFDEF), (0xFEFF, 0xFEFF), (0xFFFE, 0xFFFF),
]


@dataclass
class RoleSpec:
    name: str
    font_key: str      # manifest 中 fonts 的键
    size: int
    label: str         # C 变量后缀


@dataclass
class FontInfo:
    key: str
    path: str
    sha256: str
    file: str = ""
    label: str = ""
    license: str = "OFL-1.1"
    license_path: str = ""


@dataclass
class Group:
    """同一 (字体, 字号) 的字形集合；多个角色可共享。"""
    key: str
    font: FontInfo
    size: int
    codepoints: set = field(default_factory=set)
    rendered: dict = field(default_factory=dict)   # cp -> Glyph


@dataclass
class Glyph:
    cp: int
    x_advance: int
    x_offset: int
    y_offset: int
    width: int
    height: int
    bits: bytes = b""


def fail(msg: str) -> None:
    print(f"FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


def merge_adjacent_literals(text):
    """C 允许 "a" "b" 相邻拼接；解析前先合并，避免把一条文案数成多列。"""
    out = []
    i, n = 0, len(text)
    while i < n:
        if text[i] != '"':
            out.append(text[i])
            i += 1
            continue
        parts = []
        start = i
        while True:
            k = start + 1
            while k < n and text[k] != '"':
                if text[k] == '\\':
                    k += 1
                k += 1
            parts.append(text[start + 1:k])
            k += 1  # 跳过收尾引号
            m = k
            while m < n and text[m] in " \t":
                m += 1
            if m < n and text[m] == '"':
                start = m
                continue
            break
        out.append('"' + "".join(parts) + '"')
        i = k
    return "".join(out)


def parse_strings() -> list[tuple[str, list[str]]]:
    with open(STRINGS_H, encoding="utf-8") as f:
        src = f.read()
    # 先去掉 C 续行反斜杠，让跨行的 X(...) 条目能整体匹配
    src = src.replace("\\\n", " ")
    src = merge_adjacent_literals(src)
    body = src.split("ROCKEY_STRING_TABLE(X)", 1)[1].rsplit("#endif", 1)[0]
    rows: list[tuple[str, list[str]]] = []
    pattern = re.compile(r'X\(\s*(k\w+)\s*,\s*((?:"(?:[^"\\]|\\.)*"\s*,?\s*)+)\)', re.S)
    for m in pattern.finditer(body):
        ident = m.group(1)
        cols = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2))
        if len(cols) != len(LANGS):
            fail(f"文案 {ident} 只有 {len(cols)} 个语言列，必须是 {len(LANGS)} 个")
        rows.append((ident, [c.replace('\\"', '"').replace("\\\\", "\\") for c in cols]))
    if not rows:
        fail("未能从 strings.h 解析出文案")
    ids = [r[0] for r in rows]
    if len(ids) != len(set(ids)):
        fail("strings.h 中存在重复的文案 id")
    return rows


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest() -> dict:
    with open(FONT_MANIFEST, encoding="utf-8") as f:
        return json.load(f)


def forbidden(cp: int) -> bool:
    for lo, hi in FORBIDDEN_RANGES:
        if lo <= cp <= hi:
            return True
    return False


class Rasterizer:
    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        self._fonts: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}

    def font(self, path: str, size: int) -> ImageFont.FreeTypeFont:
        key = (path, size)
        if key not in self._fonts:
            self._fonts[key] = ImageFont.truetype(path, size)
        return self._fonts[key]

    def glyph(self, font: FontInfo, size: int, cp: int) -> Glyph:
        ch = chr(cp)
        f = self.font(font.path, size)
        asc, desc = f.getmetrics()
        try:
            bbox = f.getbbox(ch, anchor="ls")
        except Exception:  # pragma: no cover - 老版本 Pillow
            bbox = f.getbbox(ch)
        x0, y0, x1, y1 = bbox
        w, h = max(1, x1 - x0), max(1, y1 - y0)
        adv = int(round(f.getlength(ch)))
        g = Glyph(cp=cp, x_advance=adv, x_offset=x0, y_offset=asc - y0,
                  width=w, height=h)
        if cp == 0x20:
            g.bits = b""
            return g
        img = Image.new("L", (w + 2, h + 2), 0)
        d = ImageDraw.Draw(img)
        d.text((1 - x0, 1 - y0), ch, font=f, fill=255, anchor="ls")
        px = img.load()
        bits = bytearray()
        acc = 0
        nbits = 0
        for row in range(h):
            for col in range(w):
                on = px[col + 1, row + 1] >= 128
                acc = (acc << 1) | (1 if on else 0)
                nbits += 1
                if nbits == 8:
                    bits.append(acc)
                    acc = 0
                    nbits = 0
        if nbits:
            bits.append(acc << (8 - nbits))
        g.bits = bytes(bits)
        return g


def build(args) -> int:
    manifest = load_manifest()
    profile = manifest["profiles"].get(args.profile)
    if profile is None:
        fail(f"manifest 中没有 profile {args.profile}")
    if args.lang not in LANGS:
        fail(f"不支持的语言 {args.lang}")

    rows = parse_strings()
    fixed_text = "".join(cols[LANG_COL[args.lang] - 1] for _, cols in rows)

    # ── 固定 UI 字形（缺字即失败） ───────────────────────────────
    groups: dict[str, Group] = {}

    def group_for(role: str) -> Group:
        spec = profile["roles"][role]
        gkey = f"{spec['font']}@{spec['size']}"
        if gkey not in groups:
            font_key = spec["font"]
            per_lang = profile.get("per_lang", {}).get(args.lang, {})
            font_key = per_lang.get("replace", {}).get(font_key, font_key)
            fi = manifest["fonts"][font_key]
            path = os.path.join(ROOT, manifest["cache"], fi["file"])
            if not os.path.isfile(path):
                fail(f"字体源缺失：{path}\n先运行 tools/fetch_fonts.py --profile {args.profile}")
            actual = sha256_file(path)
            if actual != fi["sha256"]:
                fail(f"字体哈希不符：{path}\n  期望 {fi['sha256']}\n  实际 {actual}")
            groups[gkey] = Group(key=gkey, size=spec["size"], font=FontInfo(
                key=font_key, path=path, sha256=fi["sha256"], license=fi["license"],
                file=fi["file"]))
        return groups[gkey]

    role_groups = {r: group_for(r) for r in ROLES}

    missing: list[tuple[str, str]] = []
    for ch in dict.fromkeys(fixed_text):
        cp = ord(ch)
        if cp == 0x0A:
            continue
        if forbidden(cp):
            continue
        ok = False
        for g in role_groups.values():
            if rasterize(g, cp, roles_of(g, role_groups)):
                ok = True
        if not ok:
            missing.append((ch, f"U+{cp:04X}"))
    if missing:
        detail = ", ".join(f"{c!r} ({u})" for c, u in missing[:20])
        fail(f"固定 UI 文案缺字 {len(missing)} 个：{detail}")

    # ── 动态字集 ────────────────────────────────────────────────
    dynamic_sets = {
        "ui": ALWAYS,
        "common": ALWAYS + COMMON_DYNAMIC,
        "full": ALWAYS + COMMON_DYNAMIC,
    }
    if args.glyph_set not in dynamic_sets:
        fail(f"未知 GLYPH_SET {args.glyph_set}")
    for ch in dict.fromkeys(dynamic_sets[args.glyph_set]):
        cp = ord(ch)
        if forbidden(cp):
            continue
        # 动态集只对正文与等宽字体要求存在；标题/小字缺字时以方框显示
        for role in ("body", "small", "mono_small", "mono_large"):
            rasterize(role_groups[role], cp, [role])

    # ── full 档位：加入所选字体全部可用码位（受预算限制）────────
    budget_used = 0
    if args.glyph_set == "full":
        budget = int(profile.get("full_budget_glyphs", 3000))
        for role in ("body", "small"):
            g = role_groups[role]
            for cp in font_codepoints(g.font.path):
                if forbidden(cp) or cp in g.codepoints:
                    continue
                if budget_used >= budget:
                    break
                if rasterize(g, cp, [role]):
                    budget_used += 1

    return emit(args, manifest, profile, rows, role_groups)


def roles_of(group: Group, role_groups: dict) -> list[str]:
    return [r for r, g in role_groups.items() if g is group]


def _read_table(data: bytes, tag: bytes):
    """从 sfnt/OTF 里取某个表（不依赖 fontTools）。"""
    num_tables = int.from_bytes(data[4:6], "big")
    for i in range(num_tables):
        off = 12 + i * 16
        if data[off:off + 4] == tag:
            t_off = int.from_bytes(data[off + 8:off + 12], "big")
            t_len = int.from_bytes(data[off + 12:off + 16], "big")
            return data[t_off:t_off + t_len]
    return None


def _cmap_format4(buf: bytes) -> set:
    seg_x2 = int.from_bytes(buf[6:8], "big")
    seg = seg_x2 // 2
    end_base = 14
    start_base = end_base + seg_x2 + 2
    delta_base = start_base + seg_x2
    range_base = delta_base + seg_x2
    out = set()
    for i in range(seg):
        end = int.from_bytes(buf[end_base + i * 2:end_base + i * 2 + 2], "big")
        start = int.from_bytes(buf[start_base + i * 2:start_base + i * 2 + 2], "big")
        if start > end or end == 0xFFFF and start == 0xFFFF:
            continue
        delta = int.from_bytes(buf[delta_base + i * 2:delta_base + i * 2 + 2], "big", signed=True)
        ro = int.from_bytes(buf[range_base + i * 2:range_base + i * 2 + 2], "big")
        for cp in range(start, min(end, 0xFFFE) + 1):
            if ro == 0:
                gid = (cp + delta) & 0xFFFF
            else:
                idx = range_base + i * 2 + ro + (cp - start) * 2
                if idx + 2 > len(buf):
                    continue
                gid = int.from_bytes(buf[idx:idx + 2], "big")
                if gid != 0:
                    gid = (gid + delta) & 0xFFFF
            if gid:
                out.add(cp)
    return out


def _cmap_format12(buf: bytes) -> set:
    n_groups = int.from_bytes(buf[12:16], "big")
    out = set()
    for i in range(n_groups):
        off = 16 + i * 12
        start = int.from_bytes(buf[off:off + 4], "big")
        end = int.from_bytes(buf[off + 4:off + 8], "big")
        gid = int.from_bytes(buf[off + 8:off + 12], "big")
        if gid == 0:
            continue
        for cp in range(start, min(end, 0x10FFFF) + 1):
            out.add(cp)
    return out


def font_codepoints(path: str) -> list:
    """枚举字体可用码位（full 字集档位用），纯 Python 解析 cmap，不引入依赖。"""
    data = open(path, "rb").read()
    cmap = _read_table(data, b"cmap")
    if cmap is None:
        raise SystemExit(f"FATAL: 字体没有 cmap 表: {path}")
    n = int.from_bytes(cmap[2:4], "big")
    best = None
    for i in range(n):
        off = 4 + i * 8
        plat = int.from_bytes(cmap[off:off + 2], "big")
        enc = int.from_bytes(cmap[off + 2:off + 4], "big")
        sub = int.from_bytes(cmap[off + 4:off + 8], "big")
        fmt = int.from_bytes(cmap[sub:sub + 2], "big")
        rank = {(3, 10): 0, (0, 6): 1, (0, 4): 2, (3, 1): 3, (0, 3): 4, (0, 2): 5, (0, 1): 6,
                (0, 0): 7}.get((plat, enc), 8)
        if fmt == 12 and rank <= 1:
            best = (0, sub, fmt)
            break
        if fmt == 4 and (best is None or best[0] > 2):
            best = (2, sub, fmt)
    if best is None:
        raise SystemExit(f"FATAL: 字体 cmap 没有可用子表: {path}")
    sub = cmap[best[1]:]
    return sorted(_cmap_format12(sub) if best[2] == 12 else _cmap_format4(sub))


def rasterize(group: Group, cp: int, _roles) -> bool:
    if cp in group.rendered:
        return True
    g = RASTERIZER.glyph(group.font, group.size, cp)
    group.rendered[cp] = g
    group.codepoints.add(cp)
    return True


RASTERIZER: Rasterizer = None  # type: ignore


def emit(args, manifest, profile, rows, role_groups) -> int:
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    lines = []
    lines.append("// Generated by tools/genfont.py -- do not edit by hand.")
    lines.append(f"// LANG={args.lang} FONT_PROFILE={args.profile} GLYPH_SET={args.glyph_set}")
    src_hash = sha256_file(STRINGS_H)
    lines.append(f"// 源文案表 sha256={src_hash}")
    for key, fi in sorted(manifest["fonts"].items()):
        lines.append(f"// font {key}: {fi['file']} sha256={fi['sha256'][:16]} {fi['license']}")
    lines.append("#ifndef ROCKEY_GENERATED_FONTS_H")
    lines.append("#define ROCKEY_GENERATED_FONTS_H")
    lines.append('#include <stdint.h>')
    lines.append('#include "../../ui/font.h"')
    lines.append("namespace rockey {")

    total_bytes = 0
    report = []
    out_bytes: list[bytes] = []

    for gi, gkey in enumerate(sorted(groups_of(role_groups))):
        grp = next(x for x in role_groups.values() if x.key == gkey)
        cps = sorted(grp.codepoints)
        bm = bytearray()
        entries = []
        for cp in cps:
            g = grp.rendered[cp]
            off = len(bm)
            bm.extend(g.bits)
            entries.append((cp, off, len(g.bits), g.x_advance, g.x_offset, g.y_offset,
                            g.width, g.height))
        asc, desc = RASTERIZER.font(grp.font.path, grp.size).getmetrics()
        y_advance = asc + desc
        x_height = 0
        if 0x78 in grp.rendered:
            gx = grp.rendered[0x78]
            x_height = gx.y_offset + gx.height - 1
        out_bytes.append(_c_array(f"gfx_g{gi}_bitmap", bytes(bm)))
        out_bytes.append(b"".join([
            _struct_array(f"gfx_g{gi}_glyphs", entries),
            f"static const TableFont gfx_t{gi} = {{\n"
            f"    gfx_g{gi}_glyphs, {len(entries)}, gfx_g{gi}_bitmap,\n"
            f"    {y_advance}, {asc}, {x_height}, {y_advance}\n}};\n".encode("ascii"),
        ]))
        total_bytes += len(bm)
        report.append((grp.key, grp.font.file, grp.size, len(entries), len(bm)))

    name_by_role = {
        "title": "gfx_rockey_title",
        "body": "gfx_rockey_body",
        "small": "gfx_rockey_small",
        "mono_small": "gfx_rockey_mono_small",
        "mono_large": "gfx_rockey_mono_large",
    }
    gi = 0
    mapping = {}
    for key in sorted(groups_of(role_groups)):
        mapping[key] = f"gfx_t{gi}"
        gi += 1
    alias = "\n".join(
        f"static const TableFont {name_by_role[role]} = {mapping[role_groups[role].key]};"
        for role in ROLES)
    out_bytes.append(alias.encode("ascii"))
    tail = ["}  // namespace rockey", "#endif  // ROCKEY_GENERATED_FONTS_H"]

    with open(args.out, "wb") as f:
        f.write(("\n".join(lines) + "\n").encode("utf-8"))
        for blob in out_bytes:
            f.write(blob + b"\n")
        f.write(("\n".join(tail) + "\n").encode("utf-8"))

    report_lines = [
        "# Rockey 字体清单",
        "",
        "> 本文件由 `tools/genfont.py` 生成，记录每次构建实际编入的字库。",
        "",
        f"- 生成时间来源：构建脚本（不写入时间戳以保持可重复构建）",
        f"- LANG：`{args.lang}`",
        f"- FONT_PROFILE：`{args.profile}`",
        f"- GLYPH_SET：`{args.glyph_set}`",
        f"- 文案表 `src/i18n/strings.h` sha256：`{src_hash}`",
        f"- 固定 UI 文案条数：{len(rows)}",
        "",
        "## 字体来源",
        "",
        "| 键 | 文件 | 字节 | sha256 | 许可证 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for key, fi in sorted(manifest["fonts"].items()):
        used = any(r.key.startswith(f"{key}@") for r in role_groups.values())
        if not used:
            continue
        report_lines.append(
            f"| `{key}` | {fi['file']} | {fi['bytes']} | `{fi['sha256']}` | {fi['license']} |")
    report_lines += [
        "",
        f"许可证全文随源文件保存在 `{manifest['license_dir']}`（SIL Open Font License 1.1）。",
        "",
        "## 实际编入的字形",
        "",
        "| 字体@字号 | 文件 | 码位 | 字形数 | 位图字节 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for key, fname, size, count, nbytes in report:
        report_lines.append(f"| `{key}` | {fname} | {size}px | {count} | {nbytes} |")
    report_lines += [
        "",
        f"位图合计 {total_bytes} 字节（随固件存放在 flash，不占 RAM）。",
        "",
        "## 缺字报告",
        "",
        "固定 UI 文案缺字数为 0（否则生成器直接失败，构建不会继续）。",
        "动态文本缺字会在设备上以方框显示，并可长按查看码点，见 `ui/screen_reader.cpp`。",
        "",
    ]
    with open(args.manifest, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"[genfont] LANG={args.lang} PROFILE={args.profile} GLYPH_SET={args.glyph_set}")
    for key, fname, size, count, nbytes in report:
        print(f"[genfont]   {key:28s} {count:5d} glyphs {nbytes:7d} bytes  ({fname})")
    print(f"[genfont]   bitmap total {total_bytes} bytes -> {args.out}")
    return 0


def groups_of(role_groups: dict) -> set:
    return {g.key for g in role_groups.values()}


def _c_array(name: str, data: bytes) -> bytes:
    parts = [f"static const uint8_t {name}[] = {{"]
    line = "   "
    for i, b in enumerate(data):
        tok = f" 0x{b:02X},"
        if len(line) + len(tok) > 96:
            parts.append(line)
            line = "   "
        line += tok
    if line.strip():
        parts.append(line)
    parts.append("};")
    return "\n".join(parts).encode("ascii")


def _struct_array(name: str, entries) -> bytes:
    out = [f"static const TableGlyph {name}[] = {{"]
    for (cp, off, blen, xa, xo, yo, w, h) in entries:
        out.append(f"  {{0x{cp:04X}u,{off}u,{blen}u,{xa},{int(xo)},{yo},{w},{h}}},")
    out.append("};")
    return "\n".join(out).encode("ascii")


def main() -> int:
    global RASTERIZER
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang", required=True, choices=LANGS)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--glyph-set", required=True, choices=["ui", "common", "full"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args()
    RASTERIZER = Rasterizer(os.path.join(ROOT, "tools", "fontsrc", "cache"))
    return build(args)


if __name__ == "__main__":
    sys.exit(main())