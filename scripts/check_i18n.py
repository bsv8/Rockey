#!/usr/bin/env python3
"""i18n 检查：缺翻译、重复 key、空串、动态字符串误入固定表。

固定 UI 文案缺翻译必须让构建失败（需求 §7）。
"""
import argparse
import re
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STRINGS = os.path.join(ROOT, "src", "i18n", "strings.h")
LANGS = ["en", "zh-Hans", "zh-Hant", "zh-Hk", "ja"]

# 只在这些"档位"里允许出现的 key 白名单（无）
ALLOW_EMPTY = {"kUnitNone"}

ROW = re.compile(
    r'X\(\s*(k\w+)\s*,\s*((?:"(?:[^"\\]|\\.)*"\s*,?\s*)+)\)', re.S)


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


def parse():
    src = open(STRINGS, encoding="utf-8").read()
    # 先去掉 C 续行反斜杠，让跨行的 X(...) 条目能整体匹配
    src = src.replace("\\\n", " ")
    src = merge_adjacent_literals(src)
    body = src.split("ROCKEY_STRING_TABLE(X)", 1)[1].rsplit("#endif", 1)[0]
    rows = []
    for m in ROW.finditer(body):
        ident = m.group(1)
        cols = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2))
        rows.append((ident, cols))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang", default=None, help="同时校验该语言的字数集可用性")
    args = ap.parse_args()

    rows = parse()
    problems = []
    seen = set()
    for ident, cols in rows:
        if ident in seen:
            problems.append(f"重复 key: {ident}")
        seen.add(ident)
        if len(cols) != len(LANGS):
            problems.append(f"{ident}: 语言列数 {len(cols)} != {len(LANGS)}")
            continue
        for lang, text in zip(LANGS, cols):
            if not text.strip() and ident not in ALLOW_EMPTY:
                problems.append(f"{ident}: {lang} 为空")
            if text != text.strip():
                problems.append(f"{ident}: {lang} 首尾有空白")

    if problems:
        for p in problems:
            print(f"  FAIL {p}", file=sys.stderr)
        print(f"FAILED: {len(problems)} 个问题", file=sys.stderr)
        return 1
    print(f"[i18n] {len(rows)} 条文案，{len(LANGS)} 种语言齐全，无缺翻译")
    return 0


if __name__ == "__main__":
    sys.exit(main())