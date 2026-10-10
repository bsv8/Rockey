#!/usr/bin/env python3
"""线缆编码静态检查：主机与设备必须遵守同一份规范编码与字段表。

本脚本不做任何语义推断，只校验两类"必然出错、写完肉眼看不出来"的模式，
这两类都曾在固件里造成过整条请求路径不可用：

1. 字段名守卫  `klen == N && memcmp(k, "lit", M)`  必须满足 N == M == len("lit")。
   N 写错 => 该字段永远匹配不到（设备静默丢字段或返回 invalid-request）。
   M 写错 => 前缀相同但长度不同的别的键会被误认。

2. CBOR 键序    `proto::Writer::Key()` 的调用序列在每个 `BeginMap(n)` 块内必须按
   "字节长度优先、再字节序"严格递增，且 Key() 的个数必须等于 BeginMap(n) 的 n。
   `Writer` 自己会拒绝乱序（ok() 变 false），但调用方在设备上只表现为
   "静默不回包"，主机侧则表现为死等。

用法：python3 scripts/check_wire_encoding.py [paths...]
退出码 0 表示通过。
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# 参与检查的源文件：凡是接触 wire 字段名或 CBOR Writer 的都要查。
TARGET_GLOBS = ["src/**/*.cpp", "src/**/*.h"]


class Finding:
    def __init__(self, path, line, kind, detail):
        self.path = path
        self.line = line
        self.kind = kind
        self.detail = detail

    def __str__(self):
        return f"{self.path}:{self.line}: [{self.kind}] {self.detail}"


# klen == 11 && memcmp(k, "sessionEpoch", 11) == 0
FIELD_GUARD = re.compile(
    r"\b(?P<lenvar>\w*klen|\w*fklen)\s*==\s*(?P<len>\d+)\s*&&\s*"
    r'memcmp\(\s*\w+\s*,\s*"(?P<lit>(?:[^"\\]|\\.)*)"\s*,\s*(?P<cmplen>\d+)\s*\)'
)

# n == 10 && memcmp(k, "commitment", 10) == 0
FIELD_GUARD_ALT = re.compile(
    r"\b(?P<lenvar>n)\s*==\s*(?P<len>\d+)\s*&&\s*"
    r'memcmp\(\s*\w+\s*,\s*"(?P<lit>(?:[^"\\]|\\.)*)"\s*,\s*(?P<cmplen>\d+)\s*\)'
)

KEY_CALL = re.compile(r'\b(?P<obj>\w+)\.Key\(\s*"(?P<lit>(?:[^"\\]|\\.)*)"\s*\)')
BEGIN_MAP = re.compile(r"\b(?P<obj>\w+)\.BeginMap\(\s*(?P<n>\d+)\s*\)")


def c_unescape(s: str) -> str:
    return s.encode().decode("unicode_escape")


def check_field_guards(path: pathlib.Path, text: str, findings: list):
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.split("//")[0]
        for rx in (FIELD_GUARD, FIELD_GUARD_ALT):
            for m in rx.finditer(stripped):
                lit = c_unescape(m.group("lit"))
                want = len(lit)
                got_len = int(m.group("len"))
                got_cmp = int(m.group("cmplen"))
                if got_cmp != want:
                    findings.append(
                        Finding(
                            path,
                            lineno,
                            "field-guard",
                            f'memcmp(..., "{lit}", {got_cmp}) —— 字面量长 {want}，'
                            f"比较长度应为 {want}",
                        )
                    )
                if got_len != want:
                    findings.append(
                        Finding(
                            path,
                            lineno,
                            "field-guard",
                            f'{m.group("lenvar")} == {got_len} 与字面量 "{lit}" 的长度 {want} '
                            f"不符 —— 该字段永远匹配不到",
                        )
                    )


def check_cbor_keys(path: pathlib.Path, text: str, findings: list):
    """逐行跟踪 Writer 的 Key() 序列，校验键序与 BeginMap 计数。"""
    depth = 0
    stack = []  # 每层：{"count": 已见 Key 数, "last": (len, bytes) 或 None, "obj": 名}
    for lineno, line in enumerate(text.splitlines(), 1):
        code = line.split("//")[0]
        bm = BEGIN_MAP.search(code)
        if bm:
            stack.append(
                {"count": 0, "last": None, "n": int(bm.group("n")), "obj": bm.group("obj"),
                 "line": lineno}
            )
            depth += 1
            continue
        for km in KEY_CALL.finditer(code):
            if not stack:
                findings.append(
                    Finding(path, lineno, "cbor-key", "Key() 不在 BeginMap() 块内")
                )
                continue
            top = stack[-1]
            lit = c_unescape(km.group("lit"))
            key = (len(lit), lit.encode())
            if top["last"] is not None and key <= top["last"]:
                prev = top["last"][1].decode()
                findings.append(
                    Finding(
                        path,
                        lineno,
                        "cbor-key",
                        f'键 "{lit}"(len {len(lit)}) 不大于前一个键 "{prev}"'
                        f'(len {top["last"][0]}) —— 确定性编码要求"长度优先、再字节序"严格递增',
                    )
                )
            top["last"] = key
            top["count"] += 1
        # EndMap / EndArray 关闭当前层
        if re.search(r"\bend\b\.?EndMap\(\)", code) and stack:
            top = stack.pop()
            depth -= 1
            if top["count"] != top["n"]:
                findings.append(
                    Finding(
                        path,
                        lineno,
                        "cbor-map-count",
                        f'BeginMap({top["n"]}) 在第 {top["line"]} 行，实际只写了 '
                        f'{top["count"]} 个 Key()',
                    )
                )


def main(argv):
    paths = [pathlib.Path(a) for a in argv[1:]]
    if not paths:
        paths = sorted(
            p for pat in TARGET_GLOBS for p in ROOT.glob(pat) if "i18n/fonts" not in str(p)
        )

    findings: list = []
    for p in paths:
        if not p.exists():
            print(f"找不到文件: {p}", file=sys.stderr)
            return 2
        text = p.read_text()
        check_field_guards(p, text, findings)
        check_cbor_keys(p, text, findings)

    if findings:
        for f in sorted(findings, key=lambda x: (str(x.path), x.line)):
            print(f)
        print(f"\n线缆编码检查失败：{len(findings)} 处", file=sys.stderr)
        return 1

    print(f"线缆编码检查通过：{len(paths)} 个文件，字段名守卫与 CBOR 键序一致")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))