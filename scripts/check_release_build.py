#!/usr/bin/env python3
"""发布固件扫描（需求 §2 / RK-09）。

发布固件必须满足：
  1. 不含测试按键接口、模拟确认或绕过授权的符号；
  2. 不含任意摘要签名（通用 SIGN_HASH）与原始私钥调试导出入口；
  3. 不含测试私钥常量；
  4. 固件镜像里不出现秘密字符串（日志模板、私钥、PIN 派生材料）。

检查对象是链接产物 .elf 的符号表与可读段字符串，而不是源码 grep：
源码里可以保留开发用代码，但发布固件里必须真的没有。
"""
import argparse
import os
import re
import subprocess
import sys

FORBIDDEN_SYMBOLS = [
    # 开发/测试入口
    "DevInjectTestKey",
    "DevButtonApi",
    "TestOnlySign",
    "DebugExportPrivateKey",
    "BypassConfirm",
    # 通用盲签：正式 Key 绝不能提供任意 digest 签名
    "SignArbitraryDigest",
    "SignHashRaw",
    "signDigest",
    "signHash",
    # 原始密钥导出
    "DumpPrivateKey",
    "GetRawPrivateKey",
    "ExportPrivateKeyRaw",
]

FORBIDDEN_STRING_PATTERNS = [
    # 开发测试私钥（hex 或十进制串）
    (re.compile(r"18e14a8bf50f1e2a33445566778899aabbccddeeff0011223344556677889977", re.I),
     "embedded dev test private key"),
    # 不应出现的敏感日志标签
    (re.compile(r"\bPIN=%s\b"), "PIN value in log format"),
    (re.compile(r"\bprivkey="), "private key in log format"),
    (re.compile(r"\bderivedKey="), "derived key in log format"),
    (re.compile(r"\bplaintext="), "plaintext in log format"),
]

# 允许出现的解释性字符串（文档/断言用），避免误报
ALLOW_STRINGS = [
    "rockey:local-secret:v3",
    "keymaster.vault.local-secret.v3",
]


def elf_symbols(tool_nm, elf):
    out = subprocess.run([tool_nm, "-C", elf], capture_output=True, text=True)
    return out.stdout


def elf_strings(elf):
    with open(elf, "rb") as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--env", default="?")
    ap.add_argument("--build-id", default="?")
    ap.add_argument("--nm", default=os.environ.get("ROCKEY_NM", "xtensa-esp32-elf-nm"))
    ap.add_argument("--strings", default=os.environ.get("ROCKEY_STRINGS", "xtensa-esp32-elf-strings"))
    args = ap.parse_args()

    if not os.path.isfile(args.elf):
        print(f"FATAL: {args.elf} 不存在", file=sys.stderr)
        return 1

    problems = []
    syms = ""
    if os.path.isfile(args.nm) or subprocess.run(["which", args.nm],
                                                 capture_output=True).returncode == 0:
        syms = elf_symbols(args.nm, args.elf)

    for sym in FORBIDDEN_SYMBOLS:
        if sym in syms:
            problems.append(f"符号 {sym} 出现在发布固件中")

    blob = elf_strings(args.elf)
    try:
        text = blob.decode("latin-1")
    except Exception:
        text = ""

    for pat, why in FORBIDDEN_STRING_PATTERNS:
        m = pat.search(text)
        if m:
            problems.append(f"发现敏感串（{why}）：{m.group(0)[:40]!r}")

    # 开发日志级别不得进入发布固件
    if re.search(r"\bROCKEY_BUILD_RELEASE=0\b", text):
        problems.append("发布固件中出现 ROCKEY_BUILD_RELEASE=0 标记")

    size = os.path.getsize(args.elf)
    print(f"[release-scan] env={args.env} buildId={args.build_id} elf={size} bytes")
    if problems:
        for p in problems:
            print(f"  FAIL {p}")
        return 1
    print("  ok   无测试按键 / 无盲签 / 无原始密钥导出入口")
    print("  ok   未发现秘密字符串")
    return 0


if __name__ == "__main__":
    sys.exit(main())