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
    "DevSetLevel",
    "DevTestControl",
    "rockey::e2e::",
    "TestOnlySign",
    "DebugExportPrivateKey",
    "BypassConfirm",
    # 通用盲签：正式 Key 绝不能提供任意 digest 签名
    "SignArbitraryDigest",
    "SignHashRaw",
    "signDigest",
    "signHash",
    # 未经本地菜单、重新 PIN 与实体确认的旧原始密钥入口；
    # 正式 migration.export 由私有迁移控制器实施，不在此符号黑名单中。
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

    # 符号扫描是发布门禁的核心（盲签 / 测试按键 / raw key 接口）。
    # 早先找不到 nm 时只是跳过符号扫描、照样报"通过" —— 那等于没查。
    # 现在缺工具一律失败，并明确告诉怎么装。
    def have_tool(t):
        return os.path.isfile(t) or subprocess.run(["which", t], capture_output=True).returncode == 0

    if not have_tool(args.nm):
        print(f"FATAL: 找不到符号工具 {args.nm}", file=sys.stderr)
        print("  发布固件必须扫描 ELF 符号；跳过等于没做这道门禁。", file=sys.stderr)
        print("  装法：PlatformIO 的 xtensa 工具链已自带，可用 --nm 指定绝对路径，", file=sys.stderr)
        print("  或设置 ROCKEY_NM 环境变量。", file=sys.stderr)
        return 2
    syms = elf_symbols(args.nm, args.elf)
    if not syms.strip():
        print(f"FATAL: {args.nm} 对 {args.elf} 没有输出任何符号", file=sys.stderr)
        print("  拿不到符号表就无法确认盲签/测试接口已移除，拒绝通过。", file=sys.stderr)
        return 2

    for sym in FORBIDDEN_SYMBOLS:
        if sym in syms:
            problems.append(f"符号 {sym} 出现在发布固件中")

    # 固定目标 ESP32 的 UART ISR 和 FIFO HAL 必须在内部指令 RAM。
    # 只定义宏而仍链接框架的 Flash 实现，无法在 LittleFS 提交时接收 USB。
    for sym in ("uart_rx_intr_handler_default", "uart_hal_read_rxfifo", "uart_hal_write_txfifo"):
        match = re.search(r"^([0-9a-fA-F]+)\s+[tT]\s+" + sym + r"(?:\s|\.)", syms, re.M)
        if not match or not 0x40080000 <= int(match.group(1), 16) < 0x400A0000:
            problems.append(f"UART 必要函数 {sym} 未落入 ESP32 IRAM")

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
    print(f"  ok   已扫描 ELF 符号（{len(syms.splitlines())} 个），无测试按键 / 无通用盲签 / 无旧原始密钥入口（迁移导出另需设备解锁与实体确认）")
    print("  ok   未发现秘密字符串")
    return 0


if __name__ == "__main__":
    sys.exit(main())
