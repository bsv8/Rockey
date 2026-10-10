#!/usr/bin/env python3
"""校验固件内嵌的自检向量是否与权威来源一致。

避免"把错的期望值烧进设备、开机自检失败、却以为是硬件问题"。

权威来源：
  - X25519：RFC 7748 §5.2 / §6.1
  - AES-256-GCM：NIST SP 800-38D / GCM 规范测试用例
  - RIPEMD-160：ISO/IEC 10118-3 官方向量
  - 本地秘密 v3：keymaster.cc active-key-hkdf-v1（WebCrypto AES-GCM 等价）

用法：python3 scripts/check_test_vectors.py
"""
import binascii
import hashlib
import hmac
import json
import re
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = []


def check(name, got, want):
    if got != want:
        fails.append(f"{name}: got {got} want {want}")
        print(f"  FAIL {name}\n       got  {got}\n       want {want}")
    else:
        print(f"  ok   {name}")


def arrays_from(path):
    src = open(os.path.join(ROOT, path), encoding="utf-8").read()
    out = {}
    for m in re.finditer(r"(\w+)\[(\d+)\]\s*=\s*\{(.*?)\};", src, re.S):
        name = m.group(1)
        body = m.group(3)
        vals = re.findall(r"0x([0-9a-fA-F]{2})", body)
        if vals:
            out.setdefault(name, []).append("".join(vals))
    return out


def run_firmware_selftest(path, call, extra_includes=None):
    """编译一个只调用 SelfTest 的驱动并返回其结果；环境不满足时返回 None。"""
    import subprocess
    import tempfile
    import shutil

    cxx = shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")
    if not cxx:
        return None
    inc, lib = find_mbedtls()
    if inc is None:
        return None
    with tempfile.TemporaryDirectory() as td:
        drv = os.path.join(td, "drv.cpp")
        with open(drv, "w", encoding="utf-8") as f:
            f.write('#include <cstdio>\n')
            for header in (extra_includes or []):
                f.write(header + "\n")
            f.write('int main(){ printf("%d\\n", (int)(' + call + ')); return 0; }\n')
        out = os.path.join(td, "drv")
        cmd = [cxx, "-std=gnu++17", "-O1", "-I" + os.path.join(ROOT, "src"),
               "-I" + os.path.join(ROOT, "tests", "host", "stubs"),
               "-I" + inc, drv,
               os.path.join(ROOT, "tests", "host", "shim_esp_aes.cpp"),
               os.path.join(ROOT, path),
               os.path.join(ROOT, "src", "crypto", "secure.cpp"), "-o", out]
        if lib:
            cmd += ["-L" + lib, "-lmbedcrypto"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            err = [x for x in r.stderr.splitlines() if "error" in x or "Undefined" in x or "ld:" in x]
            print("  (构建失败: " + (err[0][:140] if err else r.stderr.strip().splitlines()[-1][:140]) + ")")
            return None
        runres = subprocess.run([out], capture_output=True, text=True)
        return runres.stdout.strip().splitlines()[0] if runres.stdout.strip() else None


def host_ripemd(msg):
    """宿主机上的权威实现（OpenSSL RIPEMD-160）。"""
    return hashlib.new("ripemd160", msg.encode()).hexdigest()


def run_firmware_ripemd(cases):
    """编译并运行 src/crypto/ripemd160.cpp，比对它自己的 SelfTest 与逐条向量。

    需要一个 C++17 编译器与 mbedTLS 头文件/库；缺任一项时返回 None，
    调用方会明确打印"跳过"，不会假装通过。
    """
    import subprocess
    import tempfile
    import shutil

    cxx = shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")
    if not cxx:
        print("  no C++ compiler available")
        return None

    inc, lib = find_mbedtls()
    src = os.path.join(ROOT, "src/crypto/ripemd160.cpp")
    with tempfile.TemporaryDirectory() as td:
        drv = os.path.join(td, "drv.cpp")
        with open(drv, "w", encoding="utf-8") as f:
            f.write(
                '#include <cstdio>\n#include <cstring>\n'
                '#include "crypto/ripemd160.h"\n'
                'int main(){\n'
                '  printf("SELFTEST %d\\n", (int)rockey::ripemd::SelfTest());\n'
            )
            for idx, msg in enumerate(cases):
                # 用下标回传结果：消息本身可能含空格，不能靠分隔符还原
                jmsg = json.dumps(msg)
                f.write(
                    "  { unsigned char d[20]; char h[41];"
                    ' const char* k="0123456789abcdef";'
                    " rockey::ripemd::Hash((const unsigned char*)" + jmsg + ", " + str(len(msg)) + ", d);"
                    " for(int i=0;i<20;i++){h[i*2]=k[d[i]>>4];h[i*2+1]=k[d[i]&15];} h[40]=0;"
                    ' printf("V ' + str(idx) + ' %s\\n", h); }\n'
                )
            f.write("  return 0;\n}\n")
        out_bin = os.path.join(td, "drv")
        cmd = [cxx, "-std=gnu++17", "-O1", "-I" + os.path.join(ROOT, "src")]
        if inc:
            cmd += ["-I" + inc]
        cmd += [drv, src, "-o", out_bin]
        if lib:
            cmd += ["-L" + lib, "-lmbedcrypto"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("  could not build firmware ripemd160:\n" + r.stderr.strip()[:400])
            return None
        run = subprocess.run([out_bin], capture_output=True, text=True)
        if run.returncode != 0:
            print("  firmware ripemd160 driver failed")
            return None
        got = {}
        selftest_ok = None
        for line in run.stdout.splitlines():
            if line.startswith("SELFTEST "):
                selftest_ok = line.split()[1] == "1"
            elif line.startswith("V "):
                _, idx_s, hexv = line.split(" ", 2)
                got[int(idx_s)] = hexv
        if selftest_ok is not True:
            fails.append("firmware ripemd::SelfTest() returned false")
            print("  FAIL firmware ripemd::SelfTest() returned false")
        return got


def find_mbedtls():
    """尽力找到 mbedTLS 的头文件与库目录（Homebrew / vcpkg / 系统）。"""
    candidates = [
        os.environ.get("MBEDTLS_ROOT"),
        "/opt/homebrew/Cellar/mbedtls/3.6.4",
        "/usr/local/Cellar/mbedtls/3.6.4",
        "/usr/local/opt/mbedtls",
        "/opt/homebrew/opt/mbedtls",
    ]
    for c in candidates:
        if not c:
            continue
        inc = os.path.join(c, "include")
        lib = os.path.join(c, "lib")
        if os.path.exists(os.path.join(inc, "mbedtls", "ripemd160.h")):
            return (inc, lib if os.path.isdir(lib) else None)
    if shutil_which_ripemd_header():
        return ("/usr/include", None)
    return (None, None)


def shutil_which_ripemd_header():
    return os.path.exists("/usr/include/mbedtls/ripemd160.h")


# ── AES-GCM ────────────────────────────────────────────────────────────
# 这里只做一件事：**执行** src/crypto/aead.cpp 自己的 SelfTest。
# 逐字节对照成熟实现（mbedtls GCM）的是 tests/host/test_aead.cpp，
# 由 scripts/run_host_tests.sh 调用。
#
# 原来的写法是 grep 源码里的期望值数组，既没执行算法，用的还是 NIST 的
# AES-128 用例去对 AES-256 的输出 —— 于是"通过"毫无信息量。
print("AES-GCM / firmware SelfTest")
_selftest = run_firmware_selftest("src/crypto/aead.cpp", "rockey::aead::SelfTest()",
                                 extra_includes=['#include "crypto/aead.h"'])
if _selftest is None:
    print("  skip 无法编译 src/crypto/aead.cpp（需要 ESP-IDF 的 aes/esp_aes.h 与 mbedTLS）")
else:
    check("firmware aead::SelfTest()", _selftest == "1", True)

# ── RIPEMD-160 (ISO/IEC 10118-3) ─────────────────────────────────────────
print("RIPEMD-160 / ISO 10118-3")
RIPEMD = {
    "": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    "a": "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
    "abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    "message digest": "5d0689ef49d2fae572b881b123a85ffa21595f36",
    "abcdefghijklmnopqrstuvwxyz": "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
}
firmware = run_firmware_ripemd(list(RIPEMD))
for idx, (msg, want) in enumerate(RIPEMD.items()):
    check(f"authoritative {msg[:16]!r}", host_ripemd(msg), want)
    if firmware is None:
        print("  skip firmware ripemd160 (无法编译，见输出)")
    else:
        check(f"firmware {msg[:16]!r}", firmware.get(idx, "<missing>"), want)

# ── X25519 (RFC 7748) ─────────────────────────────────────────────────────
# 改成**执行** src/crypto/x25519.cpp 的 SelfTest 与 RFC 向量。
#
# 原来这里只 grep 源码里的 k1/u1/o1 常量并与 RFC 值比对，但那些常量本身
# 就不是 RFC 的向量，实现也是错的（模数、字节序、ladder 初值），
# 于是"通过"毫无信息量。逐项验证改由 tests/host/test_x25519.cpp 负责。
print("X25519 / RFC 7748")
_x = run_firmware_selftest("src/crypto/x25519.cpp", "rockey::x25519::SelfTest()",
                         extra_includes=['#include "crypto/x25519.h"'])
if _x is None:
    print("  skip 无法编译 src/crypto/x25519.cpp（需要 mbedTLS 头文件与库）")
else:
    check("firmware x25519::SelfTest()", _x == "1", True)

# ── 本地秘密 v3 ──────────────────────────────────────────────────────────
print("local-secret v3 / keymaster active-key-hkdf-v1")


def hkdf_sha256(ikm, salt, info, n=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:n]


try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    priv = bytes(31) + b"\x01"
    pubhex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    scope = b"storage.bucket-password"
    salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nonce = bytes.fromhex("101112131415161718191a1b")
    key = hkdf_sha256(priv, b"keymaster.vault.local-secret.v3", pubhex.encode() + b"\x00" + scope)
    check("derived key", binascii.hexlify(key).decode(),
          "8b9534f16d1eec1714c3c5642652d3eff0a9f7b72e5da4e9973d666e8b259112")
    aad = b"keymaster:local-secret:v3|" + scope + b"\x00" + salt
    ct = AESGCM(key).encrypt(nonce, b"provider-secret", aad)
    check("ciphertext||tag", binascii.hexlify(ct).decode(),
          "ea07bec9b7f461d91d00f279b9ade38303baa3f1a28fd7373775c784e78f41")
except ImportError:
    print("  skip host cryptography unavailable")

la = arrays_from("src/ops/local_secret.cpp")
check("embedded derived key", la["kExpectKey"][0],
      "8b9534f16d1eec1714c3c5642652d3eff0a9f7b72e5da4e9973d666e8b259112")
check("embedded ciphertext", la["kExpectCt"][0],
      "ea07bec9b7f461d91d00f279b9ade38303baa3f1a28fd7373775c784e78f41")
src = open(os.path.join(ROOT, "src/ops/local_secret.cpp"), encoding="utf-8").read()
check("embedded pubkey hex",
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in src, True)

print()
if fails:
    print(f"FAILED: {len(fails)} problem(s)")
    sys.exit(1)
print()
print("说明：上面 AES-GCM、RIPEMD-160、X25519 三节都是**执行固件代码**后")
print("      与权威/参照实现比对的结果。逐项向量（RFC 5869 / RFC 7748 / 与")
print("      mbedtls 逐字节对照）见 tests/host/ 与 scripts/run_host_tests.sh。")
print("      local-secret 一节目前仍只比对源码常量 —— 它需要 Keymaster 真实")
print("      密文才能真正验证兼容，这一项尚未完成。")