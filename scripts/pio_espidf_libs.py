"""把 ESP-IDF SDK 自带的 mbedTLS 静态库加入链接路径。

Arduino-ESP32 框架默认不链接 mbedTLS（只有网络栈才需要），而 Rockey 用它做
SHA-256/HMAC/HKDF/PBKDF2/AES-GCM/ChaCha20-Poly1305 与 secp256k1 域运算。
这里在构建前把 SDK 的 lib 目录加进 LIBPATH，不引入任何额外依赖。
"""
import os
import sys
import hashlib
import json

Import("env")


def _add_sdk_libs(env):
    pkg = env.PioPlatform().get_package_dir("framework-arduinoespressif32")
    libdir = os.path.join(pkg, "tools", "sdk", "esp32", "lib")
    if not os.path.isdir(libdir):
        sys.stderr.write("ESP-IDF lib dir not found: %s\n" % libdir)
        env.Exit(1)
    env.Append(LIBPATH=[libdir])
    for lib in ("mbedtls", "mbedx509", "mbedcrypto"):
        env.Append(LIBS=[lib])


_add_sdk_libs(env)
# 固定版上游 HKDF/RIPEMD160 模块，框架静态库未编入这两项。
env.BuildSources(os.path.join("$BUILD_DIR", "mbedtls-extra"),
                 os.path.join(env["PROJECT_DIR"], "Coding", "Rockey", "mbedtls-extra"))
# JCS needs ECMAScript's exact floating-point spelling across host and device.
# Compile the pinned upstream converter, rather than relying on libc printf.
env.BuildSources(os.path.join("$BUILD_DIR", "vlp-json-number"),
                 os.path.join(env["PROJECT_DIR"], "Coding", "Rockey", "vaultlink-sdk",
                              "device", "third_party", "double-conversion"))

# Arduino 的预编译 UART ISR 在 Flash 中，LittleFS 提交时会暂停；USB
# 桥没有 RTS/CTS，心跳帧可溢出 128-byte 硬件 FIFO。重编固定版 IDF
# UART 驱动及其 HAL 为 IRAM，保持原来的 Arduino Serial API。
uart_dir = os.path.join(env["PROJECT_DIR"], "Coding", "Rockey", "esp-idf-uart")
with open(os.path.join(uart_dir, "MANIFEST.json")) as manifest_file:
    uart_manifest = json.load(manifest_file)
for filename, record in uart_manifest["files"].items():
    with open(os.path.join(uart_dir, filename), "rb") as source_file:
        if hashlib.sha256(source_file.read()).hexdigest() != record["sha256"]:
            sys.stderr.write("UART pinned source hash mismatch: %s\n" % filename)
            env.Exit(1)
env.BuildSources(os.path.join("$BUILD_DIR", "uart-iram"), uart_dir)

# 每个档位都可记录构建 ID，E2E 报告不能只有 dev-unversioned。
if os.environ.get("ROCKEY_BUILD_ID"):
    env.Append(CPPDEFINES=[("ROCKEY_FIRMWARE_BUILD_ID", env.StringifyMacro(os.environ["ROCKEY_BUILD_ID"]))])
