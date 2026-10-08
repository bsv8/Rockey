"""把 ESP-IDF SDK 自带的 mbedTLS 静态库加入链接路径。

Arduino-ESP32 框架默认不链接 mbedTLS（只有网络栈才需要），而 Rockey 用它做
SHA-256/HMAC/HKDF/PBKDF2/AES-GCM/ChaCha20-Poly1305 与 secp256k1 域运算。
这里在构建前把 SDK 的 lib 目录加进 LIBPATH，不引入任何额外依赖。
"""
import os
import sys

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
