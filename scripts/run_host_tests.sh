#!/usr/bin/env bash
# 主机侧测试：编译 src/ 里的真实实现并跑正反向向量。
#
# 两层：
#  A. 不需要第三方库 —— proto/cbor + proto/frame + store/crc32
#  B. 需要 mbedTLS 头文件与库 —— crypto/aead、ops/tx、policy、ops/local_secret、
#     store/keystore（含 shim_env 的内存 LittleFS）、ops/dispatch 收窄门禁
#     找不到 mbedTLS 时**明确跳过并说明**，不会假装通过。
#
# 覆盖：digest/HKDF/PBKDF2、X25519、AES-GCM、交易序列化与 sighash、授权状态机、
# 本地秘密 v3、密钥封装与恢复备份、已撤销/未冻结入口的拒绝行为。
#
# B 层的意义：aead/RIPEMD/交易序列化这几处曾经各自有过"实现错但自检说通过"
# 的情况，只有拿成熟实现逐字节对照才抓得住。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CXX="${CXX:-c++}"
SAN="${SAN:--fsanitize=address,undefined}"
BIN="$(mktemp -d)"
trap 'rm -rf "$BIN"' EXIT

"$ROOT/scripts/check_syntax.sh" || exit 1
echo

# ── 找 mbedTLS ───────────────────────────────────────────────────────
MB=""
for cand in "${MBEDTLS_ROOT:-}" \
            /opt/homebrew/Cellar/mbedtls/3.6.4 \
            /opt/homebrew/opt/mbedtls \
            /usr/local/opt/mbedtls \
            /usr/local; do
  [ -n "$cand" ] || continue
  if [ -f "$cand/include/mbedtls/gcm.h" ]; then MB="$cand"; break; fi
done

FAILED=0

run() {  # run <名称> <源文件...> -- <测试主文件> <额外链接源...>
  local name="$1"; shift
  local objs=()
  while [ "$1" != "--" ]; do objs+=("$1"); shift; done
  shift
  echo "=== $name ==="
  # shellcheck disable=SC2086
  if ! "$CXX" -std=gnu++17 -Wall -Wextra $SAN -Isrc -Itests/host/stubs \
       -DROCKEY_LANG_ZH_HANS=1 -DMBEDTLS_ALLOW_PRIVATE_ACCESS \
       "$@" -o "$BIN/$name" 2>&1 | sed 's/^/  /'; then
    FAILED=1
    return
  fi
  if ! "$BIN/$name"; then FAILED=1; fi
  echo
}

echo "=== 编译 CBOR / 帧 / CRC32 向量测试 ==="
# shellcheck disable=SC2086
"$CXX" -std=gnu++17 -Wall -Wextra $SAN -Isrc -o "$BIN/proto" \
  tests/host/test_proto.cpp src/proto/cbor.cpp src/proto/frame.cpp src/store/crc32.cpp || exit 1
"$BIN/proto" || FAILED=1
echo

if [ -n "$MB" ]; then
  export ROCKEY_MBEDTLS_INC="$MB/include"
  export ROCKEY_MBEDTLS_LIB="$MB/lib"
  MBFLAGS="-I$MB/include -L$MB/lib -lmbedcrypto"
  echo "mbedTLS: $MB"
  echo

  echo "=== 编译 crypto/aead 对照测试 ==="
  # shellcheck disable=SC2086
  "$CXX" -std=gnu++17 -Wall -Wextra $SAN -Isrc -Itests/host/stubs $MBFLAGS \
    -o "$BIN/aead" tests/host/test_aead.cpp src/crypto/aead.cpp src/crypto/secure.cpp \
    tests/host/shim_esp_aes.cpp || { FAILED=1; }
  if [ -x "$BIN/aead" ]; then "$BIN/aead" || FAILED=1; fi
  echo

  run "ops" -- tests/host/test_ops.cpp tests/host/host_shims.cpp src/ops/tx.cpp \
    src/policy/policy.cpp src/crypto/digest.cpp src/crypto/ripemd160.cpp src/crypto/secure.cpp \
    $MBFLAGS

  # dispatch 收窄门禁：已撤销入口/未冻结能力/池形状伪装/主机文本保护。
  # 这条把 i18n、字库、cbor、keystore 都拉进来，因此单独一个二进制。
  # -DROCKEY_FONT_TABLE=1 让缺字检测跑在**生成的**字库上（与固件一致）；
  # 仓库里检入的是 zh-Hans 档，因此该测试按中文字库断言覆盖/缺字。
  run "dispatch" -- -DROCKEY_FONT_TABLE=1 tests/host/test_dispatch.cpp \
    tests/host/shim_env.cpp src/ops/dispatch.cpp src/ops/review.cpp src/ops/tx.cpp \
    src/ops/local_secret.cpp src/i18n/i18n.cpp src/ui/font.cpp src/ui/text.cpp \
    src/proto/cbor.cpp src/crypto/digest.cpp src/crypto/ripemd160.cpp src/crypto/aead.cpp \
    src/crypto/rand.cpp src/crypto/x25519.cpp src/crypto/secure.cpp src/store/keystore.cpp \
    src/store/vault_fs.cpp src/store/crc32.cpp tests/host/shim_esp_aes.cpp $MBFLAGS

  run "keystore" -- tests/host/test_keystore.cpp tests/host/shim_env.cpp src/ops/local_secret.cpp \
    src/store/keystore.cpp src/store/vault_fs.cpp src/store/crc32.cpp src/crypto/digest.cpp \
    src/crypto/aead.cpp src/crypto/rand.cpp src/crypto/secure.cpp tests/host/shim_esp_aes.cpp \
    $MBFLAGS

  run "digest" -- tests/host/test_digest.cpp src/crypto/digest.cpp src/crypto/secure.cpp $MBFLAGS

  run "x25519" -- tests/host/test_x25519.cpp src/crypto/x25519.cpp src/crypto/secure.cpp $MBFLAGS

  run "localsecret" -- tests/host/test_localsecret.cpp tests/host/host_shims.cpp \
    src/ops/local_secret.cpp src/crypto/aead.cpp src/crypto/digest.cpp src/crypto/rand.cpp \
    src/crypto/secure.cpp tests/host/shim_esp_aes.cpp $MBFLAGS
else
  echo "=== 跳过 mbedTLS 相关测试 ==="
  echo "  未找到 mbedTLS 头文件（设置 MBEDTLS_ROOT 指向其安装目录）。"
  echo "  以下文件未覆盖：crypto/aead、ops/tx、policy、ops/local_secret、crypto/ripemd160。"
  echo "  这些在设备上另有 SelfTest()，但 SelfTest 曾出现过'实现错误却自检通过'的情况，"
  echo "  因此不能只依赖它。"
  echo
fi

if [ "$FAILED" -ne 0 ]; then
  echo "主机测试失败"
  exit 1
fi
echo "主机测试全部通过"