#!/usr/bin/env bash
# 主机侧语法检查：在没有 ESP32 工具链的机器上，对 src/ 的真实实现做 -fsyntax-only。
#
# 为什么需要它：R1-R5 的改动大部分落在 link / dispatch / app / widgets 这些
# 文件上，而它们直到真机刷写前都没有被任何编译器检查过。窄化转换、缺成员、
# 拼错的枚举名都会一直潜伏到构建时才炸。这里用 tests/host/stubs/ 下的
# Arduino / TFT_eSPI / LittleFS 替身把它们全部过一遍。
#
# 覆盖不到的：依赖 ESP-IDF 头文件的 crypto 实现
# （digest / secp256k1 / x25519 / aead / rand）。这些由固件自带的
# SelfTest() 与 tools/test-vectors/main.py 覆盖，不在本脚本范围内 ——
# 明确列出未覆盖项，不假装全绿。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STUBS="$ROOT/tests/host/stubs"
CXX="${CXX:-c++}"
STD="-std=gnu++17"
DEFS="-DROCKEY_LANG_ZH_HANS=1 -DROCKEY_FONT_TABLE=1 -DROCKEY_BUILD_RELEASE=1 -DROCKEY_GLYPH_SET_COMMON=1"

# mbedTLS 能找到时，连 crypto 一起检查（本机是 3.6.4，设备目标是 2.28；
# secp256k1.cpp 直接访问 mbedtls_ecp_point 的私有成员，需要打开访问开关）
MB=""
for cand in "${MBEDTLS_ROOT:-}" /opt/homebrew/Cellar/mbedtls/3.6.4 \
            /opt/homebrew/opt/mbedtls /usr/local/opt/mbedtls /usr/local; do
  [ -n "$cand" ] || continue
  if [ -f "$cand/include/mbedtls/gcm.h" ]; then MB="$cand"; break; fi
done
if [ -n "$MB" ]; then
  MBFLAGS="-I$MB/include -DMBEDTLS_ALLOW_PRIVATE_ACCESS"
  SKIP_RE='src/crypto/rand\.cpp$'   # 只剩 esp_random.h 拿不到
  echo "mbedTLS 头文件: $MB/include（crypto 也纳入语法检查）"
else
  MBFLAGS=""
  SKIP_RE='src/crypto/(digest|secp256k1|x25519|aead|ripemd160|rand)\.cpp$'
fi

pass=0
fail=0
warn_files=0
skipped=()

while IFS= read -r f; do
  rel="${f#"$ROOT"/}"
  if [[ "$rel" =~ $SKIP_RE ]]; then
    skipped+=("$rel")
    continue
  fi
  # shellcheck disable=SC2086
  out=$("$CXX" $STD -fsyntax-only -Wall -Wextra -Wno-unused-private-field -Wno-unused-const-variable \
        -Wno-unused-function -Wno-c99-designator -Wno-tautological-overlap-compare \
        -I"$ROOT/src" -I"$ROOT/include" -I"$STUBS" $DEFS $MBFLAGS "$f" 2>&1)
  errs=$(printf '%s\n' "$out" | grep -E "error:" || true)
  if [[ -n "$errs" ]]; then
    fail=$((fail + 1))
    printf '  FAIL %s\n' "$rel"
    printf '%s\n' "$out" | sed 's/^/         /'
  elif [[ -n "$out" ]]; then
    warn_files=$((warn_files + 1))
    printf '  warn %s\n' "$rel"
    printf '%s\n' "$out" | sed 's/^/         /'
  else
    pass=$((pass + 1))
    printf '  ok   %s\n' "$rel"
  fi
done < <(find "$ROOT/src" -name '*.cpp' | sort)

echo
echo "语法检查：$pass 个通过，$fail 个失败，$warn_files 个有警告"
if [[ ${#skipped[@]} -gt 0 ]]; then
  echo "未覆盖（缺 ESP-IDF 头文件）："
  printf '  - %s\n' "${skipped[@]}"
fi

[[ $fail -eq 0 ]]