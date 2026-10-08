#!/usr/bin/env bash
# Rockey 固件构建入口。
#
# 流程：
#   1. 按 (LANG, FONT_PROFILE, GLYPH_SET) 生成字库（有缺字/缺翻译即失败）
#   2. 注入构建 ID
#   3. 调用 PlatformIO 编译
#   4. 发布构建额外跑发布固件扫描（无测试按键 / 无盲签 / 无秘密日志）
#
# 用法：
#   scripts/build.sh                      # 构建默认环境（zh-Hans 发布）
#   scripts/build.sh --all                # 构建全部语言 × 档位
#   scripts/build.sh --upload m5stack-core-zh-hans
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── 工具链 ────────────────────────────────────────────────────────────
M5STACK_ROOT="${M5STACK_ROOT:-/home/david/Workspaces/m5stack}"
export PLATFORMIO_CORE_DIR="${PLATFORMIO_CORE_DIR:-$M5STACK_ROOT/tools/platformio}"
PIO_PY="$M5STACK_ROOT/tools/venv/bin/python"
if [ ! -x "$PIO_PY" ]; then
  echo "找不到 PlatformIO：$PIO_PY" >&2
  echo "请安装 PlatformIO 并设置 M5STACK_ROOT" >&2
  exit 1
fi
pio() { "$PIO_PY" -m platformio "$@"; }

BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
export ROCKEY_BUILD_ID="$BUILD_ID"

# ── 环境 -> 语言/字体/字集映射 ───────────────────────────────────────
env_spec() {
  case "$1" in
    m5stack-core-en)          echo "en common" ;;
    m5stack-core-zh-hans)     echo "zh-Hans common" ;;
    m5stack-core-zh-hant)     echo "zh-Hant common" ;;
    m5stack-core-zh-hk)       echo "zh-Hk common" ;;
    m5stack-core-ja)          echo "ja common" ;;
    m5stack-core-migration)   echo "zh-Hans full" ;;
    m5stack-core-debug-zh-hans) echo "zh-Hans common" ;;
    m5stack-core-dev-zh-hans) echo "zh-Hans common" ;;
    m5stack-core-dev-en)      echo "en common" ;;
    *) echo "" ;;
  esac
}

env_is_release() {
  case "$1" in
    *-dev-*|*-debug-*) return 1 ;;
    *) return 0 ;;
  esac
}

env_font_profile() {
  case "$1" in
    *-en) echo "builtin" ;;
    *)    echo "fusion-pixel" ;;
  esac
}

ALL_ENVS=(
  m5stack-core-en
  m5stack-core-zh-hans
  m5stack-core-zh-hant
  m5stack-core-zh-hk
  m5stack-core-ja
  m5stack-core-migration
  m5stack-core-debug-zh-hans
  m5stack-core-dev-zh-hans
  m5stack-core-dev-en
)

UPLOAD_ENV=""
TARGETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --all) TARGETS=("${ALL_ENVS[@]}") ;;
    --upload) shift; UPLOAD_ENV="$1" ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) TARGETS+=("$1") ;;
  esac
  shift
done
if [ ${#TARGETS[@]} -eq 0 ]; then
  TARGETS=(m5stack-core-zh-hans)
fi

echo "构建 ID: $BUILD_ID"

for env_name in "${TARGETS[@]}"; do
  spec="$(env_spec "$env_name")"
  if [ -z "$spec" ]; then
    echo "未知环境: $env_name" >&2
    exit 1
  fi
  lang="${spec%% *}"
  glyph="${spec##* }"
  profile="$(env_font_profile "$env_name")"

  echo
  echo "=== $env_name  (LANG=$lang FONT_PROFILE=$profile GLYPH_SET=$glyph) ==="

  if [ "$profile" = "builtin" ]; then
    # en 档位使用 TFT_eSPI 内置 ASCII 字库，不生成 CJK 字库
    if [ -f src/i18n/fonts/rockey_fonts.h ]; then
      mv src/i18n/fonts/rockey_fonts.h "src/i18n/fonts/.rockey_fonts.h.stale"
      trap 'mv -f src/i18n/fonts/.rockey_fonts.h.stale src/i18n/fonts/rockey_fonts.h 2>/dev/null || true' EXIT
    fi
  else
    python3 tools/genfont.py \
      --lang "$lang" --profile "$profile" --glyph-set "$glyph" \
      --out src/i18n/fonts/rockey_fonts.h \
      --manifest src/i18n/fonts/MANIFEST.md
  fi

  python3 scripts/check_i18n.py --lang "$lang" || exit 1

  rm -rf ".pio/build/$env_name"
  ( cd .pio/build 2>/dev/null || mkdir -p .pio/build && cd .pio/build
    rm -rf "$env_name" ) 2>/dev/null || true
  rm -rf ".pio/libdeps/$env_name"

  EXTRA_FLAGS=()
  if env_is_release "$env_name"; then
    EXTRA_FLAGS+=("-DROCKEY_FIRMWARE_BUILD_ID=\\\"${ROCKEY_BUILD_ID}\\\"")
  fi

  set +e
  pio run -e "$env_name" 2>&1 | tee ".pio/build-$env_name.log"
  rc=${PIPESTATUS[0]}
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "构建失败: $env_name" >&2
    exit "$rc"
  fi

  if env_is_release "$env_name"; then
    python3 scripts/check_release_build.py ".pio/build/$env_name/firmware.elf" \
      --env "$env_name" --build-id "$ROCKEY_BUILD_ID" || exit 1
  else
    echo "（开发/调试档位：跳过发布扫描）"
  fi
done

if [ -n "$UPLOAD_ENV" ]; then
  echo
  echo "=== 刷写 $UPLOAD_ENV ==="
  pio run -e "$UPLOAD_ENV" -t upload --upload-port "${M5STACK_PORT:-/dev/ttyUSB0}"
fi

echo
echo "全部完成：$BUILD_ID"