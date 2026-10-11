#!/usr/bin/env bash
# Rockey 固件构建入口。
#
# 流程：
#   0. 主机侧门禁：语法检查 + 线缆编码检查 + CBOR/帧向量测试（不需要工具链）
#   1. 按 (LANG, FONT_PROFILE, GLYPH_SET) 生成字库（有缺字/缺翻译即失败）
#   2. 注入构建 ID
#   3. 调用 PlatformIO 编译
#   4. 发布构建额外跑发布固件扫描（无测试按键 / 无盲签 / 无秘密日志）
#
# 第 0 步是本仓库自己加的：这些检查在没有 ESP32 工具链的机器上就能跑，
# 目的是让"握手发不出去 / 字段永远匹配不上 / 整棵树编译不过"这类问题
# 在刷机之前就暴露出来，而不是等到构建或联调阶段。
#
# 用法：
#   tools/build/main.sh                      # 构建默认环境（zh-Hans 发布）
#   tools/build/main.sh --all                # 构建全部语言 × 档位
#   tools/build/main.sh --check-only         # 只跑第 0 步门禁
#   tools/build/main.sh --upload m5stack-core-zh-hans
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

CHECK_ONLY=0

# ── 第 0 步：主机侧门禁（无需 ESP32 工具链） ──────────────────────────
run_host_gate() {
  echo "=== 主机侧门禁 ==="
  "$ROOT/tools/host-tests/main.sh"
  python3 tools/wire-encoding/main.py
  echo
}

# ── 工具链 ────────────────────────────────────────────────────────────
# PlatformIO 的可用性在主机侧门禁之后检查：门禁本身不需要工具链，
# 在没装 PlatformIO 的机器上也应该能跑。
# 不写死某台机器的路径：优先 M5STACK_ROOT，其次找同名目录，最后退到 PATH。
if [ -z "${M5STACK_ROOT:-}" ]; then
  for cand in "$HOME/Workspaces/m5stack" "$HOME/m5stack" "/home/$USER/Workspaces/m5stack"; do
    if [ -n "$cand" ] && [ -x "$cand/tools/venv/bin/python" ]; then
      M5STACK_ROOT="$cand"
      break
    fi
  done
fi
if [ -n "${M5STACK_ROOT:-}" ]; then
  export PLATFORMIO_CORE_DIR="${PLATFORMIO_CORE_DIR:-$M5STACK_ROOT/tools/platformio}"
fi
if [ -n "${M5STACK_ROOT:-}" ]; then
  PIO_PY="${ROCKEY_PYTHON:-$M5STACK_ROOT/tools/venv/bin/python}"
else
  PIO_PY="${ROCKEY_PYTHON:-$ROOT/.tools/venv/bin/python}"
fi
FONT_PY="${ROCKEY_PYTHON:-python3}"

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
    m5stack-core-e2e-en)      echo "en common" ;;
    m5stack-core-e2e-zh-hans) echo "zh-Hans common" ;;
    *) echo "" ;;
  esac
}

env_is_release() {
  case "$1" in
    *-dev-*|*-debug-*|*-e2e-*) return 1 ;;
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
    --upload) shift; UPLOAD_ENV="$1"; TARGETS+=("$1") ;;
    --check-only) CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) TARGETS+=("$1") ;;
  esac
  shift
done

run_host_gate
if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "主机侧门禁全部通过（未构建固件）"
  exit 0
fi

if [ -x "$PIO_PY" ] && "$PIO_PY" -m platformio --version >/dev/null 2>&1; then
  FONT_PY="$PIO_PY"
  pio() { "$PIO_PY" -m platformio "$@"; }
else
  if command -v pio >/dev/null 2>&1; then
    echo "使用 PATH 上的 PlatformIO: $(command -v pio)"
    pio() { command pio "$@"; }
  else
    echo "找不到 PlatformIO。" >&2
    echo "  查找过: $PIO_PY" >&2
    echo "请安装 PlatformIO，或设置 ROCKEY_PYTHON 指向同时安装 platformio 与 Pillow 的 Python。" >&2
    exit 1
  fi
fi

# 所选语言只用于本次固件，不污染检入的默认字库与下一次主机门禁。
# 每个环境另存实际字体清单；多语言构建不能只剩最后一份清单。
FONT_RESTORE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rockey-font-restore.XXXXXX")"
cp src/i18n/fonts/rockey_fonts.h "$FONT_RESTORE_DIR/rockey_fonts.h"
cp src/i18n/fonts/MANIFEST.md "$FONT_RESTORE_DIR/MANIFEST.md"
restore_font_sources() {
  cp "$FONT_RESTORE_DIR/rockey_fonts.h" src/i18n/fonts/rockey_fonts.h
  cp "$FONT_RESTORE_DIR/MANIFEST.md" src/i18n/fonts/MANIFEST.md
  rm -rf "$FONT_RESTORE_DIR"
}
trap restore_font_sources EXIT

BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
export ROCKEY_BUILD_ID="$BUILD_ID"
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
    # 不覆盖统一恢复 trap；否则 en→ja 后仅头文件恢复，清单却残留 ja。
    rm -f src/i18n/fonts/rockey_fonts.h
    cat > src/i18n/fonts/MANIFEST.md <<'BUILTIN_MANIFEST'
# Rockey 字体清单

- LANG：`en`
- FONT_PROFILE：`builtin`
- GLYPH_SET：`common`
- 字体来源：固定依赖 TFT_eSPI 2.5.43 内置 ASCII 字库（许可证随依赖）。
- 未编入 CJK 字体；所有英语文案须通过 check_i18n.py。
BUILTIN_MANIFEST
  else
    "$FONT_PY" tools/fonts/main.py \
      --lang "$lang" --profile "$profile" --glyph-set "$glyph" \
      --out src/i18n/fonts/rockey_fonts.h \
      --manifest src/i18n/fonts/MANIFEST.md
  fi

  python3 tools/i18n/main.py --lang "$lang" || exit 1

  rm -rf ".pio/build/$env_name"
  rm -rf ".pio/libdeps/$env_name"

  EXTRA_FLAGS=()
  if env_is_release "$env_name"; then
    EXTRA_FLAGS+=("-DROCKEY_FIRMWARE_BUILD_ID=\\\"${ROCKEY_BUILD_ID}\\\"")
  fi

  set +e
  pio run -e "$env_name" -j "${ROCKEY_BUILD_JOBS:-2}" 2>&1 | tee ".pio/build-$env_name.log"
  rc=${PIPESTATUS[0]}
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "构建失败: $env_name" >&2
    exit "$rc"
  fi

  cp src/i18n/fonts/MANIFEST.md ".pio/build/$env_name/font-MANIFEST.md"
  if env_is_release "$env_name"; then
    python3 tools/release-check/main.py ".pio/build/$env_name/firmware.elf" \
      --env "$env_name" --build-id "$ROCKEY_BUILD_ID" || exit 1
    # PlatformIO 可清理前一环境的缓存；发布成果与语言清单不能依赖缓存存活。
    artifact_dir=".pio/releases/$BUILD_ID/$env_name"
    mkdir -p "$artifact_dir"
    cp ".pio/build/$env_name/firmware.elf" ".pio/build/$env_name/firmware.bin" ".pio/build/$env_name/font-MANIFEST.md" "$artifact_dir/"
    "$FONT_PY" tools/rockey/main.py archive "$BUILD_ID" "$env_name"
  else
    echo "（开发/调试档位：跳过发布扫描）"
  fi
done

if [ -n "$UPLOAD_ENV" ]; then
  echo
  echo "=== 刷写 $UPLOAD_ENV ==="
  if ! env_is_release "$UPLOAD_ENV"; then
    echo "统一维护命令只部署发布固件；开发 E2E 使用隔离测试流程。" >&2
    exit 1
  fi
  firmware_path="$("$FONT_PY" tools/rockey/main.py archive "$BUILD_ID" "$UPLOAD_ENV")"
  upload_args=()
  if [ -n "${M5STACK_PORT:-}" ]; then upload_args+=(--port "$M5STACK_PORT"); fi
  ROCKEY_PYTHON="$FONT_PY" ./rockey flash "$firmware_path" "${upload_args[@]}"
fi

echo
echo "全部完成：$BUILD_ID"
