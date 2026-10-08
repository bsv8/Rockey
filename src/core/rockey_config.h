// 编译期与协议期冻结参数（Gate 0 记录于此，变更必须同步 docs/冻结/）
//
// 本文件是"设备不依赖主机自报"的量的唯一来源：主机请求里的任何长度、
// 数量、时限都必须落在这些边界内。
#ifndef ROCKEY_CORE_CONFIG_H
#define ROCKEY_CORE_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#define ROCKEY_FIRMWARE_VERSION_MAJOR 1
#define ROCKEY_FIRMWARE_VERSION_MINOR 0
#define ROCKEY_FIRMWARE_VERSION_PATCH 0

#ifndef ROCKEY_FIRMWARE_BUILD_ID
#define ROCKEY_FIRMWARE_BUILD_ID "dev-unversioned"
#endif

// ── 互操作协议 ────────────────────────────────────────────────────────
#define ROCKEY_PROTOCOL_VERSION 1u

// 帧与消息上限（协议草案 §3：主机不得自报无界长度）
#define ROCKEY_MAX_FRAME_PAYLOAD 1536u
#define ROCKEY_MAX_PLAINTEXT 1400u
#define ROCKEY_MAX_FRAME_HEADER 12u
#define ROCKEY_MAX_QUEUE 4u            // 一个当前屏幕请求 + 有界排队
#define ROCKEY_MAX_SESSIONS 2u
#define ROCKEY_REPLAY_CACHE 16u
#define ROCKEY_MAX_RESULT_CACHE 8u

// 长文阅读上限（需求 §6.1：大文本按需布局，不全量布局）
#define ROCKEY_MAX_DOC_BYTES 8192u
#define ROCKEY_MAX_DOC_CHARS 6144u
#define ROCKEY_MAX_CHAPTERS 32u
#define ROCKEY_MAX_DYNAMIC_TEXT 256u
#define ROCKEY_READER_VISIBLE_LINES 9u

// 事件队列
#define ROCKEY_EVENT_QUEUE 24u

// ── PIN / 密钥保护 ────────────────────────────────────────────────────
// 真机实测冻结项：真机可用后由 scripts/measure_pin_ux.py 回填。
#define ROCKEY_PIN_DEFAULT_DIGITS 8u
#define ROCKEY_PIN_MIN_DIGITS 4u
#define ROCKEY_PIN_MAX_DIGITS 12u
#define ROCKEY_PIN_KDF_ITERATIONS 120000u   // PBKDF2-HMAC-SHA256
#define ROCKEY_PIN_MAX_REPEAT_CONFIRM 3u
#define ROCKEY_PIN_FAIL_FREE_TRIES 0u       // 首次失败即等待
#define ROCKEY_PIN_FAIL_BASE_MS 2000u
#define ROCKEY_PIN_FAIL_CAP_MS 600000u
// 未经确认不设自动擦除阈值（需求 §3）；失败计数本身不承诺物理防护。
#define ROCKEY_PIN_FAIL_WIPE_THRESHOLD 0u

// 封装格式
#define ROCKEY_ENVELOPE_VERSION 1u
#define ROCKEY_KEYSTORE_SALT_LEN 16u
#define ROCKEY_KEYSTORE_NONCE_LEN 12u
#define ROCKEY_KEYSTORE_TAG_LEN 16u

// ── 会话失活 ──────────────────────────────────────────────────────────
#define ROCKEY_LIVENESS_INTERVAL_MS 1000u
#define ROCKEY_LIVENESS_TIMEOUT_MS 8000u
#define ROCKEY_HANDSHAKE_TIMEOUT_MS 60000u
#define ROCKEY_REQUEST_TTL_MS 120000u
#define ROCKEY_LOCK_IDLE_MS 300000u

// ── 业务参数 ──────────────────────────────────────────────────────────
#define ROCKEY_IDENTITY_CHALLENGE_LEN 32u
#define ROCKEY_TX_MAX_INPUTS 64u
#define ROCKEY_TX_MAX_OUTPUTS 64u
#define ROCKEY_TX_MAX_TX_BYTES 100000u
#define ROCKEY_LOCAL_SECRET_SCOPE_MAX 64u

// ── 一次性导出 ────────────────────────────────────────────────────────
#define ROCKEY_EXPORT_SINGLE_USE_MS 60000u

// ── 开发固件专属 ──────────────────────────────────────────────────────
// 发布固件不得定义 ROCKEY_DEV_TEST_KEY / ROCKEY_DEV_BUTTON_API；
// R8 的发布扫描会检查这些符号不存在。
#if defined(ROCKEY_DEV_TEST_KEY) && ROCKEY_BUILD_RELEASE
#error "ROCKEY_DEV_TEST_KEY 与发布构建互斥"
#endif
#if defined(ROCKEY_DEV_BUTTON_API) && ROCKEY_BUILD_RELEASE
#error "ROCKEY_DEV_BUTTON_API 与发布构建互斥"
#endif

#endif  // ROCKEY_CORE_CONFIG_H