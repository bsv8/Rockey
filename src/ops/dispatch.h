// 请求解析、校验、评审文档冻结与执行。
//
// 主机提交完整可核验操作；设备自己解析、生成安全摘要、匹配授权并执行。
// 主机不能提交一个 digest 加一段说明让设备假称理解：每个 operation 都有
// 固定的字段集合、对象约束与摘要构造（docs/冻结/线缆格式.md §5/§6）。
#ifndef ROCKEY_OPS_DISPATCH_H
#define ROCKEY_OPS_DISPATCH_H

#include <stdint.h>
#include <stddef.h>

#include "core/rockey_config.h"
#include "ops/local_secret.h"
#include "ops/review.h"
#include "ops/tx.h"
#include "policy/policy.h"

namespace rockey {
namespace ops {

// 稳定的 operation id（进 wire 与匹配键，不随文案变化）
//
// 2026-10-09 收窄为最小密钥设备后：
//  - 设备不再提供任何信用/证据服务入口（evidence.receive 已撤销），
//    业务解释与信用信息由 Keymaster 展示；
//  - 费用池签名（kTxFeepoolSign）在脚本/阶段/签名规则冻结前**显式不可用**，
//    只有 op 名被登记，Prepare 直接拒绝，不解析任何字段、不进 capabilities。
//    未冻结变体不得套用 tx.p2pkh-sign 的 P2PKH 语义（需求 §5 / VLP §3）。
enum class OpId : uint8_t {
  kUnknown = 0,
  kSystemInfo = 1,
  kSystemLock = 2,
  kIdentityProve = 0x11,
  kIdentityAuthorize = 0x12,
  kTxSign = 0x21,
  kTxFeepoolSign = 0x22,
  kChannelPublic = 0x31,
  kChannelHash = 0x32,
  kChannelPrivate = 0x33,
  kChannelSeal = 0x34,
  kChannelOpen = 0x35,
  kSecretSeal = 0x41,
  kSecretOpen = 0x42,
  kContentAttest = 0x51,
  kMigrationImport = 0x71,
  kMigrationExport = 0x72,
  kMigrationStatus = 0x73,
  kRecoveryBackup = 0x81,
};

// 协议草案 §6 的错误类别；wire 码在 Gate 0 冻结为这些枚举值。
// 注意：枚举值是 wire 的一部分，只能新增，不能给已有含义改号。
// 7 = invalid-evidence：随 evidence.receive 撤销而退役，保留空位不复用。
enum class ErrorCode : uint16_t {
  kOk = 0,
  kLocked = 1,
  kBusy = 2,
  kUnsupported = 3,
  kVersionMismatch = 4,
  kWrongKey = 5,
  kInvalidRequest = 6,
  kDeniedOnce = 8,
  kDeniedSession = 9,
  kRevoked = 10,
  kDisconnected = 11,
  kTimeout = 12,
  kResultUnknown = 13,
  kMigrationConflict = 14,
};

i18n::Str ErrorString(ErrorCode e);

struct ExecContext {
  OpId op = OpId::kUnknown;
  uint32_t opVersion = 1;
  policy::Category category = policy::Category::kSystem;

  // 身份/内容
  uint8_t challenge[32] = {0};
  char purpose[64] = {0};
  char intentKind[32] = {0};

  // Channel
  char protocolType[32] = {0};
  uint8_t message[512] = {0};
  size_t messageLen = 0;
  uint8_t peerPub[33] = {0};
  uint8_t senderPub[33] = {0};
  uint8_t ciphertext[512] = {0};
  size_t ciphertextLen = 0;
  uint8_t channelNonce[12] = {0};

  // 本地秘密
  char scope[96] = {0};
  uint8_t plaintext[ops::kPlaintextMax] = {0};
  size_t plaintextLen = 0;
  SealedSecret sealed{};

  // 内容摘要
  char digestHex[80] = {0};
  uint8_t digest[32] = {0};
  char filename[48] = {0};

  // 交易
  TxSignContext tx{};

  // 迁移
  uint8_t importPriv[32] = {0};

  // 本次操作涉及的金额（交易支付总额），用于会话授权的预算判定
  uint64_t valueSats = 0;

  policy::MatchKey match{};
};

enum class PrepareStatus : uint8_t {
  kOk,
  kLocked,
  kMalformed,
  kUnsupported,
  kWrongKey,
  kMigrationConflict,
  kBusy,
};

// 解析请求并生成冻结的评审文档；不产生任何签名或明文外泄。
// commitment 是主机给出的请求承诺，参与授权匹配（32 字节，可为 nullptr）。
PrepareStatus Prepare(const uint8_t* body, size_t bodyLen, uint32_t requestId,
                      ReviewDoc* doc, ExecContext* exec, const uint8_t commitment[32]);

// 执行（必须已获得授权，且执行前再次复核）
ErrorCode Execute(ExecContext& exec, uint8_t* out, size_t outCap, size_t* outLen);

// 迁移状态查询不需要授权
bool MigrationRecord(char* out, size_t cap, size_t* len);
bool MigrationImport(const uint8_t priv[32], const uint8_t expectedPub[33], char* errOut,
                     size_t errCap);

// 一次性导出：只允许在设备菜单进入后、由内部流程调用
bool ExportOnce(const uint8_t* recipientSessionKey, uint8_t* out, size_t cap, size_t* len);

}  // namespace ops
}  // namespace rockey

#endif  // ROCKEY_OPS_DISPATCH_H