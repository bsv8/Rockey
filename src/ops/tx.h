// BSV 交易：脚本解析、地址、P2PKH sighash 自算与签署。
//
// 设备责任（协议草案 §4 TRANSACTION）：
//  - 主机提交原始交易字节 + 前序输出证据；设备自行解析、重建序列化、
//    自行计算 hashPrevouts/hashSequence/hashOutputs 与 sighash；
//  - 核对每个输入的 txid/vout/金额/脚本绑定，只接受 P2PKH 前序；
//  - 找零必须付给由当前设备公钥派生的地址；任何未知脚本、无法解释的资产都拒绝；
//  - 不信任主机的 change 标签或 fee 文本（fee 由设备自己减出来）。
//  - 设备只能核对"字节与声明自洽"，不等于已验证链上未花费；界面如实标注。
//
// **这个解析器就是 P2PKH 支持集本身**：费用池（池脚本、多签、双方/三方顺序、
// 锁定与退款条件）在脚本与阶段冻结前不得走这里，设备对 tx.feepool-sign
// 明确拒绝（见 ops/dispatch.cpp 的冻结门禁）。非 P2PKH 的脚本在这里一律
// 按未知脚本拒绝，不会被解释成普通 P2PKH 展示。
#ifndef ROCKEY_OPS_TX_H
#define ROCKEY_OPS_TX_H

#include <stdint.h>
#include <stddef.h>

#include "core/rockey_config.h"

namespace rockey {
namespace ops {

constexpr size_t kMaxInputs = 16;
constexpr size_t kMaxOutputs = 32;
constexpr size_t kMaxScriptLen = 128;
// 单帧可送达的上限：REQUEST 信封（requestId/sessionId/三个世代/commitment）
// 与交易请求体共用同一条加密帧，明文不能超过 ROCKEY_MAX_PLAINTEXT。
// 384 字节是信封与 op 字段的 CBOR 开销 + 若干组前序证据的余量。
// 超过这个大小的交易需要**有界分片传输**，而分片规则尚未冻结 ——
// 在那之前明确不可用，不能宣称支持（VLP §5：交易容量决定是否需要有界分片）。
constexpr size_t kMaxTxBytes = ROCKEY_MAX_PLAINTEXT - 384;
static_assert(kMaxTxBytes + 384 <= ROCKEY_MAX_PLAINTEXT,
              "tx body + request envelope must stay within one encrypted frame");
// 对外声明的协议级上限必须与这里的实际生效值一致，否则就是宣称一个到不了的能力
static_assert(kMaxTxBytes == ROCKEY_TX_MAX_TX_BYTES, "declared tx bound drifted from the real one");
static_assert(kMaxInputs == ROCKEY_TX_MAX_INPUTS, "declared input bound drifted from the real one");
static_assert(kMaxOutputs == ROCKEY_TX_MAX_OUTPUTS, "declared output bound drifted from the real one");
constexpr uint8_t kSighashAllForkId = 0x41;
constexpr uint8_t kP2pkhVersionMainnet = 0x00;

// ripemd160(sha256(x)) 与 Base58Check 地址
bool Hash160(const uint8_t* data, size_t len, uint8_t out[20]);
// BSV 主网 P2PKH 地址（版本字节 0x00）
bool P2pkhAddress(const uint8_t pub33[33], char* out, size_t outCap);
// 已知 hash160 时直接出地址（付款明细用：地址来自交易输出脚本本身）
bool P2pkhAddressFromHash160(const uint8_t hash160[20], char* out, size_t outCap);
// 由 20 字节 hash160 判断 P2PKH 脚本并取出 hash
bool ParseP2pkhScript(const uint8_t* script, size_t len, uint8_t hash160Out[20]);
size_t BuildP2pkhScript(const uint8_t hash160[20], uint8_t* out, size_t outCap);

struct PrevOut {
  uint8_t txid[32] = {0};  // 与 raw tx 相同的字节序
  uint32_t vout = 0;
  uint64_t satoshis = 0;
  uint8_t script[kMaxScriptLen] = {0};
  uint16_t scriptLen = 0;
  bool provenOnChain = false;
};

struct TxOutputInfo {
  uint64_t satoshis = 0;
  uint8_t script[kMaxScriptLen] = {0};
  uint16_t scriptLen = 0;
};

struct ParsedTx {
  uint32_t version = 0;
  uint32_t inputCount = 0;
  uint32_t outputCount = 0;
  // 完整 4 字节 nSequence。只保留最高字节会让 hashSequence 与签名预映像
  // 都算错 —— BSV 常见的 nSequence 是 0xFFFFFFFF/0xFFFFFFFE，不是小数值。
  uint32_t sequence[kMaxInputs] = {0};
  uint8_t inputTxid[kMaxInputs][32] = {{0}};
  uint32_t inputVout[kMaxInputs] = {0};
  TxOutputInfo outputs[kMaxOutputs]{};
  uint32_t locktime = 0;
  uint64_t totalIn = 0;
  uint64_t totalOut = 0;
  uint64_t fee = 0;
};

enum class TxParseError : uint8_t {
  kOk,
  kTooLarge,
  kMalformed,
  kTooManyInputs,
  kTooManyOutputs,
  kScriptTooLong,
  kUnsupported,
};

TxParseError ParseTx(const uint8_t* raw, size_t len, ParsedTx* out);

struct TxSignContext {
  const uint8_t* raw = nullptr;
  size_t rawLen = 0;
  const PrevOut* prevouts = nullptr;
  size_t prevoutCount = 0;
  uint32_t inputIndex = 0;
  const uint8_t* pub33 = nullptr;
  uint8_t networkVersion = kP2pkhVersionMainnet;
};

enum class TxReviewError : uint8_t {
  kOk,
  kMalformed,
  kInputMissingEvidence,
  kAmountMismatch,
  kPrevoutNotP2pkh,
  kSignedInputNotOurs,
  kUnknownScript,
  kFeeOverflow,
  kNoChange,
  kChangeNotOurs,
  kUnprovenInputs,
};

// 一笔付款输出：地址与金额都由设备从 raw tx 的输出脚本自己解析出来，
// 不接受主机提供的收款方标签（需求 §5：不信任主机的 change 标签或金额文本）。
struct PayOutput {
  uint64_t satoshis = 0;
  uint8_t hash160[20] = {0};
};

constexpr size_t kMaxPayOutputs = 8;

struct TxReview {
  bool ok = false;
  TxReviewError error = TxReviewError::kOk;
  uint64_t totalIn = 0;
  uint64_t totalOut = 0;
  uint64_t fee = 0;
  uint64_t changeSats = 0;
  uint32_t payCount = 0;          // 付给其它地址的输出个数
  bool anyUnproven = false;       // 前序未提供链上证明
  bool truncatedPays = false;     // 付款输出超过 kMaxPayOutputs，只列出前几个
  PayOutput pays[kMaxPayOutputs]{};
  uint32_t payRecorded = 0;
  uint8_t inputHash160s[kMaxInputs][20] = {{0}};  // 各输入前序的收款 hash160
  char changeAddress[36] = {0};   // 设备自己算出的找零地址
  uint8_t sighashType = kSighashAllForkId;
  uint8_t sighash[32] = {0};
};

// 只做核验与摘要，不签名
TxReview ReviewTx(const TxSignContext& ctx);
// 核验通过后生成 DER 签名（低 S），调用者负责拼进 scriptSig
bool SignInput(const TxSignContext& ctx, uint8_t derOut[72], size_t* derLen);

// 单独导出签名预映像的组装，供主机侧测试逐字节断言序列化顺序。
// 三个 hash 由调用方算好传入，这里只负责字节排列。
bool OpsBuildSighashPreimage(const ParsedTx& tx, uint32_t inputIndex, const PrevOut& target,
                             const uint8_t hashPrevouts[32], const uint8_t hashSequence[32],
                             const uint8_t hashOutputs[32], uint8_t* out, size_t cap,
                             size_t* outLen);

}  // namespace ops
}  // namespace rockey

#endif  // ROCKEY_OPS_TX_H