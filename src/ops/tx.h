// BSV 交易：脚本解析、地址、P2PKH sighash 自算与签署。
//
// 设备责任（协议草案 §4 TRANSACTION）：
//  - 主机提交原始交易字节 + 前序输出证据；设备自行解析、重建序列化、
//    自行计算 hashPrevouts/hashSequence/hashOutputs 与 sighash；
//  - 核对每个输入的 txid/vout/金额/脚本绑定，只接受 P2PKH 前序；
//  - 找零必须付给由当前设备公钥派生的地址；任何未知脚本、无法解释的资产都拒绝；
//  - 不信任主机的 change 标签或 fee 文本（fee 由设备自己减出来）。
//  - 设备只能核对"字节与声明自洽"，不等于已验证链上未花费；界面如实标注。
#ifndef ROCKEY_OPS_TX_H
#define ROCKEY_OPS_TX_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace ops {

constexpr size_t kMaxInputs = 16;
constexpr size_t kMaxOutputs = 32;
constexpr size_t kMaxScriptLen = 128;
constexpr size_t kMaxTxBytes = 8192;
constexpr uint8_t kSighashAllForkId = 0x41;
constexpr uint8_t kP2pkhVersionMainnet = 0x00;

// ripemd160(sha256(x)) 与 Base58Check 地址
bool Hash160(const uint8_t* data, size_t len, uint8_t out[20]);
// BSV 主网 P2PKH 地址（版本字节 0x00）
bool P2pkhAddress(const uint8_t pub33[33], char* out, size_t outCap);
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
  uint8_t sequence[kMaxInputs] = {0};
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

struct TxReview {
  bool ok = false;
  TxReviewError error = TxReviewError::kOk;
  uint64_t totalIn = 0;
  uint64_t totalOut = 0;
  uint64_t fee = 0;
  uint64_t changeSats = 0;
  uint32_t payCount = 0;          // 付给其它地址的输出个数
  bool anyUnproven = false;       // 前序未提供链上证明
  char changeAddress[36] = {0};   // 设备自己算出的找零地址
  uint8_t sighashType = kSighashAllForkId;
  uint8_t sighash[32] = {0};
};

// 只做核验与摘要，不签名
TxReview ReviewTx(const TxSignContext& ctx);
// 核验通过后生成 DER 签名（低 S），调用者负责拼进 scriptSig
bool SignInput(const TxSignContext& ctx, uint8_t derOut[72], size_t* derLen);

}  // namespace ops
}  // namespace rockey

#endif  // ROCKEY_OPS_TX_H