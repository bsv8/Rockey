#include "ops/tx.h"

#include <stdio.h>
#include <string.h>

#include "crypto/digest.h"
#include "crypto/ripemd160.h"
#include "crypto/secp256k1.h"
#include "crypto/secure.h"
#include "store/keystore.h"

namespace rockey {
namespace ops {
namespace {

uint16_t ReadU16LE(const uint8_t* p) {
  return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t ReadU32LE(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadU64LE(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
  return v;
}

// 共识 varint（0xfd/0xfe/0xff 前缀）
bool ReadVarInt(const uint8_t* buf, size_t len, size_t* pos, uint64_t* out) {
  if (*pos >= len) return false;
  uint8_t b = buf[(*pos)++];
  if (b < 0xFD) {
    *out = b;
    return true;
  }
  if (b == 0xFD) {
    if (*pos + 2 > len) return false;
    *out = ReadU16LE(buf + *pos);
    *pos += 2;
    return true;
  }
  if (b == 0xFE) {
    if (*pos + 4 > len) return false;
    *out = ReadU32LE(buf + *pos);
    *pos += 4;
    return true;
  }
  if (*pos + 8 > len) return false;
  *out = ReadU64LE(buf + *pos);
  *pos += 8;
  return true;
}

void WriteVarInt(uint8_t* out, uint64_t v) {
  if (v < 0xFD) {
    out[0] = static_cast<uint8_t>(v);
  } else if (v <= 0xFFFF) {
    out[0] = 0xFD;
    out[1] = static_cast<uint8_t>(v);
    out[2] = static_cast<uint8_t>(v >> 8);
  } else {
    out[0] = 0xFE;
    for (int i = 0; i < 4; ++i) out[1 + i] = static_cast<uint8_t>(v >> (8 * i));
  }
}

size_t VarIntSize(uint64_t v) {
  if (v < 0xFD) return 1;
  if (v <= 0xFFFF) return 3;
  return 5;
}

const char* kB58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

size_t Base58Encode(const uint8_t* data, size_t len, char* out, size_t outCap) {
  if (!out || outCap < 2) return 0;
  size_t zeros = 0;
  while (zeros < len && data[zeros] == 0) zeros++;
  uint8_t acc[256];
  size_t accLen = 0;
  for (size_t i = zeros; i < len; ++i) {
    unsigned carry = data[i];
    for (size_t j = 0; j < accLen; ++j) {
      unsigned v = static_cast<unsigned>(acc[j]) * 256u + carry;
      acc[j] = static_cast<uint8_t>(v % 58);
      carry = v / 58;
    }
    while (carry && accLen < sizeof(acc)) {
      acc[accLen++] = static_cast<uint8_t>(carry % 58);
      carry /= 58;
    }
  }
  char tmp[160];
  size_t n = 0;
  while (zeros-- && n + 1 < sizeof(tmp)) tmp[n++] = '1';
  for (size_t j = accLen; j > 0 && n + 1 < sizeof(tmp); --j) tmp[n++] = kB58[acc[j - 1]];
  tmp[n] = '\0';
  if (n + 1 > outCap) return 0;
  memcpy(out, tmp, n + 1);
  return n;
}

void Sha256d(const uint8_t* d, size_t len, uint8_t out[32]) {
  digest::Sha256d(d, len, out);
}

}  // namespace

bool Hash160(const uint8_t* data, size_t len, uint8_t out[20]) {
  uint8_t sha[32];
  digest::Sha256(data, len, sha);
  ripemd::Hash(sha, 32, out);
  secure::Wipe(sha, sizeof(sha));
  return true;
}

size_t BuildP2pkhScript(const uint8_t hash160[20], uint8_t* out, size_t outCap) {
  if (outCap < 25) return 0;
  out[0] = 0x76;  // OP_DUP
  out[1] = 0xA9;  // OP_HASH160
  out[2] = 0x14;  // push 20
  memcpy(out + 3, hash160, 20);
  out[23] = 0x88;  // OP_EQUALVERIFY
  out[24] = 0xAC;  // OP_CHECKSIG
  return 25;
}

bool ParseP2pkhScript(const uint8_t* script, size_t len, uint8_t hash160Out[20]) {
  if (len != 25) return false;
  if (script[0] != 0x76 || script[1] != 0xA9 || script[2] != 0x14) return false;
  if (script[23] != 0x88 || script[24] != 0xAC) return false;
  memcpy(hash160Out, script + 3, 20);
  return true;
}

bool P2pkhAddressFromHash160(const uint8_t hash160[20], char* out, size_t outCap) {
  if (!hash160 || !out || outCap < 2) return false;
  uint8_t payload[1 + 20];
  payload[0] = kP2pkhVersionMainnet;
  memcpy(payload + 1, hash160, 20);
  uint8_t checksum[32];
  digest::Sha256d(payload, sizeof(payload), checksum);
  uint8_t full[1 + 20 + 4];
  memcpy(full, payload, sizeof(payload));
  memcpy(full + sizeof(payload), checksum, 4);
  secure::Wipe(checksum, sizeof(checksum));
  return Base58Encode(full, sizeof(full), out, outCap) > 0;
}

bool P2pkhAddress(const uint8_t pub33[33], char* out, size_t outCap) {
  uint8_t h[20];
  if (!Hash160(pub33, 33, h)) return false;
  return P2pkhAddressFromHash160(h, out, outCap);
}

TxParseError ParseTx(const uint8_t* raw, size_t len, ParsedTx* out) {
  memset(out, 0, sizeof(*out));
  if (!raw || len == 0) return TxParseError::kMalformed;
  if (len > kMaxTxBytes) return TxParseError::kTooLarge;
  size_t pos = 0;
  if (len < 10) return TxParseError::kMalformed;
  out->version = ReadU32LE(raw + pos);
  pos += 4;

  uint64_t nIn = 0;
  if (!ReadVarInt(raw, len, &pos, &nIn)) return TxParseError::kMalformed;
  if (nIn == 0 || nIn > kMaxInputs) return TxParseError::kTooManyInputs;
  out->inputCount = static_cast<uint32_t>(nIn);

  for (uint64_t i = 0; i < nIn; ++i) {
    if (pos + 36 > len) return TxParseError::kMalformed;
    memcpy(out->inputTxid[i], raw + pos, 32);
    pos += 32;
    out->inputVout[i] = ReadU32LE(raw + pos);
    pos += 4;
    uint64_t sl = 0;
    if (!ReadVarInt(raw, len, &pos, &sl)) return TxParseError::kMalformed;
    if (sl > len - pos) return TxParseError::kMalformed;
    if (sl > 1000) return TxParseError::kScriptTooLong;
    pos += sl;
    if (pos + 4 > len) return TxParseError::kMalformed;
    out->sequence[i] = ReadU32LE(raw + pos);
    pos += 4;
  }

  uint64_t nOut = 0;
  if (!ReadVarInt(raw, len, &pos, &nOut)) return TxParseError::kMalformed;
  if (nOut == 0 || nOut > kMaxOutputs) return TxParseError::kTooManyOutputs;
  out->outputCount = static_cast<uint32_t>(nOut);

  for (uint64_t i = 0; i < nOut; ++i) {
    if (pos + 8 > len) return TxParseError::kMalformed;
    uint64_t v = ReadU64LE(raw + pos);
    pos += 8;
    uint64_t sl = 0;
    if (!ReadVarInt(raw, len, &pos, &sl)) return TxParseError::kMalformed;
    if (sl > len - pos) return TxParseError::kMalformed;
    if (sl > kMaxScriptLen) return TxParseError::kScriptTooLong;
    out->outputs[i].satoshis = v;
    out->outputs[i].scriptLen = static_cast<uint16_t>(sl);
    memcpy(out->outputs[i].script, raw + pos, sl);
    pos += sl;
    out->totalOut += v;
  }

  if (pos + 4 != len) return TxParseError::kMalformed;
  out->locktime = ReadU32LE(raw + pos);
  return TxParseError::kOk;
}

namespace {

void PutU32LE(uint8_t* out, size_t* o, uint32_t v) {
  for (int k = 0; k < 4; ++k) out[(*o)++] = static_cast<uint8_t>(v >> (8 * k));
}

void PutU64LE(uint8_t* out, size_t* o, uint64_t v) {
  for (int k = 0; k < 8; ++k) out[(*o)++] = static_cast<uint8_t>(v >> (8 * k));
}

// 组装签名预映像（BSV SIGHASH_ALL|FORKID）。单独拆出来是为了能在主机上
// 逐字节断言序列化顺序 —— 少一个字段或多一个字段算出来的 sighash 完全不同，
// 而真机上只看"签名能不能验过"是发现不了的。
//
// 字段顺序（BSV BIP143 风格）：
//   nVersion(4) hashPrevouts(32) hashSequence(32) outpoint(36)
//   scriptCode(varint+bytes) amount(8) nSequence(4) hashOutputs(32)
//   nLockTime(4) nHashType(4)
bool BuildSighashPreimage(const ParsedTx& tx, uint32_t inputIndex, const PrevOut& target,
                          const uint8_t hashPrevouts[32], const uint8_t hashSequence[32],
                          const uint8_t hashOutputs[32], uint8_t* out, size_t cap, size_t* outLen) {
  // 容量必须先算再写：固定部分 4+32+32+32+4，脚本 varint+bytes，
  // 再加 amount(8) + nSequence(4) + hashOutputs(32) + locktime(4) + hashtype(4)。
  size_t sv = VarIntSize(target.scriptLen);
  size_t need = 4 + 32 + 32 + 32 + 4 + sv + target.scriptLen + 8 + 4 + 32 + 4 + 4;
  if (need > cap) return false;

  size_t n = 0;
  PutU32LE(out, &n, tx.version);
  memcpy(out + n, hashPrevouts, 32);
  n += 32;
  memcpy(out + n, hashSequence, 32);
  n += 32;
  memcpy(out + n, tx.inputTxid[inputIndex], 32);
  n += 32;
  PutU32LE(out, &n, tx.inputVout[inputIndex]);
  WriteVarInt(out + n, target.scriptLen);
  n += sv;
  memcpy(out + n, target.script, target.scriptLen);
  n += target.scriptLen;
  PutU64LE(out, &n, target.satoshis);
  // 被签输入的完整 nSequence —— 这里以前整个漏掉，算出来的 sighash 是错的
  PutU32LE(out, &n, tx.sequence[inputIndex]);
  memcpy(out + n, hashOutputs, 32);
  n += 32;
  PutU32LE(out, &n, tx.locktime);
  PutU32LE(out, &n, kSighashAllForkId);
  *outLen = n;
  return true;
}

// 重放序列化并计算 sighash（BSV：SIGHASH_ALL | FORKID）
bool ComputeSighash(const TxSignContext& ctx, const ParsedTx& tx, uint8_t out[32]) {
  if (ctx.inputIndex >= tx.inputCount) return false;

  // hashPrevouts
  uint8_t prevBuf[kMaxInputs * 36];
  for (uint32_t i = 0; i < tx.inputCount; ++i) {
    memcpy(prevBuf + i * 36, tx.inputTxid[i], 32);
    uint32_t v = tx.inputVout[i];
    memcpy(prevBuf + i * 36 + 32, &v, 4);
  }
  uint8_t hPrev[32], hSeq[32], hOut[32];
  Sha256d(prevBuf, tx.inputCount * 36, hPrev);

  // hashSequence：每个输入的**完整 4 字节** nSequence
  uint8_t seqBuf[kMaxInputs * 4];
  {
    size_t so = 0;
    for (uint32_t i = 0; i < tx.inputCount; ++i) {
      PutU32LE(seqBuf, &so, tx.sequence[i]);
    }
  }
  Sha256d(seqBuf, tx.inputCount * 4, hSeq);

  // hashOutputs：按每个输出的真实脚本长度累加，缓冲必须按 kMaxScriptLen 定尺，
  // 不能假设脚本只有 9 字节 —— 那是 P2PKH 的特例。
  uint8_t outBuf[kMaxOutputs * (8 + 5 + kMaxScriptLen)];
  size_t o = 0;
  for (uint32_t i = 0; i < tx.outputCount; ++i) {
    size_t vi = VarIntSize(tx.outputs[i].scriptLen);
    if (o + 8 + vi + tx.outputs[i].scriptLen > sizeof(outBuf)) return false;
    PutU64LE(outBuf, &o, tx.outputs[i].satoshis);
    WriteVarInt(outBuf + o, tx.outputs[i].scriptLen);
    o += vi;
    memcpy(outBuf + o, tx.outputs[i].script, tx.outputs[i].scriptLen);
    o += tx.outputs[i].scriptLen;
  }
  Sha256d(outBuf, o, hOut);

  const PrevOut* target = nullptr;
  for (size_t i = 0; i < ctx.prevoutCount; ++i) {
    if (ctx.prevouts[i].vout == tx.inputVout[ctx.inputIndex] &&
        memcmp(ctx.prevouts[i].txid, tx.inputTxid[ctx.inputIndex], 32) == 0) {
      target = &ctx.prevouts[i];
      break;
    }
  }
  if (!target) return false;

  uint8_t pre[512];
  size_t preLen = 0;
  if (!BuildSighashPreimage(tx, ctx.inputIndex, *target, hPrev, hSeq, hOut, pre, sizeof(pre),
                            &preLen)) {
    return false;
  }
  Sha256d(pre, preLen, out);
  return true;
}

}  // namespace

// 导出给主机侧测试逐字节断言序列化顺序
bool OpsBuildSighashPreimage(const ParsedTx& tx, uint32_t inputIndex, const PrevOut& target,
                             const uint8_t hashPrevouts[32], const uint8_t hashSequence[32],
                             const uint8_t hashOutputs[32], uint8_t* out, size_t cap,
                             size_t* outLen) {
  if (inputIndex >= tx.inputCount) return false;
  return BuildSighashPreimage(tx, inputIndex, target, hashPrevouts, hashSequence, hashOutputs, out,
                              cap, outLen);
}

TxReview ReviewTx(const TxSignContext& ctx) {
  TxReview r;
  // 找零归属与"前序是否属于自己"都靠设备自己的公钥判定；缺它就不能继续。
  if (!ctx.raw || ctx.rawLen == 0 || !ctx.pub33) {
    r.error = TxReviewError::kMalformed;
    return r;
  }
  ParsedTx tx;
  TxParseError pe = ParseTx(ctx.raw, ctx.rawLen, &tx);
  if (pe != TxParseError::kOk) {
    r.error = TxReviewError::kMalformed;
    return r;
  }
  if (ctx.inputIndex >= tx.inputCount) {
    r.error = TxReviewError::kSignedInputNotOurs;
    return r;
  }

  // 输入证据核对
  uint8_t ourHash[20];
  Hash160(ctx.pub33, 33, ourHash);
  for (uint32_t i = 0; i < tx.inputCount; ++i) {
    const PrevOut* ev = nullptr;
    for (size_t j = 0; j < ctx.prevoutCount; ++j) {
      if (ctx.prevouts[j].vout == tx.inputVout[i] &&
          memcmp(ctx.prevouts[j].txid, tx.inputTxid[i], 32) == 0) {
        ev = &ctx.prevouts[j];
        break;
      }
    }
    if (!ev) {
      r.error = TxReviewError::kInputMissingEvidence;
      return r;
    }
    uint8_t h[20];
    if (!ParseP2pkhScript(ev->script, ev->scriptLen, h)) {
      r.error = TxReviewError::kPrevoutNotP2pkh;
      return r;
    }
    r.totalIn += ev->satoshis;
    memcpy(r.inputHash160s[i], h, 20);
    if (!ev->provenOnChain) r.anyUnproven = true;
  }
  r.totalOut = tx.totalOut;
  if (r.totalIn < r.totalOut) {
    r.error = TxReviewError::kFeeOverflow;
    return r;
  }
  r.fee = r.totalIn - r.totalOut;

  // 被签的那个输入，其前序收款地址必须是本设备公钥派生出来的 hash160。
  // 不查这一项的话，主机可以把任意一个别人的 UTXO 指成 inputIndex，
  // 设备照样算 sighash、照样签，签出来的东西归属不明。
  {
    uint8_t ourHash[20];
    Hash160(ctx.pub33, 33, ourHash);
    if (memcmp(r.inputHash160s[ctx.inputIndex], ourHash, 20) != 0) {
      r.error = TxReviewError::kSignedInputNotOurs;
      return r;
    }
  }

  // 输出分类：只接受 P2PKH
  bool haveChange = false;
  for (uint32_t i = 0; i < tx.outputCount; ++i) {
    uint8_t h[20];
    if (!ParseP2pkhScript(tx.outputs[i].script, tx.outputs[i].scriptLen, h)) {
      r.error = TxReviewError::kUnknownScript;
      return r;
    }
    if (memcmp(h, ourHash, 20) == 0) {
      haveChange = true;
      r.changeSats += tx.outputs[i].satoshis;
    } else {
      // 收款方与金额由设备从输出脚本解出来：界面上展示的付款清单
      // 一定来自待签交易本身，不是主机给的标签。
      r.payCount++;
      if (r.payRecorded < kMaxPayOutputs) {
        r.pays[r.payRecorded].satoshis = tx.outputs[i].satoshis;
        memcpy(r.pays[r.payRecorded].hash160, h, 20);
        r.payRecorded++;
      } else {
        r.truncatedPays = true;
      }
    }
  }
  if (r.payCount == 0) {
    r.error = TxReviewError::kNoChange;
    return r;
  }
  if (!haveChange) {
    r.error = TxReviewError::kChangeNotOurs;
    return r;
  }
  if (!P2pkhAddress(ctx.pub33, r.changeAddress, sizeof(r.changeAddress))) {
    r.error = TxReviewError::kMalformed;
    return r;
  }
  r.sighashType = kSighashAllForkId;
  if (!ComputeSighash(ctx, tx, r.sighash)) {
    r.error = TxReviewError::kMalformed;
    return r;
  }
  r.ok = true;
  return r;
}

bool SignInput(const TxSignContext& ctx, uint8_t derOut[72], size_t* derLen) {
  TxReview r = ReviewTx(ctx);
  if (!r.ok) return false;
  const uint8_t* priv = keystore::KeyStore::PrivateKey();
  if (!priv) return false;
  size_t cap = *derLen;
  if (!secp::SignDer(priv, r.sighash, derOut, &cap)) return false;
  *derLen = cap;
  return true;
}

}  // namespace ops
}  // namespace rockey