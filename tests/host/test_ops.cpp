// 主机侧测试（需要 mbedtls）：编译 src/ 里的真实实现跑 BSV 交易与授权策略。
//
// 这一组针对几类"肉眼看不出来、只能逐字节断言"的缺陷：
//  - sighash 预映像的字段顺序与 nSequence 完整性；
//  - Base58Check 校验和只取 4 字节（曾经越界写 28 字节）；
//  - 被签输入必须真的属于设备公钥；
//  - 付款明细由设备从输出脚本解出，而不是主机给的标签；
//  - 持续授权的撤销定位、限额生效、以及"未决定不得当成允许"。
//
// 需要本机 mbedtls（开发机为 Homebrew 的 3.6.4）。
// 注意：设备目标用的是 ESP-IDF 自带的 mbedtls 2.28，API 兼容但版本不同；
// 这里验证的是序列化与状态机逻辑，不替代真机上的密码学验收。
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#include "crypto/digest.h"
#include "crypto/ripemd160.h"
#include "crypto/secure.h"
#include "crypto/secp256k1.h"
#include "ops/tx.h"
#include "policy/policy.h"

using rockey::ops::kMaxScriptLen;
using rockey::ops::ParsedTx;
using rockey::ops::ParseTx;
using rockey::ops::P2pkhAddress;
using rockey::ops::P2pkhAddressFromHash160;
using rockey::ops::PayOutput;
using rockey::ops::PrevOut;
using rockey::ops::ReviewTx;
using rockey::ops::TxParseError;
using rockey::ops::TxReview;
using rockey::ops::TxSignContext;
using rockey::policy::Decision;
using rockey::policy::EvalResult;
using rockey::policy::MatchKey;
using rockey::policy::PersistentDecisionAllowed;
using rockey::policy::Policy;

namespace {

int g_pass = 0;
int g_fail = 0;
const char* g_case = "";

void Begin(const char* name) { g_case = name; }

void Check(bool cond, const char* what) {
  if (cond) {
    g_pass++;
  } else {
    g_fail++;
    printf("  FAIL [%s] %s\n", g_case, what);
  }
}

// ── 交易构造辅助 ────────────────────────────────────────────────────

void PushU32(std::vector<uint8_t>* v, uint32_t x) {
  for (int i = 0; i < 4; ++i) v->push_back(static_cast<uint8_t>(x >> (8 * i)));
}
void PushU64(std::vector<uint8_t>* v, uint64_t x) {
  for (int i = 0; i < 8; ++i) v->push_back(static_cast<uint8_t>(x >> (8 * i)));
}
void PushVarInt(std::vector<uint8_t>* v, uint64_t x) {
  if (x < 0xFD) {
    v->push_back(static_cast<uint8_t>(x));
  } else if (x <= 0xFFFF) {
    v->push_back(0xFD);
    v->push_back(static_cast<uint8_t>(x));
    v->push_back(static_cast<uint8_t>(x >> 8));
  } else {
    v->push_back(0xFE);
    for (int i = 0; i < 4; ++i) v->push_back(static_cast<uint8_t>(x >> (8 * i)));
  }
}

// secp256k1 基点 G（= 私钥 1）的压缩公钥，公开常量。
// 用它而不是在测试里现算：开发机上的 mbedtls 3.6 与设备目标的 2.28 在
// mbedtls_ecp_mul 上行为不同（3.6 返回 BAD_INPUT_DATA），
// 密钥推导路径因此不在本测试覆盖范围内 —— 真实实现由固件 SelfTest 覆盖。
const uint8_t kPub33[33] = {0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0,
                            0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE,
                            0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};

// 由上面这个公钥独立算出的 BSV 主网 P2PKH 地址
// （hash160 = 751e76e8199196d454941c45d1b3a323f1433bd6，
//  Base58Check 前 4 字节校验和）。
const char* kExpectedAddr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

void BuildP2pkh(std::vector<uint8_t>* v, const uint8_t hash160[20]) {
  v->push_back(0x76);
  v->push_back(0xA9);
  v->push_back(0x14);
  v->insert(v->end(), hash160, hash160 + 20);
  v->push_back(0x88);
  v->push_back(0xAC);
}

// 一笔 1 输入 2 输出（1 付款 + 1 找零）的交易。
// nSequence 固定为 0xFFFFFFFF：这是 BSV 常见取值，正好用来暴露
// "只保留最高字节"的那类截断错误。
std::vector<uint8_t> BuildTx(const uint8_t txid[32], uint32_t vout, uint32_t sequence,
                             const uint8_t ourH160[20], const uint8_t payeeH160[20],
                             uint64_t inSats, uint64_t paySats, uint64_t changeSats) {
  std::vector<uint8_t> v;
  PushU32(&v, 1);  // version
  PushVarInt(&v, 1);
  v.insert(v.end(), txid, txid + 32);
  PushU32(&v, vout);
  PushVarInt(&v, 0);  // scriptSig
  PushU32(&v, sequence);
  PushVarInt(&v, 2);
  PushU64(&v, paySats);
  PushVarInt(&v, 25);
  BuildP2pkh(&v, payeeH160);
  PushU64(&v, changeSats);
  PushVarInt(&v, 25);
  BuildP2pkh(&v, ourH160);
  PushU32(&v, 0);  // locktime
  (void)inSats;
  return v;
}

void Hash160Of(const uint8_t* data, size_t len, uint8_t out[20]) {
  rockey::ops::Hash160(data, len, out);
}

}  // namespace

namespace {

uint8_t g_priv[32] = {0};
uint8_t g_pub[33] = {0};
uint8_t g_ourH160[20] = {0};
uint8_t g_payeeH160[20] = {0};
uint8_t g_txid[32] = {0};

void SetupFixtures() {
  for (int i = 0; i < 32; ++i) {
    g_priv[i] = static_cast<uint8_t>(0x11 + i);
    g_txid[i] = static_cast<uint8_t>(0x40 + i);
  }
  memcpy(g_pub, kPub33, 33);
  Hash160Of(g_pub, 33, g_ourH160);
  // 收款方用另一个公开公钥（G 的 x + 1，合法曲线点之外的取值不参与解析，
  // 这里只需要一个与设备自身不同的 hash160 即可）
  uint8_t payee[33];
  memcpy(payee, kPub33, 33);
  payee[31] ^= 0x01;
  Hash160Of(payee, 33, g_payeeH160);
}

// ── 1. Base58Check 地址 ─────────────────────────────────────────────

void TestAddress() {
  Begin("tx/address");
  char addr[64] = {0};
  Check(P2pkhAddress(g_pub, addr, sizeof(addr)), "P2pkhAddress succeeds");
  // 独立向量：privkey=1 的 P2PKH 地址。用它同时校验 hash160 与 Base58Check
  // （版本字节、4 字节校验和、小数除法进位）。
  Check(strcmp(addr, kExpectedAddr) == 0, "address matches the independently derived vector");
  Check(addr[0] == '1', "mainnet address starts with '1'");

  char addr2[64] = {0};
  Check(P2pkhAddressFromHash160(g_ourH160, addr2, sizeof(addr2)), "FromHash160 succeeds");
  Check(strcmp(addr, addr2) == 0, "both address paths agree");

  // 越界回归：以前这里是 payload[25] 上写 32 字节摘要（超出 28 字节），
  // ASan 会在这一行直接报错。
  char small[40] = {0};
  Check(P2pkhAddress(g_pub, small, 8) == false, "output buffer too small is refused");
  Check(small[0] == '\0' || strlen(small) < 40, "no overflow of the caller's buffer");
}

// ── 2. sequence 完整保存 ───────────────────────────────────────────

void TestSequenceRoundTrip() {
  Begin("tx/sequence");
  std::vector<uint8_t> raw = BuildTx(g_txid, 0, 0xFFFFFFFFu, g_ourH160, g_payeeH160, 100000, 40000,
                                     59900);
  ParsedTx tx;
  Check(ParseTx(raw.data(), raw.size(), &tx) == TxParseError::kOk, "tx parses");
  // 旧实现只保留 raw[pos+3]，0xFFFFFFFF 会变成 255
  Check(tx.sequence[0] == 0xFFFFFFFFu, "nSequence kept as full 32-bit value");

  std::vector<uint8_t> raw2 = BuildTx(g_txid, 0, 0x12345678u, g_ourH160, g_payeeH160, 100000, 40000,
                                      59900);
  ParsedTx tx2;
  ParseTx(raw2.data(), raw2.size(), &tx2);
  Check(tx2.sequence[0] == 0x12345678u, "arbitrary nSequence preserved exactly");
}

// ── 3. sighash 预映像逐字节 ────────────────────────────────────────

void TestSighashPreimage() {
  Begin("tx/sighash-preimage");
  ParsedTx tx;
  tx.version = 1;
  tx.inputCount = 1;
  tx.sequence[0] = 0xDEADBEEFu;
  memcpy(tx.inputTxid[0], g_txid, 32);
  tx.inputVout[0] = 7;
  tx.locktime = 0;

  PrevOut target{};
  memcpy(target.txid, g_txid, 32);
  target.vout = 7;
  target.satoshis = 123456;
  target.scriptLen = static_cast<uint16_t>(rockey::ops::BuildP2pkhScript(g_ourH160, target.script,
                                                                         kMaxScriptLen));

  uint8_t hPrev[32], hSeq[32], hOut[32];
  memset(hPrev, 0xA1, 32);
  memset(hSeq, 0xB2, 32);
  memset(hOut, 0xC3, 32);

  uint8_t pre[512];
  size_t n = 0;
  bool ok = rockey::ops::OpsBuildSighashPreimage(tx, 0, target, hPrev, hSeq, hOut, pre, sizeof(pre),
                                                 &n);
  Check(ok, "preimage built");

  size_t expect = 4 + 32 + 32 + 32 + 4 + 1 + 25 + 8 + 4 + 32 + 4 + 4;
  Check(n == expect, "preimage length matches the documented field list");

  size_t o = 0;
  auto u32 = [&](void) -> uint32_t {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(pre[o++]) << (8 * i);
    return v;
  };
  auto u64 = [&](void) -> uint64_t {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(pre[o++]) << (8 * i);
    return v;
  };
  Check(u32() == 1, "nVersion LE");
  Check(memcmp(pre + o, hPrev, 32) == 0, "hashPrevouts"), o += 32;
  Check(memcmp(pre + o, hSeq, 32) == 0, "hashSequence"), o += 32;
  Check(memcmp(pre + o, g_txid, 32) == 0, "outpoint txid"), o += 32;
  Check(u32() == 7, "outpoint vout");
  Check(pre[o] == 25, "scriptCode varint length"), o += 1;
  Check(memcmp(pre + o, target.script, 25) == 0, "scriptCode bytes"), o += 25;
  Check(u64() == 123456, "amount");
  // 这一项以前整个漏掉：少了它算出来的 sighash 一定是错的
  Check(u32() == 0xDEADBEEFu, "nSequence of the signed input is present");
  Check(memcmp(pre + o, hOut, 32) == 0, "hashOutputs"), o += 32;
  Check(u32() == 0, "nLockTime");
  Check(u32() == rockey::ops::kSighashAllForkId, "nHashType");
  Check(o == n, "consumed exactly the reported length");

  // 容量不足必须拒绝而不是越界写
  uint8_t tiny[8];
  size_t n2 = 0;
  Check(!rockey::ops::OpsBuildSighashPreimage(tx, 0, target, hPrev, hSeq, hOut, tiny, sizeof(tiny),
                                              &n2),
        "undersized output buffer refused");
}

// ── 4. ReviewTx 的归属与收款明细 ───────────────────────────────────

void TestReviewTx() {
  Begin("tx/review");
  PrevOut prev{};
  memcpy(prev.txid, g_txid, 32);
  prev.vout = 0;
  prev.satoshis = 100000;
  prev.provenOnChain = true;
  prev.scriptLen = static_cast<uint16_t>(
      rockey::ops::BuildP2pkhScript(g_ourH160, prev.script, kMaxScriptLen));

  std::vector<uint8_t> raw =
      BuildTx(g_txid, 0, 0xFFFFFFFFu, g_ourH160, g_payeeH160, 100000, 40000, 59900);

  TxSignContext ctx{};
  ctx.raw = raw.data();
  ctx.rawLen = raw.size();
  ctx.prevouts = &prev;
  ctx.prevoutCount = 1;
  ctx.inputIndex = 0;
  ctx.pub33 = g_pub;

  TxReview rv = ReviewTx(ctx);
  Check(rv.ok, "review succeeds");
  Check(rv.totalIn == 100000, "totalIn from prevout evidence");
  Check(rv.totalOut == 40000 + 59900, "totalOut from raw tx");
  Check(rv.fee == 100000 - (40000 + 59900), "fee computed by the device, not taken from host");
  Check(rv.payCount == 1, "one paying output");
  Check(rv.payRecorded == 1, "one payee recorded");
  if (rv.payRecorded == 1) {
    Check(rv.pays[0].satoshis == 40000, "payee amount comes from the tx output");
    Check(memcmp(rv.pays[0].hash160, g_payeeH160, 20) == 0,
          "payee hash160 decoded from the output script");
  }
  Check(strlen(rv.changeAddress) > 0, "change address derived by the device");

  // 前序不属于自己：必须拒绝
  {
    PrevOut foreign{};
    memcpy(foreign.txid, g_txid, 32);
    foreign.vout = 0;
    foreign.satoshis = 100000;
    foreign.scriptLen = static_cast<uint16_t>(
        rockey::ops::BuildP2pkhScript(g_payeeH160, foreign.script, kMaxScriptLen));
    TxSignContext c2 = ctx;
    c2.prevouts = &foreign;
    TxReview r2 = ReviewTx(c2);
    Check(!r2.ok, "prevout not belonging to the device is rejected");
  }

  // proven 由主机声明：false 时必须保留未验证提示
  {
    PrevOut unproven = prev;
    unproven.provenOnChain = false;
    TxSignContext c3 = ctx;
    c3.prevouts = &unproven;
    TxReview r3 = ReviewTx(c3);
    Check(r3.ok, "review still succeeds without chain proof");
    Check(r3.anyUnproven, "unproven flag surfaced so the UI keeps the warning");
  }
  {
    PrevOut proven = prev;
    proven.provenOnChain = true;
    TxSignContext c4 = ctx;
    c4.prevouts = &proven;
    TxReview r4 = ReviewTx(c4);
    Check(!r4.anyUnproven, "proven claim only removes the unproven flag");
  }

  // 缺少 pub33：必须拒绝（以前这里是空指针解引用）
  {
    TxSignContext c5 = ctx;
    c5.pub33 = nullptr;
    TxReview r5 = ReviewTx(c5);
    Check(!r5.ok, "missing pub33 is rejected instead of dereferencing null");
  }
}

// ── 4b. 费用池形状的交易不得走 P2PKH 解释 ─────────────────────────
//
// 费用池（池脚本、多签、双方/三方顺序、锁定与退款条件）在脚本与阶段冻结前
// 不得套用 P2PKH 语义（需求 §5 / VLP §3）。这里的断言是"未冻结变体明确
// 不可用"的设备侧保证：池形状的前序或输出一律拒绝，不会被解释成普通 P2PKH
// 展示给用户。
void TestFeePoolShapesRejected() {
  Begin("tx/fee-pool-freeze");
  // 2-of-3 裸多签脚本（池参与的常见形状）
  uint8_t multi[128];
  size_t mn = 0;
  multi[mn++] = 0x52;  // OP_2
  for (int i = 0; i < 3; ++i) {
    multi[mn++] = 0x21;  // push 33
    multi[mn++] = 0x02;
    for (int j = 0; j < 32; ++j) multi[mn++] = static_cast<uint8_t>(0x10 + i * 32 + j);
  }
  multi[mn++] = 0x53;  // OP_3
  multi[mn++] = 0xAE;  // OP_CHECKMULTISIG

  // 形似"开池/funding"：前序是多签脚本，不是 P2PKH
  {
    PrevOut prev{};
    memcpy(prev.txid, g_txid, 32);
    prev.vout = 0;
    prev.satoshis = 100000;
    prev.provenOnChain = true;
    memcpy(prev.script, multi, mn);
    prev.scriptLen = static_cast<uint16_t>(mn);
    std::vector<uint8_t> raw =
        BuildTx(g_txid, 0, 0xFFFFFFFFu, g_ourH160, g_payeeH160, 100000, 40000, 59900);
    TxSignContext ctx{};
    ctx.raw = raw.data();
    ctx.rawLen = raw.size();
    ctx.prevouts = &prev;
    ctx.prevoutCount = 1;
    ctx.inputIndex = 0;
    ctx.pub33 = g_pub;
    TxReview rv = ReviewTx(ctx);
    Check(!rv.ok, "fee-pool funding prevout (multisig) is not accepted as P2PKH");
    Check(rv.error == rockey::ops::TxReviewError::kPrevoutNotP2pkh,
          "rejection names the non-P2PKH prevout");
  }

  // 形似"池输出"：输入是本设备的 P2PKH，输出是多签池脚本
  {
    PrevOut prev{};
    memcpy(prev.txid, g_txid, 32);
    prev.vout = 0;
    prev.satoshis = 100000;
    prev.provenOnChain = true;
    prev.scriptLen = static_cast<uint16_t>(
        rockey::ops::BuildP2pkhScript(g_ourH160, prev.script, kMaxScriptLen));
    std::vector<uint8_t> raw;
    PushU32(&raw, 1);
    PushVarInt(&raw, 1);
    raw.insert(raw.end(), g_txid, g_txid + 32);
    PushU32(&raw, 0);
    PushVarInt(&raw, 0);
    PushU32(&raw, 0xFFFFFFFFu);
    PushVarInt(&raw, 2);
    PushU64(&raw, 40000);
    PushVarInt(&raw, mn);
    raw.insert(raw.end(), multi, multi + mn);   // 池输出
    PushU64(&raw, 59900);
    PushVarInt(&raw, 25);
    BuildP2pkh(&raw, g_ourH160);                 // 找零仍回本设备
    PushU32(&raw, 0);
    TxSignContext ctx{};
    ctx.raw = raw.data();
    ctx.rawLen = raw.size();
    ctx.prevouts = &prev;
    ctx.prevoutCount = 1;
    ctx.inputIndex = 0;
    ctx.pub33 = g_pub;
    TxReview rv = ReviewTx(ctx);
    Check(!rv.ok, "fee-pool output (multisig) is not accepted as P2PKH");
    Check(rv.error == rockey::ops::TxReviewError::kUnknownScript,
          "rejection names the unknown output script");
  }

  // 超过单帧容量的原始交易：明确拒绝，不宣称支持跨帧重组
  {
    PrevOut prev{};
    memcpy(prev.txid, g_txid, 32);
    prev.vout = 0;
    prev.satoshis = 1000000;
    prev.scriptLen = static_cast<uint16_t>(
        rockey::ops::BuildP2pkhScript(g_ourH160, prev.script, kMaxScriptLen));
    std::vector<uint8_t> raw;
    PushU32(&raw, 1);
    PushVarInt(&raw, 1);
    raw.insert(raw.end(), g_txid, g_txid + 32);
    PushU32(&raw, 0);
    PushVarInt(&raw, 0);
    PushU32(&raw, 0xFFFFFFFFu);
    PushVarInt(&raw, 1);
    PushU64(&raw, 900000);
    PushVarInt(&raw, 25);
    BuildP2pkh(&raw, g_payeeH160);
    // 用一个超长（非法但定长）的输出脚本把交易撑过上限
    PushU64(&raw, 99000);
    PushVarInt(&raw, 200);
    for (int i = 0; i < 200; ++i) raw.push_back(0x00);
    PushU64(&raw, 1000);
    PushVarInt(&raw, 25);
    BuildP2pkh(&raw, g_ourH160);
    for (int o = 0; o < 6; ++o) {
      PushU64(&raw, 1000);
      PushVarInt(&raw, 200);
      for (int i = 0; i < 200; ++i) raw.push_back(0x00);
    }
    PushU32(&raw, 0);
    Check(raw.size() > rockey::ops::kMaxTxBytes, "fixture really exceeds the bound");
    TxSignContext ctx{};
    ctx.raw = raw.data();
    ctx.rawLen = raw.size();
    ctx.prevouts = &prev;
    ctx.prevoutCount = 1;
    ctx.inputIndex = 0;
    ctx.pub33 = g_pub;
    TxReview rv = ReviewTx(ctx);
    Check(!rv.ok, "oversized raw tx is refused at the declared bound");
  }
}

// ── 5. 持续授权：撤销、限额、未决定不得放行 ─────────────────────────

MatchKey MakeKey(uint8_t op, uint8_t object) {
  MatchKey k{};
  k.category = 3;
  k.operation = op;
  k.protocol = 1;
  k.direction = 2;
  k.objectHash[0] = object;
  k.sessionId = 42;
  k.sessionEpoch = 1;
  return k;
}

void TestPolicy() {
  Begin("policy");
  Policy::BeginSession(7, 42, 1);
  Policy::ClearAll();

  // 未决定
  MatchKey a = MakeKey(0x31, 0xAA);
  Check(Policy::Evaluate(a, 3, "x") == EvalResult::kNeedUser, "undecided needs the user");
  Check(Policy::Revalidate(a) == false, "undecided is not an allow");

  // 会话允许
  Check(Policy::GrantSession(a, 3, "allow-a", 0, 0), "grant A");
  Check(Policy::Evaluate(a, 3, "x") == EvalResult::kAllowed, "A allowed");
  Check(Policy::Count() == 1, "one decision");

  // 不同协议 / 不同方向 / 不同对端：都不能复用 A 的授权
  {
    MatchKey other = a;
    other.protocol = 2;
    Check(Policy::Evaluate(other, 3, "x") == EvalResult::kNeedUser, "other protocol not covered");
  }
  {
    MatchKey other = a;
    other.direction = 1;
    Check(Policy::Evaluate(other, 3, "x") == EvalResult::kNeedUser, "other direction not covered");
  }
  {
    MatchKey other = a;
    other.objectHash[0] = 0xBB;
    Check(Policy::Evaluate(other, 3, "x") == EvalResult::kNeedUser, "other object not covered");
  }
  {
    MatchKey other = a;
    other.sessionId = 43;
    Check(Policy::Evaluate(other, 3, "x") == EvalResult::kNeedUser, "other session not covered");
  }

  // 连续三条，然后撤销中间那条：必须精确撤掉 B，A 和 C 都还在
  MatchKey b = MakeKey(0x32, 0xCC);
  MatchKey c = MakeKey(0x33, 0xDD);
  Check(Policy::GrantSession(b, 3, "allow-b", 0, 0), "grant B");
  Check(Policy::GrantSession(c, 3, "allow-c", 0, 0), "grant C");
  Check(Policy::Count() == 3, "three decisions");
  Check(Policy::Evaluate(b, 3, "x") == EvalResult::kAllowed, "B allowed before cancel");
  Check(Policy::Evaluate(c, 3, "x") == EvalResult::kAllowed, "C allowed before cancel");

  // B 的下标
  uint8_t idxB = 0xFF;
  for (uint8_t i = 0; i < rockey::policy::kMaxSessionDecisions; ++i) {
    rockey::policy::SessionDecision d;
    if (Policy::Get(i, &d) && strcmp(d.label, "allow-b") == 0) idxB = i;
  }
  Check(idxB != 0xFF, "found B's slot");
  Check(Policy::CancelSession(idxB), "cancel B");
  Check(Policy::Count() == 2, "two decisions remain");
  Check(Policy::Evaluate(b, 3, "x") == EvalResult::kNeedUser, "B back to undecided");
  Check(Policy::Evaluate(a, 3, "x") == EvalResult::kAllowed, "A still allowed (not collaterally cancelled)");
  Check(Policy::Evaluate(c, 3, "x") == EvalResult::kAllowed,
        "C still findable after B was removed (slot compaction)");

  // 撤销后必须重新询问
  Check(Policy::Revalidate(b) == false, "cancelled grant does not revalidate");
  Check(Policy::Revalidate(a) == true, "surviving grant revalidates");

  // 持续否决优先
  Check(Policy::DenySession(b, 3, "deny-b"), "deny B");
  Check(Policy::Evaluate(b, 3, "x") == EvalResult::kDenied, "deny wins immediately");
  Check(Policy::DenySession(c, 3, "deny-c"), "deny C");

  Check(Policy::CancelAll(), "cancel all");
  Check(Policy::Count() == 0, "no decisions left");
  Check(Policy::Evaluate(a, 3, "x") == EvalResult::kNeedUser, "A forgotten after ClearAll");

  // 会话/世代变化必须清空
  Policy::GrantSession(a, 3, "allow-a2", 0, 0);
  Check(Policy::Count() == 1, "granted again");
  Policy::BeginSession(7, 42, 2);  // 同设备运行/连接，epoch 变了
  Check(Policy::Count() == 0, "epoch change clears decisions");
}

void TestPolicyQuota() {
  Begin("policy/quota");
  Policy::BeginSession(7, 42, 1);
  Policy::ClearAll();
  MatchKey k = MakeKey(0x21, 0x55);
  k.category = 2;

  // 次数限额：usedCount 以前从不自增，kExhausted 不可达
  Check(Policy::GrantSession(k, 2, "tx", 2, 0), "grant with maxCount=2");
  Check(Policy::Evaluate(k, 2, "tx", 1000) == EvalResult::kAllowed, "1st allowed");
  Policy::Consume(k, 1000);
  Check(Policy::Evaluate(k, 2, "tx", 1000) == EvalResult::kAllowed, "2nd allowed");
  Policy::Consume(k, 1000);
  Check(Policy::Evaluate(k, 2, "tx", 1000) == EvalResult::kExhausted,
        "3rd exhausted (usedCount actually increments)");

  // 金额限额：以前 budgetSats != 0 && budgetSats < 1 恒假
  Policy::ClearAll();
  Check(Policy::GrantSession(k, 2, "tx-budget", 0, 5000), "grant with budget 5000");
  Check(Policy::Evaluate(k, 2, "tx-budget", 4000) == EvalResult::kAllowed, "under budget");
  Policy::Consume(k, 4000);
  Check(Policy::Evaluate(k, 2, "tx-budget", 2000) == EvalResult::kExhausted,
        "would exceed budget -> re-authorise");
  Check(Policy::Evaluate(k, 2, "tx-budget", 500) == EvalResult::kAllowed,
        "smaller amount still fits");

  Policy::ClearAll();
}

}  // namespace

void TestPersistentDecisionGate() {
  Begin("policy/persistent-gate");
  // 导出、迁移与恢复备份：私钥离开设备这类动作不得留下持续授权
  Check(!PersistentDecisionAllowed(rockey::policy::Category::kMigration),
        "migration/export cannot be granted for the session");
  Check(PersistentDecisionAllowed(rockey::policy::Category::kIdentity), "identity may persist");
  Check(PersistentDecisionAllowed(rockey::policy::Category::kTransaction), "tx may persist");
  Check(PersistentDecisionAllowed(rockey::policy::Category::kChannel), "channel may persist");
  Check(PersistentDecisionAllowed(rockey::policy::Category::kLocalSecret), "local secret may persist");
  Check(PersistentDecisionAllowed(rockey::policy::Category::kContent), "content may persist");
}

int main() {
  printf("rockey host tests: ops/tx + policy (needs mbedtls)\n");
  SetupFixtures();

  TestAddress();
  TestSequenceRoundTrip();
  TestSighashPreimage();
  TestReviewTx();
  TestFeePoolShapesRejected();
  TestPolicy();
  TestPolicyQuota();
  TestPersistentDecisionGate();

  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}