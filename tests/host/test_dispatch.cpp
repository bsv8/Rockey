// 主机侧测试（需要 mbedtls）：编译 src/ 里的**真实** dispatch / review / tx /
// keystore 实现，固定"2026-10-09 收窄后设备拒绝什么"。
//
// 覆盖三类只能靠执行才能守住的行为：
//  1. 已撤销的入口确实没了：`evidence.receive`（设备信用/证据服务）→ unsupported；
//  2. 未冻结的能力确实不可用：`tx.feepool-sign` → unsupported，且不解析任何字段；
//  3. 未冻结变体不能借用已支持解析器：池形状交易伪装成 `tx.p2pkh-sign`
//     （多签前序 / 池输出脚本）→ malformed，不会被当成普通 P2PKH 展示；
//  4. 主机文本字段仍受 UTF-8/缺字保护（RK-05），无法解释的字节按 malformed 拒绝。
//
// 真机与 Keymaster 联调不在此覆盖范围内。
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>

// 主机替身时钟（shim_env.cpp）
void delay(unsigned long ms);
unsigned long millis();

#include "crypto/secp256k1.h"
#include "ops/dispatch.h"
#include "ui/font.h"
#include "ops/review.h"
#include "proto/cbor.h"
#include "store/keystore.h"

using rockey::keystore::KeyStore;
using rockey::keystore::Status;
using rockey::ops::ErrorCode;
using rockey::ops::ExecContext;
using rockey::ops::OpId;
using rockey::ops::Prepare;
using rockey::ops::PrepareStatus;
using rockey::ops::ReviewDoc;
using rockey::FontRole;
using rockey::FontCoversUtf8;
using rockey::proto::Writer;

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

const uint8_t kPriv[32] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                           0xcc, 0xdd, 0xee, 0xff, 0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
                           0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0x01};
const char* kPin = "12345678";
const uint8_t kChallenge[32] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B,
                                0x5C, 0x6D, 0x7E, 0x8F, 0x90, 0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F,
                                0x60, 0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6, 0xD7, 0xE8, 0xF9};

// ── 请求构造（严格遵循确定性键序：长度优先，再字节序） ────────────────

// 2-of-3 裸多签：池参与的常见形状，设备必须当作未知脚本
size_t BuildMultisig(uint8_t* out, size_t cap) {
  size_t n = 0;
  out[n++] = 0x52;  // OP_2
  for (int i = 0; i < 3; ++i) {
    out[n++] = 0x21;  // push 33
    out[n++] = 0x02;
    for (int j = 0; j < 32; ++j) out[n++] = static_cast<uint8_t>(0x10 + i * 32 + j);
  }
  out[n++] = 0x53;  // OP_3
  out[n++] = 0xAE;  // OP_CHECKMULTISIG
  (void)cap;
  return n;
}

// 一笔"输入属本设备 P2PKH、输出是池脚本"的交易
size_t BuildPoolOutputTx(std::vector<uint8_t>* raw, const uint8_t txid[32],
                         const uint8_t ourH160[20], const uint8_t* poolScript,
                         size_t poolLen) {
  auto pushU32 = [&](uint32_t x) {
    for (int i = 0; i < 4; ++i) raw->push_back(static_cast<uint8_t>(x >> (8 * i)));
  };
  auto pushU64 = [&](uint64_t x) {
    for (int i = 0; i < 8; ++i) raw->push_back(static_cast<uint8_t>(x >> (8 * i)));
  };
  auto pushVarInt = [&](uint64_t x) {
    if (x < 0xFD) {
      raw->push_back(static_cast<uint8_t>(x));
    } else {
      raw->push_back(0xFD);
      raw->push_back(static_cast<uint8_t>(x));
      raw->push_back(static_cast<uint8_t>(x >> 8));
    }
  };
  pushU32(1);  // version
  pushVarInt(1);
  raw->insert(raw->end(), txid, txid + 32);
  pushU32(0);
  pushVarInt(0);  // scriptSig
  pushU32(0xFFFFFFFFu);
  pushVarInt(2);
  pushU64(40000);
  pushVarInt(poolLen);
  raw->insert(raw->end(), poolScript, poolScript + poolLen);  // 池输出
  pushU64(59900);
  pushVarInt(25);
  raw->push_back(0x76);
  raw->push_back(0xA9);
  raw->push_back(0x14);
  raw->insert(raw->end(), ourH160, ourH160 + 20);
  raw->push_back(0x88);
  raw->push_back(0xAC);
  pushU32(0);  // locktime
  return raw->size();
}

}  // namespace

// identity.prove 请求：op(2) < purpose(7) < challenge(9) < opVersion(9)
size_t BuildIdentityProve(uint8_t* buf, size_t cap, const char* purpose, size_t purposeLen) {
  Writer w(buf, cap);
  w.BeginMap(4);
  w.Key("op");
  w.Text("identity.prove");
  w.Key("purpose");
  w.TextN(purpose, purposeLen);
  w.Key("challenge");
  w.Bytes(kChallenge, 32);
  w.Key("opVersion");
  w.Uint(1);
  w.EndMap();
  return w.ok() ? w.size() : 0;
}

size_t BuildOpOnly(uint8_t* buf, size_t cap, const char* op) {
  Writer w(buf, cap);
  w.BeginMap(2);
  w.Key("op");
  w.Text(op);
  w.Key("opVersion");
  w.Uint(1);
  w.EndMap();
  return w.ok() ? w.size() : 0;
}

// tx.p2pkh-sign 请求，rawTx 由调用方给出
size_t BuildP2pkhSign(uint8_t* buf, size_t cap, const uint8_t* raw, size_t rawLen,
                      const uint8_t txid[32], const uint8_t script[25], uint64_t sats) {
  Writer w(buf, cap);
  w.BeginMap(6);
  w.Key("op");
  w.Text("tx.p2pkh-sign");
  w.Key("rawTx");
  w.Bytes(raw, rawLen);
  w.Key("network");
  w.Uint(0);
  w.Key("prevouts");
  w.BeginArray(1);
  w.BeginMap(5);
  w.Key("txid");
  w.Bytes(txid, 32);
  w.Key("vout");
  w.Uint(0);
  w.Key("proven");
  w.Bool(true);
  w.Key("script");
  w.Bytes(script, 25);
  w.Key("satoshis");
  w.Uint(sats);
  w.EndMap();
  w.EndArray();
  w.Key("opVersion");
  w.Uint(1);
  w.Key("inputIndex");
  w.Uint(0);
  w.EndMap();
  return w.ok() ? w.size() : 0;
}

void DrainPinWait() {
  for (int i = 0; i < 1200; ++i) {
    if (KeyStore::WaitMsRemaining(millis()) == 0) return;
    delay(1000);
  }
}

int main() {
  printf("rockey host tests: dispatch freeze gates (needs mbedtls)\n");

  Begin("dispatch/setup");
  Check(KeyStore::Init(), "keystore init");
  Check(KeyStore::SetPinAndWrap(kPin, strlen(kPin), kPriv) == Status::kOk, "set PIN + wrap");
  DrainPinWait();
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "unlock");

  uint8_t pub[33];
  Check(rockey::secp::PubkeyFromPriv(kPriv, pub), "device pubkey derived");
  uint8_t ourH160[20];
  Check(rockey::ops::Hash160(pub, 33, ourH160), "our hash160 derived");
  uint8_t p2pkh[25];
  Check(rockey::ops::BuildP2pkhScript(ourH160, p2pkh, sizeof(p2pkh)) == 25, "P2PKH script built");

  uint8_t commitment[32] = {0};
  for (int i = 0; i < 32; ++i) commitment[i] = static_cast<uint8_t>(0x40 + i);

  uint8_t body[4096];
  ReviewDoc doc;
  ExecContext exec;

  Begin("dispatch/evidence-revoked");
  {
    size_t n = BuildOpOnly(body, sizeof(body), "evidence.receive");
    Check(n > 0, "request encoded");
    PrepareStatus ps = Prepare(body, n, 1, &doc, &exec, commitment);
    Check(ps == PrepareStatus::kUnsupported,
          "evidence.receive is refused (credit/evidence entry revoked)");
  }

  Begin("dispatch/fee-pool-freeze");
  {
    size_t n = BuildOpOnly(body, sizeof(body), "tx.feepool-sign");
    Check(n > 0, "request encoded");
    PrepareStatus ps = Prepare(body, n, 2, &doc, &exec, commitment);
    Check(ps == PrepareStatus::kUnsupported,
          "tx.feepool-sign is refused until the script/stage freeze");
  }
  {
    // 即便夹带字段，也必须在识别 op 的那一刻就被拒绝（不解析、不发明字段）
    Writer w(body, sizeof(body));
    w.BeginMap(3);
    w.Key("op");
    w.Text("tx.feepool-sign");
    w.Key("poolId");
    w.Text("pool-1");
    w.Key("opVersion");
    w.Uint(1);
    w.EndMap();
    Check(w.ok() && w.size() > 0, "request with extra fields encoded");
    PrepareStatus ps = Prepare(body, w.size(), 3, &doc, &exec, commitment);
    Check(ps == PrepareStatus::kUnsupported,
          "fee-pool refusal happens at op identification, before any field parsing");
  }

  Begin("dispatch/unknown-op");
  {
    size_t n = BuildOpOnly(body, sizeof(body), "sign.digest");
    Check(Prepare(body, n, 4, &doc, &exec, commitment) == PrepareStatus::kUnsupported,
          "unknown op is unsupported (no blind digest signing entry)");
  }

  Begin("dispatch/pool-shape-not-p2pkh");
  {
    // 池输出脚本（2-of-3 多签）伪装成 tx.p2pkh-sign：必须 malformed
    uint8_t pool[128];
    size_t poolLen = BuildMultisig(pool, sizeof(pool));
    uint8_t txid[32];
    for (int i = 0; i < 32; ++i) txid[i] = static_cast<uint8_t>(0x60 + i);
    std::vector<uint8_t> raw;
    BuildPoolOutputTx(&raw, txid, ourH160, pool, poolLen);
    size_t n = BuildP2pkhSign(body, sizeof(body), raw.data(), raw.size(), txid, p2pkh, 100000);
    Check(n > 0, "pool-shaped request encoded");
    PrepareStatus ps = Prepare(body, n, 5, &doc, &exec, commitment);
    Check(ps == PrepareStatus::kMalformed,
          "pool output script is not explained as a plain P2PKH payment");
  }

  Begin("dispatch/valid-identity");
  {
    const char* purpose = "connect-login";
    size_t n = BuildIdentityProve(body, sizeof(body), purpose, strlen(purpose));
    Check(n > 0, "identity.prove encoded");
    PrepareStatus ps = Prepare(body, n, 6, &doc, &exec, commitment);
    Check(ps == PrepareStatus::kOk, "a supported op still prepares");
    Check(doc.chapterCount > 0 && doc.requiredTotal > 0, "review doc has required chapters");
    Check(strcmp(doc.title, "Prove identity") == 0 || strlen(doc.title) > 0, "doc title set");
    Check(!doc.hasMissingGlyph, "ASCII purpose has no missing glyph");
  }

  Begin("dispatch/host-text-invalid-utf8");
  {
    const char bad[] = {'a', 'b', char(0xFF), char(0xFE), 'c'};
    size_t n = BuildIdentityProve(body, sizeof(body), bad, sizeof(bad));
    Check(n > 0, "request with invalid UTF-8 encoded");
    PrepareStatus ps = Prepare(body, n, 7, &doc, &exec, commitment);
    Check(ps == PrepareStatus::kMalformed,
          "uninterpretable host bytes are refused instead of displayed");
  }

  Begin("dispatch/host-text-missing-glyph");
  {
    // BMP 内但一般不在中文字库里的码位（泰文 U+0E01 "ก"）
    const char thai[] = {'a', (char)0xE0, (char)0xB8, (char)0x81};
    size_t n = BuildIdentityProve(body, sizeof(body), thai, sizeof(thai));
    Check(n > 0, "request with rare codepoint encoded");
    PrepareStatus ps = Prepare(body, n, 8, &doc, &exec, commitment);
    Check(ps == PrepareStatus::kOk, "valid UTF-8 is accepted");
    Check(doc.hasMissingGlyph, "missing glyph is flagged for the reader footer");
    Check(doc.missingGlyphCp == 0x0E01, "the missing codepoint is the one that is missing");
  }

  Begin("ui/font-covers-utf8");
  {
    // 这条断言固定 FontCoversUtf8 的**真解码**行为：它曾经把首字节当码位，
    // 于是所有多字节字符都按 Latin-1 查表 —— 只要字库有 U+00E0，整段中文
    // 都报"覆盖"，缺字检测形同虚设（RK-05 要求缺字可见且码点正确）。
    uint32_t miss = 0;
    Check(FontCoversUtf8(FontRole::kBody, "abc 123", 7, &miss), "ASCII is covered");
    const char zh[] = {(char)0xE4, (char)0xB8, (char)0xAD, (char)0xE6, (char)0x96, (char)0x87};
    Check(FontCoversUtf8(FontRole::kBody, zh, sizeof(zh), &miss),
          "Chinese text is covered by the zh-Hans font (multi-byte decoded)");
    const char thai[] = {(char)0xE0, (char)0xB8, (char)0x81};
    Check(!FontCoversUtf8(FontRole::kBody, thai, sizeof(thai), &miss),
          "a codepoint outside the font is reported missing");
    Check(miss == 0x0E01, "the reported codepoint is the real one, not a lead byte");
    const char bad[] = {(char)0xFF, (char)0xFE};
    Check(!FontCoversUtf8(FontRole::kBody, bad, sizeof(bad), &miss),
          "invalid UTF-8 is reported missing");
    Check(miss == 0xFFFD, "invalid bytes report the replacement codepoint");
  }

  KeyStore::Lock();
  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
