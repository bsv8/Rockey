// 主机侧线缆层测试：直接编译 src/ 里的真实实现（cbor / frame / crc32），
// 不做任何复制或替身。
//
// 覆盖 R3 门禁要求的负向测试：伪帧、超长、乱序、重放前置条件（乱序 seq）、
// 截断、缺字/超限，以及确定性 CBOR 键序契约。
//
// 主机上运行：
//   scripts/run_host_tests.sh
// 或：
//   c++ -std=gnu++17 -Isrc -o /tmp/rk_proto tests/host/test_proto.cpp \
//       src/proto/cbor.cpp src/proto/frame.cpp src/store/crc32.cpp && /tmp/rk_proto
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "proto/cbor.h"
#include "proto/frame.h"
#include "store/crc32.h"

using rockey::proto::Frame;
using rockey::proto::FrameReader;
using rockey::proto::FrameType;
using rockey::proto::kFrameHeaderLen;
using rockey::proto::kFrameTrailerLen;
using rockey::proto::Reader;
using rockey::proto::Writer;
using rockey::store::Crc32;

namespace {

int g_pass = 0;
int g_fail = 0;
const char* g_case = "";

void Begin(const char* name) {
  g_case = name;
}

void Check(bool cond, const char* what) {
  if (cond) {
    g_pass++;
  } else {
    g_fail++;
    printf("  FAIL [%s] %s\n", g_case, what);
  }
}

template <size_t N>
bool HexEq(const uint8_t* p, size_t n, const char (&hex)[N]) {
  if (n != (N - 1) / 2) return false;
  for (size_t i = 0; i < n; ++i) {
    auto nib = [&](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    if (p[i] != static_cast<uint8_t>(hi * 16 + lo)) return false;
  }
  return true;
}

// 按真实调用方（Link::Poll）的方式驱动 FrameReader：尊重 consumed，指针前移。
// 返回取出的帧数；顺序写入 seqs（容量 cap）。
size_t Drive(FrameReader& rd, const uint8_t* data, size_t len, uint32_t* seqs, size_t cap) {
  size_t off = 0, seen = 0;
  while (off < len && seen < cap) {
    Frame f;
    size_t used = 0;
    if (!rd.Feed(data + off, len - off, &f, &used)) break;
    off += used;
    seqs[seen++] = f.seq;
  }
  return seen;
}

// ExpectKey 的等价物：MapKey 取出后比对
bool ExpectCode(Reader* r, const char* want) {
  size_t n = 0;
  const char* got = r->MapKey(&n);
  if (!got) return false;
  size_t w = strlen(want);
  return n == w && memcmp(got, want, n) == 0;
}


// ── CBOR 确定性编码契约 ──────────────────────────────────────────────

void TestCborIntegers() {
  Begin("cbor/int");
  uint8_t b[32];
  {
    Writer w(b, sizeof(b));
    w.Uint(0);
    Check(w.ok() && w.size() == 1 && b[0] == 0x00, "uint 0");
  }
  {
    Writer w(b, sizeof(b));
    w.Uint(23);
    Check(w.ok() && w.size() == 1 && b[0] == 0x17, "uint 23 shortest");
  }
  {
    Writer w(b, sizeof(b));
    w.Uint(24);
    Check(w.ok() && w.size() == 2 && b[0] == 0x18 && b[1] == 24, "uint 24 uses kAi8");
  }
  {
    Writer w(b, sizeof(b));
    w.Int(-1);
    Check(w.ok() && w.size() == 1 && b[0] == 0x20, "negative -1");
  }
  {
    Writer w(b, sizeof(b));
    w.Int(-1000);
    Check(w.ok() && w.size() == 3 && b[0] == 0x39, "negative -1000 uses kAi16");
  }
  // 容量不足必须失败而不是越界写
  {
    uint8_t tiny[2];
    Writer w(tiny, sizeof(tiny));
    w.Uint(0xFFFFFFFFull);
    Check(!w.ok(), "capacity overflow sets ok_=false");
  }
}

void TestCborKeyOrdering() {
  Begin("cbor/key-order");
  uint8_t b[128];

  // 契约：键按"字节长度优先，再字节序"严格递增
  {
    Writer w(b, sizeof(b));
    w.BeginMap(3);
    w.Key("ab");  w.Uint(1);
    w.Key("cd");  w.Uint(2);
    w.Key("ef");  w.Uint(3);
    w.EndMap();
    Check(w.ok(), "ascending equal-length keys accepted");
  }
  {
    Writer w(b, sizeof(b));
    w.BeginMap(2);
    w.Key("b");   w.Uint(1);
    w.Key("aa");  w.Uint(2);   // 更长的键，允许
    w.EndMap();
    Check(w.ok(), "length-ascending keys accepted");
  }
  {
    Writer w(b, sizeof(b));
    w.BeginMap(2);
    w.Key("zz");  w.Uint(1);
    w.Key("a");   w.Uint(2);   // 变短 => 拒绝
    w.EndMap();
    Check(!w.ok(), "length-descending keys rejected");
  }
  {
    Writer w(b, sizeof(b));
    w.BeginMap(2);
    w.Key("ab");  w.Uint(1);
    w.Key("aa");  w.Uint(2);   // 同长但字节序变小 => 拒绝
    w.EndMap();
    Check(!w.ok(), "byte-descending keys rejected");
  }
  {
    Writer w(b, sizeof(b));
    w.BeginMap(2);
    w.Key("dup"); w.Uint(1);
    w.Key("dup"); w.Uint(2);
    w.EndMap();
    Check(!w.ok(), "duplicate keys rejected");
  }
  {
    // 这正是修复前 tx.p2pkh-sign 响应的失败模式：
    // publicKey(9) 后面跟更短的 sighash(7)
    Writer w(b, sizeof(b));
    w.BeginMap(4);
    w.Key("publicKey");   w.Uint(1);
    w.Key("sighash");     w.Uint(2);
    w.Key("signature");   w.Uint(3);
    w.Key("sighashType"); w.Uint(4);
    w.EndMap();
    Check(!w.ok(), "publicKey before sighash rejected (old tx.p2pkh-sign order)");
  }
  {
    // 修复后顺序：sighash(7) < publicKey(9) < signature(9) < sighashType(11)
    Writer w(b, sizeof(b));
    w.BeginMap(4);
    w.Key("sighash");     w.Uint(1);
    w.Key("publicKey");   w.Uint(2);
    w.Key("signature");   w.Uint(3);
    w.Key("sighashType"); w.Uint(4);
    w.EndMap();
    Check(w.ok(), "sighash before publicKey accepted (new order)");
  }
  {
    // 超长键名（> kMaxTextKeyLen）必须拒绝
    Writer w(b, sizeof(b));
    w.BeginMap(1);
    w.Key("0123456789012345678901234567890123456789");
    w.Uint(1);
    w.EndMap();
    Check(!w.ok(), "over-long key name rejected");
  }
}

void TestCborReaderRejects() {
  Begin("cbor/reader");
  // 非最短整数表示：23 写成 kAi8
  {
    const uint8_t bad[] = {0x18, 0x17};
    Reader r(bad, sizeof(bad));
    r.Uint();
    Check(!r.ok(), "non-minimal uint rejected");
  }
  // 截断的多字节整数
  {
    const uint8_t bad[] = {0x19, 0x01};
    Reader r(bad, sizeof(bad));
    r.Uint();
    Check(!r.ok(), "truncated uint16 rejected");
  }
  // 声明长度超过剩余字节
  {
    const uint8_t bad[] = {0x58, 0x10, 0x01, 0x02};
    Reader r(bad, sizeof(bad));
    size_t n = 0;
    r.Bytes(&n);
    Check(!r.ok(), "over-long byte string rejected");
  }
  // 深度超限：kMaxDepth 层嵌套之后必须失败，而不是栈溢出
  {
    uint8_t deep[64];
    size_t p = 0;
    for (int i = 0; i < 64; ++i) deep[p++] = 0x81;  // array(1)
    Reader r(deep, p);
    for (int i = 0; i < 40; ++i) {
      size_t n = r.ArrayBegin();
      if (!r.ok()) break;
      (void)n;
    }
    Check(!r.ok(), "excessive nesting depth rejected");
  }
  // SkipItem 不得在无界嵌套上递归爆栈（这是修复前的 DoS）
  {
    uint8_t deep[4096];
    memset(deep, 0x81, sizeof(deep));
    Reader r(deep, sizeof(deep));
    r.SkipItem();
    Check(!r.ok(), "SkipItem stops at depth limit instead of recursing forever");
  }
  // SkipItem 正常跳过
  {
    const uint8_t data[] = {0x83, 0x01, 0x62, 0x68, 0x69, 0x41, 0x01};
    Reader r(data, sizeof(data));
    r.SkipItem();
    Check(r.ok() && r.position() == sizeof(data), "SkipItem consumes whole array");
  }
  // 未知的 simple value 必须拒绝
  {
    const uint8_t bad[] = {0xF7};  // undefined
    Reader r(bad, sizeof(bad));
    r.SkipItem();
    Check(!r.ok(), "unknown simple value rejected");
  }
}

void TestCborRoundTrip() {
  Begin("cbor/roundtrip");
  uint8_t b[256];
  Writer w(b, sizeof(b));
  w.BeginMap(4);
  w.Key("a");  w.Uint(7);
  w.Key("bb"); w.Bool(true);
  w.Key("ccc");
  w.Bytes(reinterpret_cast<const uint8_t*>("\x01\x02\x03"), 3);
  w.Key("dddd");
  w.BeginArray(2);
  w.Int(-5);
  w.Null();
  w.EndArray();
  w.EndMap();
  Check(w.ok(), "writer ok");

  Reader r(b, w.size());
  size_t pairs = r.MapBegin();
  Check(pairs == 4 && r.ok(), "map has 4 pairs");

  size_t n = 0;
  const char* k = r.MapKey(&n);
  Check(k && n == 1 && memcmp(k, "a", 1) == 0, "key a");
  Check(r.Uint() == 7, "value 7");

  k = r.MapKey(&n);
  Check(k && n == 2 && memcmp(k, "bb", 2) == 0, "key bb");
  Check(r.Bool(), "value true");

  k = r.MapKey(&n);
  Check(k && n == 3 && memcmp(k, "ccc", 3) == 0, "key ccc");
  size_t bn = 0;
  const uint8_t* p = r.Bytes(&bn);
  Check(p && bn == 3 && p[0] == 1 && p[2] == 3, "value bytes");

  k = r.MapKey(&n);
  Check(k && n == 4 && memcmp(k, "dddd", 4) == 0, "key dddd");
  size_t arr = r.ArrayBegin();
  Check(arr == 2, "array of 2");
  Check(r.Int() == -5, "array -5");
  r.Null();
  r.EndArray();
  r.EndMap();
  Check(r.ok(), "reader fully consumed and ok");
}

// ── 容器计数 ─────────────────────────────────────────────────────────
// 这一组针对一个曾经让 tx.p2pkh-sign 全部请求被判 malformed 的 bug：
// map/array 共用一个 itemsLeft_，且读值时从不递减，导致 EndArray/EndMap
// 永远失败。凡是"先 ArrayBegin 再逐项读再 EndArray"的路径都要覆盖到。

void TestContainerAccounting() {
  Begin("cbor/container");
  {
    // 单对 map，用 ExpectKey 读（PAIR_CONFIRM / PROVE_POSSESSION 的形状）
    const uint8_t data[] = {0xA1, 0x64, 'c', 'o', 'd', 'e', 0x62, 'h', 'i'};
    Reader r(data, sizeof(data));
    size_t pairs = r.MapBegin();
    bool ok = ExpectCode(&r, "code");
    size_t n = 0;
    const char* v = r.Text(&n);
    ok = ok && r.ok();
    Check(pairs == 1 && ok, "single-pair map via ExpectKey");
    Check(v && n == 2 && memcmp(v, "hi", 2) == 0, "value read");
    r.EndMap();
    Check(r.ok(), "EndMap after reading exactly one pair");
  }
  {
    // 声明 1 对但没读值就 EndMap：必须报错，不能静默放过
    const uint8_t data[] = {0xA1, 0x64, 'c', 'o', 'd', 'e', 0x01};
    Reader r(data, sizeof(data));
    size_t pairs = r.MapBegin();
    (void)pairs;
    size_t n = 0;
    (void)r.MapKey(&n);
    r.EndMap();
    Check(!r.ok(), "EndMap rejects unread map value");
  }
  {
    // 数组元素没读完就 EndArray：必须报错
    const uint8_t data[] = {0x82, 0x01, 0x02};
    Reader r(data, sizeof(data));
    size_t n = r.ArrayBegin();
    (void)n;
    r.Uint();
    r.EndArray();
    Check(!r.ok(), "EndArray rejects unread array element");
  }
  {
    // prevouts 的形状：array(N) of map(m)。这是 tx.p2pkh-sign 的真实结构。
    // 键序必须满足确定性编码：proven(6) < satoshis(8) < script(6)?
    // 不对：按长度 script(6) < proven(6)? "proven" < "script"，所以
    // proven 在 script 之前，satoshis(8) 在最后。
    const uint8_t data[] = {
        0x82,                                            // array(2)
        0xA3, 0x64, 't', 'x', 'i', 'd', 0x41, 0xAA,        // map(3): txid
        0x64, 'v', 'o', 'u', 't', 0x01,                    //          vout
        0x66, 'p', 'r', 'o', 'v', 'e', 'n', 0xF5,          //          proven
        0xA1, 0x64, 'v', 'o', 'u', 't', 0x02,               // map(1): vout
    };
    Reader r(data, sizeof(data));
    size_t cnt = r.ArrayBegin();
    Check(cnt == 2 && r.ok(), "prevouts array of 2");
    for (size_t i = 0; i < cnt; ++i) {
      size_t pairs = r.MapBegin();
      if (!r.ok() || pairs == 0) break;
      for (size_t j = 0; j < pairs; ++j) {
        size_t n = 0;
        const char* k = r.MapKey(&n);
        if (!k) break;
        if (n == 4 && memcmp(k, "txid", 4) == 0) {
          size_t bn = 0;
          r.Bytes(&bn);
        } else if (n == 4 && memcmp(k, "vout", 4) == 0) {
          r.Uint();
        } else if (n == 6 && memcmp(k, "proven", 6) == 0) {
          r.Bool();
        } else {
          Check(false, "prevouts key must be recognised");
        }
      }
      r.EndMap();
      if (!r.ok()) break;
    }
    r.EndArray();
    Check(r.ok(), "prevouts parses cleanly (tx.p2pkh-sign shape)");
  }
  {
    // 键序违规的 prevouts 元素必须被拒：防止主机换一种"等价"写法绕过
    const uint8_t bad[] = {
        0x81,
        0xA2, 0x64, 'v', 'o', 'u', 't', 0x01,             // vout(4)
        0x64, 't', 'x', 'i', 'd', 0x41, 0xAA,             // txid(4) —— 同长但字节序在后，OK
    };
    Reader r(bad, sizeof(bad));
    size_t cnt = r.ArrayBegin();
    Check(cnt == 1 && r.ok(), "array begin ok");
    size_t pairs = r.MapBegin();
    Check(pairs == 2 && r.ok(), "map begin ok");
    size_t n = 0;
    r.MapKey(&n);
    r.Uint();
    r.MapKey(&n);
    Check(!r.ok(), "out-of-order key rejected mid-map");
  }
}

// ── 帧层 ────────────────────────────────────────────────────────────

void TestFrameRoundTrip() {
  Begin("frame/roundtrip");
  uint8_t out[256];
  const uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
  size_t n = 0, used = 0;
  Check(EncodeFrame(out, sizeof(out), FrameType::kRequest, 0, 42, payload, sizeof(payload), &n),
        "encode ok");
  Check(n == kFrameHeaderLen + sizeof(payload) + kFrameTrailerLen, "encoded length");
  Check(out[0] == 0xA5 && out[1] == 0x5A && out[2] == 1, "magic + version");
  Check(out[3] == static_cast<uint8_t>(FrameType::kRequest), "type");
  Check(out[5] == 42 && out[6] == 0 && out[7] == 0 && out[8] == 0, "seq little endian");

  FrameReader rd;
  Frame f;
  Check(rd.Feed(out, n, &f, &used), "reader produced frame");
  Check(f.seq == 42 && f.len == sizeof(payload) && f.payload[0] == 0xDE, "frame fields match");
  Check(used == n, "whole frame consumed");

  uint32_t seqs[8];
  Check(Drive(rd, out, n, seqs, 8) == 1, "exactly one frame, no duplicate on re-drive");
}

void TestFrameNegative() {
  Begin("frame/negative");
  uint8_t out[256];
  const uint8_t payload[] = {0x01, 0x02, 0x03};
  size_t n = 0;
  EncodeFrame(out, sizeof(out), FrameType::kRequest, 0, 1, payload, sizeof(payload), &n);

  {
    // CRC 被篡改
    uint8_t bad[256];
    memcpy(bad, out, n);
    bad[n - 1] ^= 0xFF;
    FrameReader rd;
    Frame f;
    size_t used = 0;
    Check(!rd.Feed(bad, n, &f, &used), "corrupt CRC rejected");
    Check(rd.dropped() > 0, "drop counter advanced");
  }
  {
    // 版本不符
    uint8_t bad[256];
    memcpy(bad, out, n);
    bad[2] = 0x7F;
    FrameReader rd;
    Frame f;
    size_t used = 0;
    Check(!rd.Feed(bad, n, &f, &used), "wrong version rejected");
  }
  {
    // 长度字段被改成超过上限：只喂帧头就够了，设备必须在读 payload 之前拒绝，
    // 不能据此分配或拷贝主机自报的巨量数据。
    uint8_t bad[256];
    memcpy(bad, out, n);
    uint16_t huge = 0xFFFF;
    memcpy(bad + 9, &huge, 2);
    FrameReader rd;
    Frame f;
    size_t used = 0;
    Check(!rd.Feed(bad, kFrameHeaderLen, &f, &used), "oversize payload length rejected on header alone");
    Check(rd.dropped() > 0, "oversize counted as dropped");
  }
  {
    // 前导垃圾必须重新同步，而不是丢弃后续有效帧
    uint8_t stream[512];
    size_t p = 0;
    stream[p++] = 0x00;  // 噪声
    stream[p++] = 0xFF;
    stream[p++] = 0xA5;  // 半个 magic，必须回滚而不是误认
    stream[p++] = 0x00;
    memcpy(stream + p, out, n);
    p += n;
    FrameReader rd;
    uint32_t seqs[8];
    size_t seen = Drive(rd, stream, p, seqs, 8);
    Check(seen == 1 && seqs[0] == 1, "resyncs past leading garbage and finds the real frame");
    Check(rd.resyncs() > 0, "resync counter advanced");
  }
  {
    // 纯噪声：不得崩溃、不得产出帧、不得无限增长
    uint8_t noise[1024];
    for (size_t i = 0; i < sizeof(noise); ++i) {
      noise[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    FrameReader rd;
    uint32_t seqs[8];
    Check(Drive(rd, noise, sizeof(noise), seqs, 8) == 0, "pure noise yields no frames");
    Check(rd.dropped() + rd.resyncs() > 0, "noise accounted as dropped/resync");
  }
}

void TestFramingAcrossReads() {
  Begin("frame/split");
  // USB 串口会断包/粘包：逐字节喂入与一次喂入必须得到同样的帧序列
  uint8_t out[256];
  const uint8_t p1[] = {0xA1};
  const uint8_t p2[] = {0xB2, 0xC3};
  size_t n1 = 0, n2 = 0;
  EncodeFrame(out, sizeof(out), FrameType::kRequest, 0, 7, p1, sizeof(p1), &n1);
  uint8_t s1[256];
  memcpy(s1, out, n1);
  EncodeFrame(out, sizeof(out), FrameType::kResponse, 0, 8, p2, sizeof(p2), &n2);
  uint8_t s2[256];
  memcpy(s2, out, n2);

  uint8_t stream[512];
  size_t p = 0;
  memcpy(stream + p, s1, n1);
  p += n1;
  memcpy(stream + p, s2, n2);
  p += n2;

  {
    // 一次喂入两帧（粘包）
    FrameReader rd;
    uint32_t seqs[8];
    size_t seen = Drive(rd, stream, p, seqs, 8);
    Check(seen == 2, "coalesced input yields exactly two frames");
    Check(seqs[0] == 7 && seqs[1] == 8, "coalesced frames in order, no duplication");
    // 缓冲已空、也没有新输入时不应再产出帧（Link::Poll 靠 consumed 前移来避免重喂）
    Frame f;
    size_t used = 0;
    Check(!rd.Feed(stream + p, 0, &f, &used), "buffer drained");
  }
  {
    // 逐字节喂入（最坏断包）
    FrameReader rd;
    uint32_t seqs[8];
    size_t seen = 0;
    for (size_t i = 0; i < p; ++i) {
      Frame f;
      size_t used = 0;
      if (!rd.Feed(stream + i, 1, &f, &used)) continue;
      seen++;
      if (seen <= 2) seqs[seen - 1] = f.seq;
    }
    Check(seen == 2, "byte-at-a-time delivery yields both frames");
    Check(seqs[0] == 7 && seqs[1] == 8, "byte-at-a-time preserves order");
  }
  {
    // 半帧后暂停，再补齐剩余字节
    FrameReader rd;
    Frame f;
    size_t used = 0;
    size_t half = n1 / 2;
    Check(!rd.Feed(s1, half, &f, &used), "partial frame not emitted");
    Check(rd.Feed(s1 + half, n1 - half, &f, &used), "frame completed by second half");
    Check(f.seq == 7, "completed frame fields");
  }
  {
    // Feed 一取到完整帧就立刻返回，并把 consumed 报准确：
    // 调用方必须按 consumed 前移，否则会重复投递同一帧。
    FrameReader rd;
    Frame f;
    size_t used = 0;
    Check(rd.Feed(stream, p, &f, &used) && f.seq == 7, "first frame");
    Check(used == n1, "consumed stops exactly at the frame boundary");
    Check(rd.Feed(stream + used, p - used, &f, &used) && f.seq == 8, "second frame");
    Check(used == n2, "consumed covers the rest");
    Check(!rd.Feed(stream + p, 0, &f, &used) && used == 0,
          "drained reader yields nothing on zero-length input");
  }
}

void TestCrc32() {
  Begin("crc32");
  Check(Crc32(reinterpret_cast<const uint8_t*>("123456789"), 9) == 0xCBF43926u,
        "CRC-32/ISO-HDLC check value 0xCBF43926");
  Check(Crc32(reinterpret_cast<const uint8_t*>(""), 0) == 0x00000000u, "empty input");
}

// ── 端到端：一个真实形状的加密请求信封 ───────────────────────────────

void TestRequestEnvelopeShape() {
  Begin("proto/envelope");
  // 模拟主机侧编码请求信封（键序必须满足确定性契约）
  uint8_t b[512];
  uint8_t body[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t commitment[32];
  memset(commitment, 0xAB, sizeof(commitment));
  Writer w(b, sizeof(b));
  // 确定性编码要求的顺序：op(2) < body(4) < requestId(9) = sessionId(9) = walletGen(9)
  //   < backendGen(10) = commitment(10) < sessionEpoch(12) < runGeneration(13)
  w.BeginMap(9);
  w.Key("op");            w.Text("identity.prove");  // 仅用于形状测试
  w.Key("body");          w.Bytes(body, sizeof(body));
  w.Key("requestId");     w.Uint(11);
  w.Key("sessionId");     w.Uint(9);
  w.Key("walletGen");     w.Uint(5);
  w.Key("backendGen");    w.Uint(3);
  w.Key("commitment");    w.Bytes(commitment, 32);
  w.Key("sessionEpoch");  w.Uint(1);
  w.Key("runGeneration"); w.Uint(7);
  w.EndMap();
  Check(w.ok(), "envelope encodes under deterministic ordering");

  Reader r(b, w.size());
  size_t pairs = r.MapBegin();
  Check(pairs == 9, "envelope pair count");
  uint32_t requestId = 0, sessionId = 0, sessionEpoch = 0;
  uint32_t backendGen = 0, runGen = 0, walletGen = 0;
  size_t bodyLen = 0;
  const uint8_t* bodyPtr = nullptr;
  for (size_t i = 0; i < pairs; ++i) {
    size_t n = 0;
    const char* k = r.MapKey(&n);
    if (!k) break;
    if (n == 10 && memcmp(k, "backendGen", 10) == 0) {
      backendGen = static_cast<uint32_t>(r.Uint());
    } else if (n == 4 && memcmp(k, "body", 4) == 0) {
      bodyPtr = r.Bytes(&bodyLen);
    } else if (n == 10 && memcmp(k, "commitment", 10) == 0) {
      size_t cn = 0;
      const uint8_t* c = r.Bytes(&cn);
      Check(c && cn == 32, "commitment is 32 bytes");
    } else if (n == 2 && memcmp(k, "op", 2) == 0) {
      size_t on = 0;
      r.Text(&on);
    } else if (n == 9 && memcmp(k, "requestId", 9) == 0) {
      requestId = static_cast<uint32_t>(r.Uint());
    } else if (n == 13 && memcmp(k, "runGeneration", 13) == 0) {
      runGen = static_cast<uint32_t>(r.Uint());
    } else if (n == 12 && memcmp(k, "sessionEpoch", 12) == 0) {
      sessionEpoch = static_cast<uint32_t>(r.Uint());
    } else if (n == 9 && memcmp(k, "sessionId", 9) == 0) {
      sessionId = static_cast<uint32_t>(r.Uint());
    } else if (n == 9 && memcmp(k, "walletGen", 9) == 0) {
      walletGen = static_cast<uint32_t>(r.Uint());
    } else {
      Check(false, "unknown envelope key must be rejected by host parser");
    }
  }
  r.EndMap();
  Check(r.ok(), "envelope fully parsed");
  Check(requestId == 11 && sessionId == 9 && sessionEpoch == 1, "ids round-trip");
  Check(backendGen == 3 && runGen == 7 && walletGen == 5, "generations round-trip");
  Check(bodyPtr && bodyLen == sizeof(body) && bodyPtr[0] == 1, "body round-trip");
}

}  // namespace

int main() {
  printf("rockey host tests: proto/cbor + proto/frame + store/crc32\n");

  TestCrc32();
  TestCborIntegers();
  TestCborKeyOrdering();
  TestCborReaderRejects();
  TestCborRoundTrip();
  TestContainerAccounting();
  TestFrameRoundTrip();
  TestFrameNegative();
  TestFramingAcrossReads();
  TestRequestEnvelopeShape();

  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}