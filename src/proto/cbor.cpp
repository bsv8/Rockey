#include "proto/cbor.h"

#include <string.h>

namespace rockey {
namespace proto {
namespace {

constexpr uint8_t kMajUint = 0;
constexpr uint8_t kMajNeg = 1;
constexpr uint8_t kMajBytes = 2;
constexpr uint8_t kMajText = 3;
constexpr uint8_t kMajArray = 4;
constexpr uint8_t kMajMap = 5;
constexpr uint8_t kMajSimple = 7;

constexpr uint8_t kAi8 = 24;
constexpr uint8_t kAi16 = 25;
constexpr uint8_t kAi32 = 26;
constexpr uint8_t kAi64 = 27;

uint8_t SmallestAi(uint64_t v) {
  if (v < 24) return static_cast<uint8_t>(v);
  if (v <= 0xFF) return kAi8;
  if (v <= 0xFFFF) return kAi16;
  if (v <= 0xFFFFFFFFull) return kAi32;
  return kAi64;
}

size_t AiWidth(uint8_t ai) {
  switch (ai) {
    case kAi8: return 2;
    case kAi16: return 3;
    case kAi32: return 5;
    case kAi64: return 9;
    default: return 1;
  }
}

void PutHead(uint8_t* out, uint8_t major, uint8_t ai, uint64_t v) {
  out[0] = static_cast<uint8_t>((major << 5) | ai);
  switch (ai) {
    case kAi8: out[1] = static_cast<uint8_t>(v); break;
    case kAi16: out[1] = static_cast<uint8_t>(v >> 8); out[2] = static_cast<uint8_t>(v); break;
    case kAi32:
      for (int i = 0; i < 4; ++i) out[1 + i] = static_cast<uint8_t>(v >> (24 - 8 * i));
      break;
    case kAi64:
      for (int i = 0; i < 8; ++i) out[1 + i] = static_cast<uint8_t>(v >> (56 - 8 * i));
      break;
    default: break;
  }
}

bool AiIsMinimal(uint8_t ai, uint64_t v) {
  if (ai < 24) return v == ai;
  switch (ai) {
    case kAi8: return v > 23 && v <= 0xFF;
    case kAi16: return v > 0xFF && v <= 0xFFFF;
    case kAi32: return v > 0xFFFF && v <= 0xFFFFFFFFull;
    case kAi64: return v > 0xFFFFFFFFull;
    default: return false;
  }
}

}  // namespace

// ── Writer ─────────────────────────────────────────────────────────────
void Writer::Need(size_t n) {
  if (!ok_ || len_ + n > cap_) ok_ = false;
}

void Writer::Head(uint8_t major, uint64_t v) {
  Need(9);
  if (!ok_) return;
  uint8_t ai = SmallestAi(v);
  PutHead(buf_ + len_, major, ai, v);
  len_ += AiWidth(ai);
}

void Writer::BeginMap(size_t pairs) {
  Head(kMajMap, pairs);
  inMap_ = true;
  hasLastKey_ = false;
  lastKeyLen_ = 0;
}

void Writer::TrackKey(const char* k, size_t n) {
  if (n >= kMaxTextKeyLen) {
    ok_ = false;
    return;
  }
  // 确定性顺序：键字节长度优先，再按字节序
  if (hasLastKey_) {
    if (n < lastKeyLen_) {
      ok_ = false;
      return;
    }
    if (n == lastKeyLen_ && memcmp(k, lastKey_, n) <= 0) {
      ok_ = false;  // 重复键或乱序键
      return;
    }
  }
  hasLastKey_ = true;
  lastKeyLen_ = n;
  memcpy(lastKey_, k, n);
}

void Writer::Key(const char* k) {
  size_t n = strlen(k);
  TrackKey(k, n);
  Head(kMajText, n);
  Need(n);
  if (!ok_) return;
  memcpy(buf_ + len_, k, n);
  len_ += n;
}

void Writer::EndMap() { inMap_ = false; }

void Writer::BeginArray(size_t n) { Head(kMajArray, n); }
void Writer::EndArray() {}

void Writer::Uint(uint64_t v) { Head(kMajUint, v); }

void Writer::Int(int64_t v) {
  if (v >= 0) {
    Head(kMajUint, static_cast<uint64_t>(v));
  } else {
    Head(kMajNeg, static_cast<uint64_t>(-(v + 1)));
  }
}

void Writer::Bytes(const uint8_t* p, size_t n) {
  Head(kMajBytes, n);
  Need(n);
  if (!ok_ || n == 0) return;
  memcpy(buf_ + len_, p, n);
  len_ += n;
}

void Writer::BytesNull() { Head(kMajBytes, 0); }

void Writer::TextN(const char* s, size_t n) {
  Head(kMajText, n);
  Need(n);
  if (!ok_ || n == 0) return;
  memcpy(buf_ + len_, s, n);
  len_ += n;
}

void Writer::Text(const char* s) { TextN(s, strlen(s)); }

void Writer::Bool(bool v) {
  Need(1);
  if (!ok_) return;
  buf_[len_++] = static_cast<uint8_t>(0xE0 | (v ? 21 : 20));
}

void Writer::Null() {
  Need(1);
  if (!ok_) return;
  buf_[len_++] = 0xF6;
}

// ── Reader ─────────────────────────────────────────────────────────────
uint8_t Reader::ReadByte() {
  if (pos_ >= len_) {
    ok_ = false;
    return 0;
  }
  return buf_[pos_++];
}

bool Reader::ReadHead(uint8_t* major, uint64_t* val) {
  size_t start = pos_;
  uint8_t b = ReadByte();
  if (!ok_) return false;
  *major = static_cast<uint8_t>(b >> 5);
  uint8_t ai = static_cast<uint8_t>(b & 0x1F);
  uint64_t v = 0;
  size_t width = AiWidth(ai);
  if (pos_ + (width - 1) > len_) {
    ok_ = false;
    return false;
  }
  switch (ai) {
    case kAi8: v = buf_[pos_]; break;
    case kAi16: v = (static_cast<uint64_t>(buf_[pos_]) << 8) | buf_[pos_ + 1]; break;
    case kAi32:
      for (int i = 0; i < 4; ++i) v = (v << 8) | buf_[pos_ + i];
      break;
    case kAi64:
      for (int i = 0; i < 8; ++i) v = (v << 8) | buf_[pos_ + i];
      break;
    default:
      if (ai < 24) v = ai;
      else { ok_ = false; return false; }
      break;
  }
  pos_ += width - 1;
  (void)start;
  if (!AiIsMinimal(ai, v)) {  // 拒绝非最短整数表示
    ok_ = false;
    return false;
  }
  *val = v;
  return true;
}

void Reader::Enter() {
  if (depth_ + 1 > kMaxDepth) ok_ = false;
  depth_++;
}

void Reader::Leave() {
  if (depth_ > 0) depth_--;
}

size_t Reader::MapBegin() {
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v)) return 0;
  if (major != kMajMap) {
    ok_ = false;
    return 0;
  }
  if (v * 2 > remaining() + 2) {
    ok_ = false;
    return 0;
  }
  Enter();
  inMap_ = true;
  hasLastKey_ = false;
  lastKeyLen_ = 0;
  itemsLeft_ = static_cast<size_t>(v) * 2;
  return static_cast<size_t>(v);
}

const char* Reader::MapKey(size_t* n) {
  if (!inMap_ || itemsLeft_ == 0) {
    ok_ = false;
    return nullptr;
  }
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v) || major != kMajText) {
    ok_ = false;
    return nullptr;
  }
  if (v > remaining()) {
    ok_ = false;
    return nullptr;
  }
  const char* p = reinterpret_cast<const char*>(buf_ + pos_);
  pos_ += v;
  TrackKey(p, static_cast<size_t>(v));
  itemsLeft_--;
  *n = static_cast<size_t>(v);
  return p;
}

void Reader::EndMap() {
  if (inMap_) {
    inMap_ = false;
    itemsLeft_ = 0;
    Leave();
  }
}

bool Reader::ExpectKey(const char* k) {
  size_t n = 0;
  const char* got = MapKey(&n);
  if (!got) return false;
  size_t want = strlen(k);
  return n == want && memcmp(got, k, n) == 0;
}

void Reader::TrackKey(const char* k, size_t n) {
  if (n >= kMaxTextKeyLen) {
    ok_ = false;
    return;
  }
  if (hasLastKey_) {
    if (n < lastKeyLen_) {
      ok_ = false;
      return;
    }
    if (n == lastKeyLen_ && memcmp(k, lastKey_, n) <= 0) {
      ok_ = false;
      return;
    }
  }
  hasLastKey_ = true;
  lastKeyLen_ = n;
  memcpy(lastKey_, k, n);
}

size_t Reader::ArrayBegin() {
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v)) return 0;
  if (major != kMajArray) {
    ok_ = false;
    return 0;
  }
  if (v > remaining() + 1) {
    ok_ = false;
    return 0;
  }
  Enter();
  itemsLeft_ = static_cast<size_t>(v);
  return static_cast<size_t>(v);
}

void Reader::EndArray() {
  if (itemsLeft_ != 0) ok_ = false;
  itemsLeft_ = 0;
  Leave();
}

uint64_t Reader::Uint() {
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v)) return 0;
  if (major != kMajUint) {
    ok_ = false;
    return 0;
  }
  return v;
}

int64_t Reader::Int() {
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v)) return 0;
  if (major == kMajUint) return static_cast<int64_t>(v);
  if (major == kMajNeg) return -1 - static_cast<int64_t>(v);
  ok_ = false;
  return 0;
}

const uint8_t* Reader::Bytes(size_t* n) {
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v)) {
    *n = 0;
    return nullptr;
  }
  if (major != kMajBytes || v > remaining()) {
    ok_ = false;
    *n = 0;
    return nullptr;
  }
  const uint8_t* p = buf_ + pos_;
  pos_ += v;
  *n = static_cast<size_t>(v);
  return p;
}

const char* Reader::Text(size_t* n) {
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v)) {
    *n = 0;
    return nullptr;
  }
  if (major != kMajText || v > remaining()) {
    ok_ = false;
    *n = 0;
    return nullptr;
  }
  const char* p = reinterpret_cast<const char*>(buf_ + pos_);
  pos_ += v;
  *n = static_cast<size_t>(v);
  return p;
}

bool Reader::Bool() {
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v)) return false;
  if (major != kMajSimple || (v != 20 && v != 21)) {
    ok_ = false;
    return false;
  }
  return v == 21;
}

void Reader::Null() {
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v)) return;
  if (major != kMajSimple || v != 22) ok_ = false;
}

void Reader::SkipItem() {
  uint8_t major;
  uint64_t v;
  if (!ReadHead(&major, &v)) return;
  switch (major) {
    case kMajUint:
    case kMajNeg:
      break;
    case kMajBytes:
    case kMajText:
      if (v > remaining()) {
        ok_ = false;
        return;
      }
      pos_ += v;
      break;
    case kMajArray:
      for (uint64_t i = 0; i < v; ++i) SkipItem();
      break;
    case kMajMap:
      for (uint64_t i = 0; i < v; ++i) {
        SkipItem();
        SkipItem();
      }
      break;
    case kMajSimple:
      if (v != 20 && v != 21 && v != 22) ok_ = false;
      break;
    default:
      ok_ = false;
      break;
  }
}

}  // namespace proto
}  // namespace rockey