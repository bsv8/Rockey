// 规范编码：RFC 8949 核心确定性子集（CBOR deterministic encoding）。
//
// 只使用：unsigned/negative int、byte string、text string、array、map、bool、null。
//  - 整数一律最短表示；
//  - map 键按"字节长度优先、再字节序"严格递增，编码器强制校验，重复键与乱序键
//    一律使编码/解码失败 —— 同一语义只有唯一字节序列（协议草案 §9 规范编码冻结项）；
//  - 嵌套深度与声明长度受上限约束，主机自报的无界长度不会被分配。
#ifndef ROCKEY_PROTO_CBOR_H
#define ROCKEY_PROTO_CBOR_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace proto {

constexpr size_t kMaxDepth = 6;
constexpr size_t kMaxTextKeyLen = 32;

class Writer {
 public:
  Writer(uint8_t* buf, size_t cap) : buf_(buf), cap_(cap) {}

  void BeginMap(size_t pairs);
  void Key(const char* k);   // 必须在每个值之前调用，且严格递增
  void EndMap();

  void BeginArray(size_t n);
  void EndArray();

  void Uint(uint64_t v);
  void Int(int64_t v);
  void Bytes(const uint8_t* p, size_t n);
  void BytesNull();
  void Text(const char* s);
  void TextN(const char* s, size_t n);
  void Bool(bool v);
  void Null();

  bool ok() const { return ok_; }
  size_t size() const { return len_; }
  const uint8_t* data() const { return buf_; }

 private:
  void Head(uint8_t major, uint64_t v);
  void Need(size_t n);
  void TrackKey(const char* k, size_t n);

  uint8_t* buf_;
  size_t cap_;
  size_t len_ = 0;
  bool ok_ = true;
  bool inMap_ = false;
  bool hasLastKey_ = false;
  size_t lastKeyLen_ = 0;
  char lastKey_[kMaxTextKeyLen] = {0};
};

class Reader {
 public:
  Reader(const uint8_t* buf, size_t len) : buf_(buf), len_(len) {}

  bool ok() const { return ok_; }
  size_t remaining() const { return len_ - pos_; }
  size_t position() const { return pos_; }

  size_t MapBegin();                 // 返回键值对数量
  const char* MapKey(size_t* n);     // 读下一个键；失败返回 nullptr
  void EndMap();

  size_t ArrayBegin();
  void EndArray();

  uint64_t Uint();
  int64_t Int();
  const uint8_t* Bytes(size_t* n);
  const char* Text(size_t* n);
  bool Bool();
  void Null();
  void SkipItem();

  // 便捷：期待某个文本键，否则失败
  bool ExpectKey(const char* k);

 private:
  uint8_t ReadByte();
  bool ReadHead(uint8_t* major, uint64_t* val);
  void TrackKey(const char* k, size_t n);
  void Enter();
  void Leave();

  const uint8_t* buf_;
  size_t len_;
  size_t pos_ = 0;
  bool ok_ = true;
  uint8_t depth_ = 0;
  size_t itemsLeft_ = 0;
  bool inMap_ = false;
  bool hasLastKey_ = false;
  size_t lastKeyLen_ = 0;
  char lastKey_[kMaxTextKeyLen] = {0};
};

}  // namespace proto
}  // namespace rockey

#endif  // ROCKEY_PROTO_CBOR_H