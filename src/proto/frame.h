// 帧层：有界解析、分片重组、序号、重放与序号检查。
//
// 冻结帧格式（docs/冻结/协议规范.md）：
//   0  magic0 = 0xA5
//   1  magic1 = 0x5A
//   2  version(1) = 1
//   3  type(1)
//   4  flags(1)
//   5  seq(4, little endian)
//   9  payloadLen(2, little endian) <= ROCKEY_MAX_FRAME_PAYLOAD
//   11 payload[payloadLen]
//   11+len crc32(4, little endian，覆盖 [2, 11+len))
//
// USB 串口有断包/粘包，绝不把一次 read 当成一帧；超长/超速输入一律丢弃并计数，
// 不允许主机自报无界长度导致内存耗尽。
#ifndef ROCKEY_PROTO_FRAME_H
#define ROCKEY_PROTO_FRAME_H

#include <stdint.h>
#include <stddef.h>

#include "core/rockey_config.h"

namespace rockey {
namespace proto {

enum class FrameType : uint8_t {
  kInvalid = 0x00,
  kHello = 0x01,        // 未加密：主机 -> 设备
  kHelloAck = 0x02,     // 未加密：设备 -> 主机
  kPairConfirm = 0x03,  // 已加密
  kPairOk = 0x04,       // 已加密
  kRequest = 0x10,      // 已加密
  kResponse = 0x11,     // 已加密
  kEvent = 0x12,        // 已加密，设备 -> 主机
  kPing = 0x20,
  kPong = 0x21,
  kAbort = 0x30,        // 已加密
};

enum class FrameFlags : uint8_t {
  kNone = 0x00,
  kAckRequired = 0x01,
  kCancel = 0x02,
};

constexpr size_t kFrameHeaderLen = 11;
constexpr size_t kFrameTrailerLen = 4;

struct Frame {
  FrameType type = FrameType::kInvalid;
  uint8_t flags = 0;
  uint32_t seq = 0;
  uint16_t len = 0;
  const uint8_t* payload = nullptr;  // 指向内部缓冲，NextFrame 返回后立即失效
};

// 编码：payload 已被信道加密时传密文
bool EncodeFrame(uint8_t* out, size_t outCap, FrameType type, uint8_t flags, uint32_t seq,
                 const uint8_t* payload, size_t len, size_t* outLen);

class FrameReader {
 public:
  void Reset();
  // 喂入一段字节；解析出一条完整帧时返回 true，*out.payload 指向内部缓冲
  bool Feed(const uint8_t* data, size_t len, Frame* out);
  uint32_t dropped() const { return dropped_; }
  uint32_t resyncs() const { return resyncs_; }

 private:
  void Flush();

  uint8_t buf_[ROCKEY_MAX_FRAME_PAYLOAD + kFrameHeaderLen + kFrameTrailerLen]{};
  size_t len_ = 0;
  uint32_t dropped_ = 0;
  uint32_t resyncs_ = 0;
};

}  // namespace proto
}  // namespace rockey

#endif  // ROCKEY_PROTO_FRAME_H