#include "proto/frame.h"

#include <string.h>

#include "store/vault_fs.h"

namespace rockey {
namespace proto {
namespace {
constexpr uint8_t kMagic0 = 0xA5;
constexpr uint8_t kMagic1 = 0x5A;
constexpr uint8_t kVersion = 1;
}  // namespace

bool EncodeFrame(uint8_t* out, size_t outCap, FrameType type, uint8_t flags, uint32_t seq,
                 const uint8_t* payload, size_t len, size_t* outLen) {
  if (len > ROCKEY_MAX_FRAME_PAYLOAD) return false;
  size_t total = kFrameHeaderLen + len + kFrameTrailerLen;
  if (outCap < total) return false;
  out[0] = kMagic0;
  out[1] = kMagic1;
  out[2] = kVersion;
  out[3] = static_cast<uint8_t>(type);
  out[4] = flags;
  memcpy(out + 5, &seq, 4);
  uint16_t l = static_cast<uint16_t>(len);
  memcpy(out + 9, &l, 2);
  if (len && payload) memcpy(out + kFrameHeaderLen, payload, len);
  uint32_t crc = store::Crc32(out + 2, kFrameHeaderLen - 2 + len);
  memcpy(out + kFrameHeaderLen + len, &crc, 4);
  *outLen = total;
  return true;
}

void FrameReader::Reset() {
  len_ = 0;
}

void FrameReader::Flush() {
  len_ = 0;
  resyncs_++;
}

// 尝试从内部缓冲里切出一条完整帧；切出后返回 true 并把剩余字节前移。
// 单独成函数，保证"缓冲里已经躺着一条完整帧"时不必等下一批字节就能取出：
// 调用方（Link::Poll）会用同一批输入反复调用 Feed，Feed 必须先把缓冲吐干净，
// 否则已缓冲的帧会被新输入顶在后面，或被重复投递。
bool FrameReader::TakeBuffered(Frame* out) {
  if (len_ < kFrameHeaderLen) return false;
  if (buf_[0] != kMagic0 || buf_[1] != kMagic1) {
    Flush();
    return false;
  }
  if (buf_[2] != kVersion) {
    dropped_++;
    Flush();
    return false;
  }
  uint16_t plen;
  memcpy(&plen, buf_ + 9, 2);
  if (plen > ROCKEY_MAX_FRAME_PAYLOAD) {
    // 主机自报的无界/超限长度：立刻丢弃，不据此分配或拷贝
    dropped_++;
    Flush();
    return false;
  }
  size_t total = kFrameHeaderLen + plen + kFrameTrailerLen;
  if (len_ < total) return false;  // 还没收齐，继续等

  uint32_t crc;
  memcpy(&crc, buf_ + kFrameHeaderLen + plen, 4);
  if (crc != store::Crc32(buf_ + 2, kFrameHeaderLen - 2 + plen)) {
    dropped_++;
    Flush();
    return false;
  }

  uint32_t seq;
  memcpy(&seq, buf_ + 5, 4);
  out->type = static_cast<FrameType>(buf_[3]);
  out->flags = buf_[4];
  out->seq = seq;
  out->len = plen;
  out->payload = buf_ + kFrameHeaderLen;
  size_t rest = len_ - total;
  if (rest) memmove(buf_, buf_ + total, rest);
  len_ = rest;
  return true;
}

bool FrameReader::Feed(const uint8_t* data, size_t len, Frame* out, size_t* consumed) {
  *consumed = 0;
  // 1) 先把缓冲里已有的完整帧取干净（不消耗新输入）
  if (TakeBuffered(out)) return true;

  // 2) 消费新字节。USB 串口会断包/粘包：一次 read 既不等于一帧，也不等于零帧。
  size_t need = kFrameHeaderLen + kFrameTrailerLen;
  for (size_t i = 0; i < len; ++i) {
    if (len_ + need > sizeof(buf_)) {
      // 缓冲已被垃圾填满：丢弃并重新寻找 magic
      dropped_++;
      Flush();
      continue;
    }
    buf_[len_++] = data[i];

    if (len_ == 2 && !(buf_[0] == kMagic0 && buf_[1] == kMagic1)) {
      // 保留可能是 magic0 的最后一个字节
      if (buf_[1] == kMagic0) {
        buf_[0] = kMagic0;
        len_ = 1;
      } else {
        Flush();
      }
      continue;
    }
    if (TakeBuffered(out)) {
      *consumed = i + 1;
      return true;
    }
  }
  *consumed = len;
  return false;
}

}  // namespace proto
}  // namespace rockey