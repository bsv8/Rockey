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

bool FrameReader::Feed(const uint8_t* data, size_t len, Frame* out) {
  // 单次只输出一条帧；剩余数据留给下一次调用（调用方循环直到 Feed 返回 false）
  size_t need = kFrameHeaderLen + kFrameTrailerLen;
  for (size_t i = 0; i < len; ++i) {
    if (len_ + need > sizeof(buf_)) {
      // 缓冲已被垃圾填满：丢弃并重新寻找 magic
      dropped_++;
      Flush();
      // 从当前字节重新开始
      i--;
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
    if (len_ < kFrameHeaderLen) continue;

    uint16_t plen;
    memcpy(&plen, buf_ + 9, 2);
    if (buf_[2] != kVersion) {
      dropped_++;
      Flush();
      continue;
    }
    if (plen > ROCKEY_MAX_FRAME_PAYLOAD) {
      dropped_++;
      Flush();
      continue;
    }
    size_t total = kFrameHeaderLen + plen + kFrameTrailerLen;
    if (len_ < total) continue;

    uint32_t crc;
    memcpy(&crc, buf_ + kFrameHeaderLen + plen, 4);
    if (crc != store::Crc32(buf_ + 2, kFrameHeaderLen - 2 + plen)) {
      dropped_++;
      Flush();
      continue;
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
  return false;
}

}  // namespace proto
}  // namespace rockey