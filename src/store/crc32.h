// CRC-32（IEEE 802.3，反射多项式 0xEDB88320），帧与记录共用的唯一实现。
//
// 单独成文件，使帧层（proto/frame.cpp）不依赖 LittleFS/Arduino，
// 从而可以在主机上直接编译真实实现做正反向向量测试。
#ifndef ROCKEY_STORE_CRC32_H
#define ROCKEY_STORE_CRC32_H

#include <stdint.h>
#include <stddef.h>

namespace rockey {
namespace store {
// Streaming state starts at UINT32_MAX; xor UINT32_MAX after the final chunk.
uint32_t Crc32Extend(uint32_t state, const uint8_t* data, size_t len);
uint32_t Crc32(const uint8_t* data, size_t len);
}  // namespace store
}  // namespace rockey

#endif  // ROCKEY_STORE_CRC32_H