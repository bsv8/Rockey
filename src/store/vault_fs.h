// 设备私有 LittleFS 分区上的原子记录存储。
//
// 断电安全策略（R2 / RK-07）：
//  - 每条记录带 generation 与 CRC32；读取时校验，损坏则视为不存在；
//  - 写入走 "临时文件 -> rename" 单一提交点，rename 之前旧记录保持有效；
//  - 记录头带 generation，单调递增，读旧记录即得下一代号；
//  - LittleFS 自身带 wear levelling；每次提交写一个新文件并 rename，
//    长期使用的记录（如失败计数）额外由 LittleFS 的 rename 摊到不同块。
#ifndef ROCKEY_STORE_VAULT_FS_H
#define ROCKEY_STORE_VAULT_FS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace rockey {
namespace store {

// 文件路径（分区表 partitions/partitions_rockey.csv 定义的 rockey 分区）
extern const char* const kPathDevice;    // /vault/dev.bin
extern const char* const kPathKey;       // /vault/key.bin
extern const char* const kPathState;     // /vault/state.bin
extern const char* const kPathBackup;    // /vault/backup.bin
extern const char* const kPathMigration; // /vault/mig.bin

constexpr size_t kRecordHeaderLen = 18;  // magic(4) version(2) generation(4) crc(4) len(4)

bool Init();
bool Available();
uint32_t Crc32(const uint8_t* data, size_t len);

// 记录读写；payload 不含头
bool ReadRecord(const char* path, uint8_t* out, size_t outCap, size_t* outLen,
                uint32_t* outGeneration);
bool WriteRecord(const char* path, uint16_t version, const uint8_t* payload, size_t len,
                 uint32_t* outGeneration);
bool Remove(const char* path);
bool Exists(const char* path);

// 单调计数器：取两个槽中 generation 较大者（失败计数跨重启保存）
bool ReadCounter(const char* path, uint32_t* value);
bool WriteCounter(const char* path, uint32_t value);

}  // namespace store
}  // namespace rockey

#endif  // ROCKEY_STORE_VAULT_FS_H