#pragma once
#include "../vaultlink-sdk/device/sdk/policy.hpp"
#include "store/vault_fs.h"
namespace rockey::vlp {
class PolicyStore final : public vaultlink::Store {
 public:
  vaultlink::Bytes load() override {
    vaultlink::require(store::Available(), "storage-unavailable");
    constexpr const char* path = "/vault/vlp-policy.bin";
    if (!store::Exists(path)) return {};
    vaultlink::Bytes bytes(65536);
    size_t len = 0;
    uint32_t generation = 0;
    // 损坏记录与不存在不能合并，否则已有额度/未知支付会被重置。
    vaultlink::require(store::ReadRecord(path, bytes.data(), bytes.size(), &len, &generation), "corrupt-policy");
    vaultlink::require(len > 0 && len <= bytes.size(), "corrupt-policy");
    bytes.resize(len);
    // resize 不释放 64KiB 容量。解码还会构造整份 CBOR 树，历史账本增长
    // 时同时持有最大缓冲和树会耗尽 ESP32 堆；只保留实际记录长度。
    bytes.shrink_to_fit();
    return bytes;
  }
  void save(const vaultlink::Bytes& bytes) override {
    vaultlink::require(store::Available() && !bytes.empty() && bytes.size() <= 65536, "storage-unavailable");
    uint32_t generation = 0;
    vaultlink::require(store::WriteRecord("/vault/vlp-policy.bin", 1, bytes.data(), bytes.size(), &generation), "storage-failed");
  }
};

}
