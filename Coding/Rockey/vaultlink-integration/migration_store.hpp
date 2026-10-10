#pragma once
#include "../vaultlink-sdk/device/sdk/migration.hpp"
#include "store/vault_fs.h"
namespace rockey::vlp {
/** Atomic PUBLIC recovery record. Missing and corrupt are distinct; migration
 * from the retired wire must not silently enable v2 signing or a fresh key. */
class MigrationStore final:public vaultlink::Store {
 public:
  static constexpr const char* path="/vault/vlp-migration.bin";
  vaultlink::Bytes load()override {
    vaultlink::require(store::Available(),"storage-unavailable");
    vaultlink::require(!store::Exists(store::kPathMigration),"legacy-migration-recovery-required");
    if(!store::Exists(path))return {};
    vaultlink::Bytes bytes(1024);size_t size=0;
    vaultlink::require(store::ReadRecord(path,bytes.data(),bytes.size(),&size,nullptr)&&size>0,"corrupt-migration");
    bytes.resize(size);return bytes;
  }
  void save(const vaultlink::Bytes& bytes)override {
    vaultlink::require(!bytes.empty()&&bytes.size()<=1024,"corrupt-migration");
    vaultlink::require(store::WriteRecord(path,1,bytes.data(),bytes.size(),nullptr),"storage-failed");
  }
};
} // namespace rockey::vlp
