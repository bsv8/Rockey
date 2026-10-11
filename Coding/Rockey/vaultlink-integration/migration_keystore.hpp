#pragma once
#include "migration_private.hpp"
#include "store/keystore.h"
namespace rockey::vlp {
/** Actual device secret adapter. Export is reachable only via the physical
 * once-only physical action above; no ordinary crypto or Connect port receives this. */
class KeyStoreMigrationKeys final:public MigrationKeys {
  vaultlink::Bytes expected;
  std::function<void()> wipe_copies;
  void check() {
    const auto info=keystore::KeyStore::Info_();
    vaultlink::require(keystore::KeyStore::IsUnlocked()&&info.initialized&&expected.size()==33
      &&std::equal(expected.begin(),expected.end(),info.pubkey),"locked");
  }
 public:
  KeyStoreMigrationKeys(vaultlink::Bytes publicKey,std::function<void()> wipe)
    :expected(std::move(publicKey)),wipe_copies(std::move(wipe)) {
      vaultlink::require(bool(wipe_copies),"adapter-required");
    }
  vaultlink::Bytes public_key()override{check();return expected;}
  vaultlink::Bytes export_once()override {
    check();const auto* key=keystore::KeyStore::PrivateKey();vaultlink::require(key!=nullptr,"locked");
    return vaultlink::Bytes(key,key+32);
  }
  void erase()override {
    check();const bool ok=keystore::KeyStore::Erase(true);wipe_copies();
    vaultlink::require(ok,"erase-failed");
  }
};
} // namespace rockey::vlp
