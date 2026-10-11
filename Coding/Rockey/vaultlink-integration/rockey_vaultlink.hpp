#pragma once
// 协议由固定版本 SDK 实现；此处只适配真实 KeyStore 和原子记录存储。
#include "../vaultlink-sdk/device/sdk/endpoint.hpp"
#include "../vaultlink-sdk/device/sdk/policy.hpp"
#include "../vaultlink-sdk/device/sdk/migration.hpp"
#include "store/keystore.h"
#include "store/vault_fs.h"
#include "crypto/secure.h"
#include "operations.hpp"
#include "migration_requests.hpp"
#include "migration_keystore.hpp"
#include "migration_store.hpp"
#include "policy_store.hpp"
#include "import_requests.hpp"
#include "i18n/i18n.h"
#include <functional>
#include <memory>

namespace rockey::vlp {
class NetworkIdentityQuery final : public vaultlink::Operation {
 public:
  bool ready() override { return true; }
  bool allowed() override { return keystore::KeyStore::IsUnlocked(); }
  vaultlink::Value execute() override {
    using namespace vaultlink;
    require(keystore::KeyStore::IsUnlocked(),"locked");
    auto info=keystore::KeyStore::Info_();require(info.initialized,"network-identity-required");
    return obj({{"bsvNetwork",info.bsvNetwork==keystore::BsvNetwork::Test?"test":"main"},{"publicKey",Bytes(info.pubkey,info.pubkey+33)}});
  }
};

inline constexpr const char* sdk_version = "0.2.0-draft.1";
inline constexpr uint8_t wire_version = 2;

/** PIN 成功后由固件调用。无主机 PIN/自动配对/测试私钥/任意摘要入口。 */
class Runtime final {
 public:
  using Factory = std::function<vaultlink::Prepared(const std::string&, const vaultlink::Value&, const vaultlink::Bytes&)>;
  using Pairing = std::function<bool(const std::string&)>;
  Runtime(vaultlink::ByteTransport& transport, vaultlink::Rng rng, uint32_t run,
          ApprovalUI& ui, vaultlink::Store& store, Pairing physicalPairing,
          std::function<int()> pairingPoll, std::function<void()> revokeSessions,
          std::function<bool()> exportArmed,std::function<void()> disarmExport)
      : revoke_(std::move(revokeSessions)) {
    vaultlink::require(keystore::KeyStore::IsUnlocked(), "locked");
    vaultlink::require(bool(physicalPairing) && bool(revoke_), "adapter-required");
    const auto* plain = keystore::KeyStore::PrivateKey();
    vaultlink::require(plain != nullptr, "locked");
    vaultlink::Bytes temporary(plain, plain + 32);
    try { identity_ = std::make_unique<vaultlink::IdentityKey>(temporary, rng); }
    catch (...) { secure::Wipe(temporary.data(), temporary.size()); throw; }
    secure::Wipe(temporary.data(), temporary.size());
    payments_ = std::make_unique<PaymentService>(*identity_, store, ui,keystore::KeyStore::Info_().bsvNetwork==keystore::BsvNetwork::Test?"test":"main");
    migration_ = std::make_unique<vaultlink::MigrationJournal>(migration_store_);
    migration_keys_=std::make_unique<KeyStoreMigrationKeys>(identity_->public_key(),std::move(exportArmed),std::move(disarmExport),
      [this]{identity_->lock();});
    migration_private_=std::make_unique<MigrationPrivateRequests>(*migration_,*migration_keys_,ui,
      [this]{return payments_->policy_bank();},[](bool erase){return std::string(i18n::T(erase?i18n::Str::kEraseWarning:i18n::Str::kExportWarning));});
    import_requests_=std::make_unique<ImportRequests>(*migration_,nullptr,ui,rng);
    migration_requests_=std::make_unique<MigrationRequests>(*payments_,*migration_,identity_->public_key(),migration_private_.get());
    endpoint_ = std::make_unique<vaultlink::Endpoint>(transport, *identity_, rng, run,
      [this](const std::string& op, const vaultlink::Value& body, const vaultlink::Bytes& hash) {
        if(op=="identity.network") {
          body.fields({});vaultlink::require(vaultlink::commitment("identity-network",body)==hash,"invalid-commitment");
          return vaultlink::Prepared{"identity-network",body,std::make_unique<NetworkIdentityQuery>()};
        }
        if(op.rfind("migration.import-",0)==0)return import_requests_->prepare(op,body,hash);
        return migration_requests_->prepare(op,body,hash);
      },
      [this] {
        // USB 心跳失活、配对拒绝或浏览器重连只结束通讯会话。
        // SDK reset 已擦除链路材料和身份副本；设备仍通电且本地已解锁时，
        // 从 KeyStore 的内存私钥重新准备身份。绝不恢复旧授权或旧链路密钥。
        payments_->disconnected();
        revoke_();
        if (!closing_ && keystore::KeyStore::IsUnlocked()) {
          const auto* plain = keystore::KeyStore::PrivateKey();
          vaultlink::require(plain != nullptr, "locked");
          vaultlink::Bytes temporary(plain, plain + 32);
          vaultlink::WipeBytes wipe{temporary};
          identity_->unlock(temporary);
        }
      }, std::move(physicalPairing));
    endpoint_->set_pairing_poll(std::move(pairingPoll));
    // 本产品实现渠道额度支付；不宣称旧任意摘要或尚未实现的费用池能力。
    endpoint_->set_capabilities({vaultlink::Value(uint64_t(0x230)),vaultlink::Value(uint64_t(0x233))});
  }
  ~Runtime() { lock(); }
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;
  size_t grant_count() const{return payments_?payments_->grant_count():0;}
  ScopeGrants::Entry grant(size_t i) const{vaultlink::require(bool(payments_),"locked");return payments_->grant(i);}
  void cancel_grant(size_t i){vaultlink::require(bool(payments_),"locked");payments_->cancel_grant(i);}
  void cancel_grants(){if(payments_)payments_->cancel_grants();}
  void poll() {
    vaultlink::require(bool(endpoint_), "disconnected");
    if (!keystore::KeyStore::IsUnlocked()) { lock(); return; }
    endpoint_->poll();
  }
  void lock() noexcept {
    if (!endpoint_) return;
    closing_ = true;
    // 显式锁定/销毁仍擦除钱包私钥；此时 reset 回调不能重新准备身份。
    keystore::KeyStore::Lock();
    try { endpoint_->reset(); } catch (...) { keystore::KeyStore::Lock(); }
    endpoint_.reset();
    migration_requests_.reset();
    import_requests_.reset();
    migration_private_.reset();
    migration_keys_.reset();
    payments_.reset();
    migration_.reset();
    if (identity_) identity_->lock();
    identity_.reset();
  }
 private:
  bool closing_ = false;
  std::function<void()> revoke_;
  std::unique_ptr<vaultlink::IdentityKey> identity_;
  std::unique_ptr<PaymentService> payments_;
  MigrationStore migration_store_;
  std::unique_ptr<vaultlink::MigrationJournal> migration_;
  std::unique_ptr<MigrationRequests> migration_requests_;
  std::unique_ptr<ImportRequests> import_requests_;
  std::unique_ptr<KeyStoreMigrationKeys> migration_keys_;
  std::unique_ptr<MigrationPrivateRequests> migration_private_;
  std::unique_ptr<vaultlink::Endpoint> endpoint_;
};
} // namespace rockey::vlp
