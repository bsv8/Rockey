#pragma once
#include "import_requests.hpp"
namespace rockey::vlp {
/** Temporary identity is transport-only. Once import succeeds this session
 * remains migration-only; ordinary wallet activation requires a fresh USB
 * possession challenge of the actual imported key after PIN unlock. */
class ProvisionNetworkQuery final : public vaultlink::Operation {
  ProvisionKeys& keys;
 public:
  explicit ProvisionNetworkQuery(ProvisionKeys& k):keys(k){}
  bool ready() override{return true;}
  bool allowed() override{return keys.ready()||keystore::KeyStore::IsUnlocked();}
  vaultlink::Value execute() override {
    vaultlink::require(allowed(),"locked");
    if(!keystore::KeyStore::HasKey())return vaultlink::obj({{"bsvNetwork",vaultlink::Value()}});
    const auto info=keystore::KeyStore::Info_();
    vaultlink::require(info.initialized,"network-identity-required");
    return vaultlink::obj({{"bsvNetwork",info.bsvNetwork==keystore::BsvNetwork::Test?"test":"main"},
      {"publicKey",vaultlink::Bytes(info.pubkey,info.pubkey+33)}});
  }
};
class ProvisionRuntime {
  class Staging final:public vaultlink::Store {vaultlink::Bytes bytes;public:vaultlink::Bytes load()override{return bytes;}void save(const vaultlink::Bytes& b)override{bytes=b;}} store;
  vaultlink::MigrationJournal journal;
  std::unique_ptr<vaultlink::IdentityKey> identity;
  std::unique_ptr<ImportRequests> requests;
  std::unique_ptr<vaultlink::Endpoint> endpoint;
  ProvisionKeys& keys;
 public:
  ProvisionRuntime(vaultlink::ByteTransport& transport,vaultlink::Rng rng,uint32_t run,ApprovalUI& ui,ProvisionKeys& k,
    std::function<bool(const std::string&)> pair,std::function<int()> pairPoll,std::function<void()> clear)
    :journal(store),keys(k){
    using namespace vaultlink;require(!keystore::KeyStore::HasKey()&&keys.ready(),"device-import-not-armed");
    auto r=journal.status();require(r.kind==Value::Null||(r.at("direction").string()=="to-hardware"&&r.at("phase").string()=="staged"),"migration-conflict");
    Bytes secret(32);WipeBytes wipe{secret};check(rng(nullptr,secret.data(),secret.size()));identity=std::make_unique<IdentityKey>(secret,rng);
    requests=std::make_unique<ImportRequests>(journal,&keys,ui,rng);
    endpoint=std::make_unique<Endpoint>(transport,*identity,rng,run,[this](const std::string& op,const Value& b,const Bytes& h){if(op=="identity.network"){b.fields({});require(commitment("identity-network",b)==h,"invalid-commitment");return Prepared{"identity-network",b,std::make_unique<ProvisionNetworkQuery>(keys)};}return requests->prepare(op,b,h);},
      [this,clear]{keys.clear();keystore::KeyStore::Lock();clear();},std::move(pair));
    endpoint->set_pairing_poll(std::move(pairPoll));endpoint->set_capabilities({Value(uint64_t(0x232))});
  }
  bool connected()const{return endpoint && endpoint->connected();}
  bool receiving()const{return journal.pending();}
  void poll(){endpoint->poll();}
  ~ProvisionRuntime(){endpoint.reset();requests.reset();identity->lock();keys.clear();keystore::KeyStore::Lock();}
};
} // namespace rockey::vlp
