#pragma once
#include "import_requests.hpp"
namespace rockey::vlp {
/** Temporary identity is transport-only. Once import succeeds this session
 * remains migration-only; ordinary wallet activation requires a fresh USB
 * possession challenge of the actual imported key after PIN unlock. */
class ProvisionRuntime {
  MigrationStore store;vaultlink::MigrationJournal journal;
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
    endpoint=std::make_unique<Endpoint>(transport,*identity,rng,run,[this](const std::string& op,const Value& b,const Bytes& h){return requests->prepare(op,b,h);},
      [this,clear]{keys.clear();keystore::KeyStore::Lock();clear();},std::move(pair));
    endpoint->set_pairing_poll(std::move(pairPoll));endpoint->set_capabilities({Value(uint64_t(0x232))});
  }
  void poll(){endpoint->poll();}
  ~ProvisionRuntime(){endpoint.reset();requests.reset();identity->lock();keys.clear();keystore::KeyStore::Lock();}
};
} // namespace rockey::vlp
