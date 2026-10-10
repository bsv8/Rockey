#pragma once
#include "migration_store.hpp"
#include "migration_private.hpp"
#include "store/keystore.h"
#include "i18n/i18n.h"
// A wiped device cannot prove possession of the old private key. This runtime
// uses a RAM-only temporary handshake identity and physical pairing, exclusively
// to reconcile the browser's already committed SAME migration. It never exposes
// key import, signatures, payment state, PIN entry or ordinary wallet activation.
namespace rockey::vlp {
class ErasedMigrationRuntime {
  MigrationStore store;
  vaultlink::MigrationJournal journal;
  std::unique_ptr<vaultlink::IdentityKey> identity;
  std::unique_ptr<vaultlink::Endpoint> endpoint;
  ApprovalUI& ui;
  using Value=vaultlink::Value;
  static std::unique_ptr<vaultlink::IdentityKey> ephemeral(vaultlink::Rng rng){
    vaultlink::Bytes bytes(32);vaultlink::WipeBytes wipe{bytes};vaultlink::check(rng(nullptr,bytes.data(),bytes.size()));return std::make_unique<vaultlink::IdentityKey>(bytes,rng);
  }
  class Status final:public vaultlink::Operation {
    std::function<Value()> run;
   public:explicit Status(std::function<Value()> f):run(std::move(f)){}
    bool ready()override{return true;}bool allowed()override{return true;}Value execute()override{return run();}
  };
  class ConfirmCleanup final:public vaultlink::Operation {
    ApprovalUI& ui;vaultlink::MigrationJournal& journal;Value record;bool started=false,finished=false;Approval answer;
   public:ConfirmCleanup(ApprovalUI& u,vaultlink::MigrationJournal& j,Value r):ui(u),journal(j),record(std::move(r)){}
    bool ready()override{
      if(!started){started=true;ui.begin(Review{"migration.recover-erased","","",{{"requestId",record.at("id").string()},
        {"objectHash",vaultlink::to_hex(record.at("publicKey").binary(33))},
        {"contentHash",vaultlink::to_hex(record.at("targetHash").binary(32))},
        {"risk",i18n::T(i18n::Str::kMigNoOldKey)}}});}
      answer=ui.decision();return answer.state!=Approval::Pending;
    }
    bool allowed()override{return answer.state==Approval::Once;}
    Value execute()override{
      vaultlink::require(started&&!finished&&allowed()&&!keystore::KeyStore::HasKey(),"migration-conflict");
      // No PIN can be checked after its wrapping record has been erased. This
      // path is impossible while ANY key record exists, including a corrupt one.
      vaultlink::require(keystore::KeyStore::Erase(true),"erase-failed");
      journal.advance(record.at("id").string(),"erased",record.at("targetHash"));
      auto result=vaultlink::obj({{"migration",journal.status()}});cancel();return result;
    }
    void cancel()override{if(finished)return;finished=true;if(started)ui.clear();}
    ~ConfirmCleanup()override{cancel();}
  };
  vaultlink::Prepared prepare(const std::string& op,const Value& body,const vaultlink::Bytes& hash){
    using namespace vaultlink;require(!keystore::KeyStore::HasKey(),"migration-conflict");
    if(op=="migration.status"){
      body.fields({});require(hash==commitment("key-migration-status",body),"invalid-commitment");
      return {"key-migration-status",body,std::make_unique<Status>([this]{return obj({{"migration",journal.status()}});})};
    }
    require(op=="migration.recover-erased"||op=="migration.complete","unsupported");body.fields({"id","targetHash"});
    const std::string profile=op=="migration.complete"?"key-migration-complete":"key-migration-recover-erased";
    require(hash==commitment(profile,body),"invalid-commitment");
    auto record=journal.status();
    require(record.at("id").string()==body.at("id").string()&&record.at("targetHash").binary(32)==body.at("targetHash").binary(32),"migration-conflict");
    if(op=="migration.complete")return {profile,body,std::make_unique<Status>([this,body]{journal.advance(body.at("id").string(),"complete",body.at("targetHash"));return obj({{"migration",journal.status()}});})};
    require(record.at("phase").string()!="complete","migration-conflict");
    return {"key-migration-recover-erased",body,std::make_unique<ConfirmCleanup>(ui,journal,record)};
  }
 public:
  ErasedMigrationRuntime(vaultlink::ByteTransport& transport,vaultlink::Rng rng,uint32_t run,ApprovalUI& approval,
    std::function<bool(const std::string&)> pairing,std::function<int()> pairPoll,std::function<void()> clear)
    :journal(store),identity(ephemeral(rng)),ui(approval){
    using namespace vaultlink;
    require(!keystore::KeyStore::HasKey(),"migration-conflict");auto record=journal.status();
    require(record.kind!=Value::Null&&record.at("direction").string()=="to-software"
      &&(record.at("phase").string()=="erasing"||record.at("phase").string()=="erased"||record.at("phase").string()=="complete"),"migration-recovery-unavailable");
    endpoint=std::make_unique<Endpoint>(transport,*identity,rng,run,
      [this](const std::string& op,const Value& b,const Bytes& h){return prepare(op,b,h);},std::move(clear),std::move(pairing));
    endpoint->set_pairing_poll(std::move(pairPoll));endpoint->set_capabilities({Value(uint64_t(0x231))});
  }
  void poll(){vaultlink::require(bool(endpoint),"disconnected");endpoint->poll();}
  ~ErasedMigrationRuntime(){endpoint.reset();identity->lock();}
};
} // namespace rockey::vlp
