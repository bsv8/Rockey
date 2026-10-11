#pragma once
#include "approval_ui.hpp"
#include "../vaultlink-sdk/device/sdk/endpoint.hpp"
#include "../vaultlink-sdk/device/sdk/migration.hpp"
#include <functional>
namespace rockey::vlp {
// Private firmware port, not a host API. Runtime supplies the actual KeyStore
// adapter; the paired browser may request export, but only a fresh physical
// once decision authorizes it. An unlocked device does not ask for PIN again.
struct MigrationKeys {
  virtual vaultlink::Bytes public_key()=0;
  virtual vaultlink::Bytes export_once()=0;
  virtual void erase()=0;
  virtual ~MigrationKeys()=default;
};
class MigrationPrivateRequests {
  using Value=vaultlink::Value;
  using Bytes=vaultlink::Bytes;
  vaultlink::MigrationJournal& journal;
  MigrationKeys& keys;
  ApprovalUI& ui;
  std::function<Bytes()> bank;
  std::function<std::string(bool)> warning;
  class Physical final:public vaultlink::Operation {
    ApprovalUI& ui;
    Review review;
    Approval answer;
    std::function<Value()> run;
    bool started=false,finished=false;
   public:
    Physical(ApprovalUI& u,Review r,std::function<Value()> f)
      :ui(u),review(std::move(r)),run(std::move(f)){}
    bool ready()override{if(!started){ui.begin(review);started=true;}answer=ui.decision();return answer.state!=Approval::Pending;}
    bool allowed()override{return answer.state==Approval::Once&&(!review.requires_pin||answer.pin_verified);}
    Value execute()override {
      vaultlink::require(started&&!finished&&allowed(),"physical-confirmation-required");
      auto result=run();cancel();return result;
    }
    void cancel()override{if(finished)return;finished=true;if(started)ui.clear();}
    ~Physical()override{cancel();}
  };
  class Immediate final:public vaultlink::Operation {
    std::function<Value()> run;
   public:explicit Immediate(std::function<Value()> f):run(std::move(f)){}
    bool ready()override{return true;}bool allowed()override{return true;}
    Value execute()override{return run();}
  };
  void check_bank(const Value& record) {
    auto bytes=bank();
    vaultlink::require(vaultlink::sha256(bytes)==record.at("policyHash").binary(32),"migration-policy-changed");
    auto value=vaultlink::decode(bytes,65536);
    for(const auto& payment:value.at("pending").array)
      vaultlink::require(payment.at("state").string()!="reserved","migration-payment-busy");
  }
 public:
  MigrationPrivateRequests(vaultlink::MigrationJournal& j,MigrationKeys& k,ApprovalUI& u,
    std::function<Bytes()> b,std::function<std::string(bool)> text):journal(j),keys(k),ui(u),bank(std::move(b)),warning(std::move(text)){}
  vaultlink::Prepared prepare(const std::string& op,const Value& body,const Bytes& hash) {
    using namespace vaultlink;
    if(op=="migration.export") {
      body.fields({"id","walletGeneration","sourceHash","policyHash"});
      require(commitment("key-migration-export",body)==hash,"invalid-commitment");
      auto proposed=inspect_device_migration(obj({{"version",uint64_t(1)},{"id",body.at("id")},
        {"walletGeneration",body.at("walletGeneration")},{"publicKey",keys.public_key()},
        {"sourceHash",body.at("sourceHash")},{"policyHash",body.at("policyHash")},
        {"direction","to-software"},{"phase","staged"},{"targetHash",Value()}}));
      auto current=journal.status();
      if(current.kind!=Value::Null&&current.at("phase").string()!="complete") {
        require(current.at("direction").string()=="to-software"
          &&current.at("targetHash").kind==Value::Null,"migration-conflict");
      }
      check_bank(proposed);
      Review review{op,"","",{{"operation",op},{"requestId",body.at("id").string()},
        {"objectHash",to_hex(proposed.at("publicKey").binary(33))},{"risk",warning(false)}}};
      return {"key-migration-export",body,std::make_unique<Physical>(ui,review,[this,proposed] {
        require(keys.public_key()==proposed.at("publicKey").binary(33),"migration-conflict");
        check_bank(proposed);journal.begin(proposed);
        journal.advance(proposed.at("id").string(),"device-committed");
        auto secret=keys.export_once();WipeBytes wipe{secret};require(secret.size()==32,"invalid-key");
        return obj({{"privateKey",secret},{"migration",journal.status()}});
      }),false};
    }
    require(op=="migration.host-commit"||op=="migration.erase","unsupported");
    body.fields({"id","targetHash"});const auto id=body.at("id").string();body.at("targetHash").binary(32);
    const std::string profile=op=="migration.erase"?"key-migration-erase":"key-migration-host-commit";
    require(commitment(profile,body)==hash,"invalid-commitment");
    auto current=journal.status();require(current.kind!=Value::Null&&current.at("id").string()==id
      &&current.at("direction").string()=="to-software"&&current.at("publicKey").binary(33)==keys.public_key(),"migration-conflict");
    if(op=="migration.host-commit")return {profile,body,std::make_unique<Immediate>([this,id,body] {
      // Browser commit completes transfer even when the device copy is retained.
      // Erasure is a subsequent independent once-only physical request.
      if(journal.status().at("phase").string()!="complete") {
        journal.advance(id,"host-committed",body.at("targetHash"));
        journal.advance(id,"complete",body.at("targetHash"));
      } else require(journal.status().at("targetHash").binary(32)==body.at("targetHash").binary(32),"migration-conflict");
      return obj({{"migration",journal.status()}});
    })};
    require((current.at("phase").string()=="complete"||current.at("phase").string()=="erasing")
      &&current.at("targetHash").binary(32)==body.at("targetHash").binary(32),"migration-conflict");
    Review review{op,"","",{{"operation",op},{"requestId",id},
      {"objectHash",to_hex(current.at("publicKey").binary(33))},{"contentHash",to_hex(body.at("targetHash").binary(32))},
      {"risk",warning(true)}}};
    return {profile,body,std::make_unique<Physical>(ui,review,[this,id,body,current] {
      require(keys.public_key()==current.at("publicKey").binary(33),"migration-conflict");
      if(current.at("phase").string()!="erasing")check_bank(current);
      journal.advance(id,"erasing",body.at("targetHash"));keys.erase();
      journal.advance(id,"erased",body.at("targetHash"));return obj({{"migration",journal.status()}});
    })};
  }
};
} // namespace rockey::vlp
