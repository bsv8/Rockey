#pragma once
#include "provision_keys.hpp"
#include "../vaultlink-sdk/device/sdk/migration_import.hpp"
#include "approval_ui.hpp"
#include "../vaultlink-sdk/device/sdk/endpoint.hpp"
#include "i18n/i18n.h"
namespace rockey::vlp {
/** A migration-only router, usable with a temporary transport identity or the
 * actual PIN-unlocked imported key after reboot. It never signs host digests or
 * enables payments before both durable journals commit. */
class ImportRequests {
  using Value=vaultlink::Value;using Bytes=vaultlink::Bytes;
  vaultlink::MigrationJournal& journal;ProvisionKeys* keys;ApprovalUI& ui;vaultlink::Rng rng;
  static constexpr const char* meta_path="/vault/vlp-import-meta.bin";
  static constexpr const char* bank_path="/vault/vlp-import-stage.bin";
  static Bytes read(const char* path,size_t cap){
    using namespace vaultlink;require(store::Available(),"storage-unavailable");
    if(!store::Exists(path))return {};Bytes b(cap);size_t n=0;
    require(store::ReadRecord(path,b.data(),b.size(),&n,nullptr)&&n>0,"corrupt-import-stage");b.resize(n);return b;
  }
  static void write(const char* path,const Bytes& bytes){vaultlink::require(!bytes.empty()&&store::WriteRecord(path,1,bytes.data(),bytes.size(),nullptr),"storage-failed");}
  Value metadata(const std::string& id){using namespace vaultlink;auto b=read(meta_path,128);require(!b.empty(),"import-stage-missing");auto m=decode(b,128);m.fields({"id","size"});require(m.at("id").string()==id&&m.at("size").integer()>0&&m.at("size").integer()<=65536,"migration-conflict");return m;}
  Bytes complete_bank(const Value& record){
    using namespace vaultlink;auto m=metadata(record.at("id").string());auto bank=read(bank_path,65536);
    require(bank.size()==m.at("size").integer()&&sha256(bank)==record.at("policyHash").binary(32),"import-stage-incomplete");
    struct Validation final:Store {Bytes bytes;explicit Validation(Bytes b):bytes(std::move(b)){}Bytes load()override{return bytes;}void save(const Bytes& b)override{require(b==bytes,"non-canonical-import-policy");}} validation(bank);
    auto source=decode(bank,65536);require(source.at("version").integer()==2||source.at("version").integer()==3,"unsupported-policy-version");
    for(const auto& p:source.at("pending").array)require(p.at("state").string()!="reserved","migration-payment-busy");
    const auto network=keys&&keys->ready()?keys->network():keystore::KeyStore::Info_().bsvNetwork;
    Policy policy(validation,to_hex(record.at("publicKey").binary(33)),sha256,network==keystore::BsvNetwork::Test?"test":"main");return bank;
  }
  class Action final:public vaultlink::Operation {
    ApprovalUI* ui;Review review;std::function<Value()> run;bool started=false,finished=false;Approval answer;
   public:Action(std::function<Value()> f):ui(nullptr),run(std::move(f)){}
    Action(ApprovalUI& u,Review r,std::function<Value()> f):ui(&u),review(std::move(r)),run(std::move(f)){}
    bool ready()override{if(!ui)return true;if(!started){started=true;ui->begin(review);}answer=ui->decision();return answer.state!=Approval::Pending;}
    bool allowed()override{return !ui||(answer.state==Approval::Once&&answer.pin_verified);}
    Value execute()override{vaultlink::require(!finished&&(!ui||started)&&allowed(),"physical-confirmation-required");auto v=run();cancel();return v;}
    void cancel()override{if(finished)return;finished=true;if(ui&&started)ui->clear();}
    ~Action()override{cancel();}
  };
  Value proof(const Value& body){
    using namespace vaultlink;using K=keystore::KeyStore;auto r=journal.status();
    require(r.kind!=Value::Null&&r.at("direction").string()=="to-hardware"&&r.at("id").string()==body.at("id").string(),"migration-conflict");
    require(K::IsUnlocked()&&K::PrivateKey(),"locked");auto bank=complete_bank(r);PolicyStore disk;
    require(disk.load()==bank,"migration-policy-changed");Bytes secret(K::PrivateKey(),K::PrivateKey()+32);WipeBytes wipe{secret};IdentityKey actual(secret,rng);
    require(actual.public_key()==r.at("publicKey").binary(33),"wrong-key");
    if(r.at("phase").string()=="staged")journal.advance(r.at("id").string(),"device-committed");
    return obj({{"migration",journal.status()},{"signature",actual.sign(migration_import_proof_commitment(r,body.at("challenge").binary(32)))}});
  }
 public:
  ImportRequests(vaultlink::MigrationJournal& j,ProvisionKeys* k,ApprovalUI& u,vaultlink::Rng random):journal(j),keys(k),ui(u),rng(random){}
  vaultlink::Prepared prepare(const std::string& op,const Value& body,const Bytes& hash){
    using namespace vaultlink;
    const std::string profile=op=="migration.status"?"key-migration-status":op=="migration.import-begin"?"key-import-begin":
      op=="migration.import-stage"?"key-import-stage":op=="migration.import-stage-status"?"key-import-stage-status":
      op=="migration.import-key"?"key-import-key":op=="migration.import-proof"?"key-import-proof-request":
      op=="migration.import-commit"?"key-import-commit":"";
    require(!profile.empty(),"unsupported");require(commitment(profile,body)==hash,"invalid-commitment");
    if(op=="migration.status"){body.fields({});return {profile,body,std::make_unique<Action>([this]{return obj({{"migration",journal.status()}});})};}
    if(op=="migration.import-begin"){
      body.fields({"id","walletGeneration","publicKey","sourceHash","policyHash","size"});
      require(keys&&keys->ready()&&!keystore::KeyStore::HasKey(),"device-import-not-armed");
      const auto size=body.at("size").integer();require(size>0&&size<=65536,"invalid-size");
      auto r=inspect_device_migration(obj({{"version",uint64_t(1)},{"id",body.at("id")},{"walletGeneration",body.at("walletGeneration")},
        {"publicKey",body.at("publicKey")},{"sourceHash",body.at("sourceHash")},{"policyHash",body.at("policyHash")},{"direction","to-hardware"},{"phase","staged"},{"targetHash",Value()}}));
      return {profile,body,std::make_unique<Action>([this,r,size]{
        require(keys&&keys->ready()&&!keystore::KeyStore::HasKey(),"device-import-not-armed");journal.begin(r);
        auto old=read(meta_path,128);if(!old.empty())require(encode(metadata(r.at("id").string()),128)==encode(obj({{"id",r.at("id")},{"size",size}}),128),"migration-conflict");
        else {require(!store::Exists(bank_path),"corrupt-import-stage");write(meta_path,encode(obj({{"id",r.at("id")},{"size",size}}),128));}
        return obj({{"migration",journal.status()}});
      })};
    }
    auto r=journal.status();require(r.kind!=Value::Null&&r.at("direction").string()=="to-hardware"&&r.at("id").string()==body.at("id").string(),"migration-conflict");
    if(op=="migration.import-stage-status"){
      body.fields({"id"});return {profile,body,std::make_unique<Action>([this,r]{auto m=metadata(r.at("id").string());auto b=read(bank_path,65536);
        require(b.size()<=m.at("size").integer(),"corrupt-import-stage");return obj({{"size",uint64_t(b.size())},{"total",m.at("size")},{"sha256",sha256(b)}});})};
    }
    if(op=="migration.import-stage"){
      body.fields({"id","offset","chunk"});auto chunk=body.at("chunk").binary();require(!chunk.empty()&&chunk.size()<=8192,"invalid-size");
      require(r.at("phase").string()=="staged"&&!keystore::KeyStore::HasKey()&&keys&&keys->ready(),"migration-conflict");
      return {profile,body,std::make_unique<Action>([this,r,body]{
        require(keys&&keys->ready()&&!keystore::KeyStore::HasKey(),"device-import-not-armed");auto m=metadata(r.at("id").string());auto b=read(bank_path,65536);
        const auto offset=body.at("offset").integer();const auto& chunk=body.at("chunk").binary();
        require(offset<=b.size()&&offset<=m.at("size").integer()&&chunk.size()<=m.at("size").integer()-offset,"invalid-range");
        if(offset<b.size())require(chunk.size()<=b.size()-offset&&std::equal(chunk.begin(),chunk.end(),b.begin()+offset),"migration-conflict");
        else {b.insert(b.end(),chunk.begin(),chunk.end());write(bank_path,b);}
        return obj({{"size",uint64_t(b.size())},{"total",m.at("size")},{"sha256",sha256(b)}});
      })};
    }
    if(op=="migration.import-proof"){
      body.fields({"id","challenge"});body.at("challenge").binary(32);
      return {profile,body,std::make_unique<Action>([this,body]{return proof(body);})};
    }
    if(op=="migration.import-commit"){
      body.fields({"id","targetHash"});body.at("targetHash").binary(32);
      require(keystore::KeyStore::IsUnlocked()&&(r.at("phase").string()=="device-committed"||r.at("phase").string()=="host-committed"||r.at("phase").string()=="complete"),"migration-conflict");
      return {profile,body,std::make_unique<Action>([this,body]{
        const auto id=body.at("id").string();auto now=journal.status();
        if(now.at("phase").string()=="device-committed")journal.advance(id,"host-committed",body.at("targetHash"));
        journal.advance(id,"complete",body.at("targetHash"));return obj({{"migration",journal.status()}});
      })};
    }
    body.fields({"id","privateKey","challenge"});body.at("privateKey").binary(32);body.at("challenge").binary(32);
    require(keys&&keys->ready()&&!keystore::KeyStore::HasKey()&&r.at("phase").string()=="staged","device-import-not-armed");
    complete_bank(r);IdentityKey proposed(body.at("privateKey").binary(32),rng);
    require(proposed.public_key()==r.at("publicKey").binary(33),"wrong-key");
    Review review{op,"","",{{"operation",op},{"requestId",r.at("id").string()},{"objectHash",to_hex(r.at("publicKey").binary(33))},
      {"contentHash",to_hex(r.at("policyHash").binary(32))},{"risk",i18n::T(i18n::Str::kImportWarning)}}};review.requires_pin=true;
    return {profile,body,std::make_unique<Action>(ui,review,[this,r,body]{
      auto bank=complete_bank(r);keys->install(r,bank,body.at("privateKey").binary(32),rng);
      journal.advance(r.at("id").string(),"device-committed");return proof(body);
    }),false};
  }
};
} // namespace rockey::vlp
