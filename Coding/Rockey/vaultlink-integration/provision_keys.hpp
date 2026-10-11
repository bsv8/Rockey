#pragma once
#include "store/keystore.h"
#include "crypto/secure.h"
#include "migration_store.hpp"
#include "policy_store.hpp"
namespace rockey::vlp {
/** Device-local PIN setup. No host API receives a PIN; cancellation, expiry and
 * connection destruction wipe it. The only friend access to KeyStore is tied
 * to a staged SAME identity and a validated, durably committed policy bank. */
class ProvisionKeys {
  secure::SecretBytes<ROCKEY_PIN_MAX_DIGITS+1> pin;
  size_t length=0;
  keystore::BsvNetwork network_=keystore::BsvNetwork::Main;
 public:
  void clear(){pin.Clear();length=0;}
  keystore::BsvNetwork network()const{return network_;}
  bool ready()const{return length!=0;}
  size_t digits()const{return length;}
  void arm(const char* p,size_t n,keystore::BsvNetwork network){
    network_=network;
    clear();vaultlink::require(!keystore::KeyStore::HasKey()&&p&&n>=ROCKEY_PIN_MIN_DIGITS&&n<=ROCKEY_PIN_MAX_DIGITS,"migration-conflict");
    for(size_t i=0;i<n;++i)vaultlink::require(p[i]>='0'&&p[i]<='9',"invalid-pin");
    memcpy(pin.data(),p,n);length=n;
  }
  bool authenticate(const char* p,size_t n,uint32_t now){
    using K=keystore::KeyStore;
    if(!ready()||K::HasKey()||K::WaitMsRemaining(now))return false;
    const bool ok=n==length&&secure::ConstEq(pin.data(),p,n);
    if(!ok){K::NoteUnlockFailure(now);clear();return false;}
    if(!K::NoteUnlockSuccess()){clear();return false;}return true;
  }
  void install(const vaultlink::Value& record,const vaultlink::Bytes& bank,const vaultlink::Bytes& secret,vaultlink::Rng rng){
    using namespace vaultlink;using K=keystore::KeyStore;
    require(ready()&&!K::HasKey()&&secret.size()==32&&record.at("direction").string()=="to-hardware"
      &&record.at("phase").string()=="staged"&&sha256(bank)==record.at("policyHash").binary(32),"migration-conflict");
    IdentityKey actual(secret,rng);
    require(actual.public_key()==record.at("publicKey").binary(33),"wrong-key");
    MigrationStore disk;MigrationJournal journal(disk);
    require(encode(journal.status(),1024)==encode(record,1024),"migration-conflict");
    PolicyStore policy;policy.save(bank);
    const auto result=K::WrapAndStore(reinterpret_cast<const char*>(pin.data()),length,secret.data(),network_,true);
    require(result==keystore::Status::kOk,"import-key-store-failed");
    const auto verified=K::Unlock(reinterpret_cast<const char*>(pin.data()),length);
    clear();require(verified==keystore::Status::kOk,"import-key-verification-failed");
  }
};
} // namespace rockey::vlp
