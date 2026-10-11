// Explicit HOST event adapter, not a physical USB/button test. Exercises the
// actual product Runtime, KeyStore, vault_fs, PIN model, SDK encryption and
// migration operations. A public test key and PIN are seeded only in this CLI.
#include "../rockey_vaultlink.hpp"
#include "../provision_runtime.hpp"
#include "../rockey_vaultlink.hpp"
#include "../pin_reauthentication.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <csignal>
#include <cstdlib>
static volatile sig_atomic_t localExportMenu=1;
static volatile sig_atomic_t hostPairApproved=0;
static void arm_host_export_menu(int){localExportMenu=1;}
static void approve_host_pair(int){hostPairApproved=1;}
using namespace vaultlink;
int random_os(void*,unsigned char* b,size_t n){int fd=open("/dev/urandom",O_RDONLY);if(fd<0)return -1;size_t at=0;while(at<n){auto k=read(fd,b+at,n-at);if(k<=0){close(fd);return -1;}at+=k;}return close(fd);}
class Pipe final:public ByteTransport {
  std::chrono::steady_clock::time_point start=std::chrono::steady_clock::now();
 public:bool eof=false;Pipe(){fcntl(0,F_SETFL,fcntl(0,F_GETFL)|O_NONBLOCK);}
  int read_byte()override{uint8_t b;auto n=read(0,&b,1);if(n==1)return b;if(n==0)eof=true;return -1;}
  void write(const Bytes& b)override{size_t at=0;while(at<b.size()){auto n=::write(1,b.data()+at,b.size()-at);require(n>0,"write-failed");at+=n;}}
  uint64_t millis()override{return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();}
};
class HostPinUI final:public rockey::vlp::ApprovalUI {
  rockey::vlp::ProvisionKeys* provision=nullptr;rockey::vlp::PinReauthentication pin;rockey::vlp::Approval answer;
 public:
  explicit HostPinUI(rockey::vlp::ProvisionKeys& keys):provision(&keys){}
  void begin(const rockey::vlp::Review& r)override {
    fprintf(stderr,"host-review:%s:pin=%d\n",r.operation.c_str(),r.requires_pin);answer={rockey::vlp::Approval::Once,0,false};
    if(r.requires_pin){require(provision->ready()?pin.begin_local(provision->digits(),[this](const char* p,size_t n){return provision->authenticate(p,n,0);}):pin.begin(),"pin-unavailable");for(char c:std::string("12345678")){for(char d='0';d<c;++d)pin.next();pin.select();}answer.pin_verified=pin.verified();}
  }
  rockey::vlp::Approval decision()override{return answer;}
  void clear()override{pin.clear();answer={};}
};
int main(int argc,char** argv){try {
  using rockey::keystore::KeyStore;using rockey::keystore::Status;
  require(argc==1||(argc==6&&(std::string(argv[1])=="import-staged"||std::string(argv[1])=="key-wrapped"||std::string(argv[1])=="device-committed")),"invalid-fixture");
  require(rockey::store::Init()&&KeyStore::Init(),"storage-init");
  rockey::vlp::ProvisionKeys keys;keys.arm("12345678",8);Pipe pipe;HostPinUI ui(keys);
  // Explicit host button adapter: tests can withhold device approval and
  // verify the displayed pairing request before approving the browser.
  const bool manualPair=getenv("ROCKEY_HOST_MANUAL_PAIR")!=nullptr;
  signal(SIGUSR2,approve_host_pair);
  const auto pair=[](const std::string& code){fprintf(stderr,"host-pair:%s\n",code.c_str());return true;};
  const auto pairPoll=[manualPair]{return manualPair&&!hostPairApproved?0:1;};
  std::unique_ptr<rockey::vlp::Runtime> wrapped;std::unique_ptr<rockey::vlp::ProvisionRuntime> provision;
  if(argc==6){
    // Named public commit-point fixture, not a simulated physical power cut.
    Bytes secret(32);secret[31]=1;WipeBytes wipe{secret};IdentityKey source(secret,random_os);
    auto bank=encode(obj({{"version",uint64_t(2)},{"key",to_hex(source.public_key())},{"channels",Value::list({})},
      {"sessions",Value::list({})},{"pending",Value::list({})},{"pools",Value::list({})}}),65536);
    require(to_hex(sha256(bank))==argv[5],"invalid-fixture-bank");
    rockey::vlp::MigrationStore disk;MigrationJournal journal(disk);
    auto record=obj({{"version",uint64_t(1)},{"id",argv[2]},{"walletGeneration",argv[3]},{"publicKey",source.public_key()},
      {"sourceHash",from_hex(argv[4])},{"policyHash",sha256(bank)},{"direction","to-hardware"},{"phase","staged"},{"targetHash",Value()}});
    journal.begin(record);auto meta=encode(obj({{"id",argv[2]},{"size",uint64_t(bank.size())}}),128);
    require(rockey::store::WriteRecord("/vault/vlp-import-meta.bin",1,meta.data(),meta.size(),nullptr)
      &&rockey::store::WriteRecord("/vault/vlp-import-stage.bin",1,bank.data(),bank.size(),nullptr),"fixture-write-failed");
    if(std::string(argv[1])!="import-staged"){
      keys.install(record,bank,secret,random_os);
      if(std::string(argv[1])=="device-committed")journal.advance(argv[2],"device-committed");
      // Boot unlock uses the actual stored PIN-encrypted envelope.
      require(KeyStore::Unlock("12345678",8)==Status::kOk,"fixture-unlock-failed");
      static rockey::vlp::PolicyStore policy;
      wrapped=std::make_unique<rockey::vlp::Runtime>(pipe,random_os,1,ui,policy,pair,pairPoll,[]{},[]{return false;},[]{});
    }
  }
  if(!wrapped)provision=std::make_unique<rockey::vlp::ProvisionRuntime>(pipe,random_os,1,ui,keys,pair,pairPoll,[]{});
  while(!pipe.eof){if(wrapped)wrapped->poll();else provision->poll();usleep(1000);}
  return 0;
}catch(const std::exception& e){fprintf(stderr,"failure:%s\n",e.what());return 1;}}
