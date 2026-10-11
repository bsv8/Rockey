// Explicit HOST event adapter, not a physical USB/button test. Exercises the
// actual product Runtime, KeyStore, vault_fs, PIN model, SDK encryption and
// migration operations. A public test key and PIN are seeded only in this CLI.
#include "../rockey_vaultlink.hpp"
#include "../erased_migration.hpp"
#include "../pin_reauthentication.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <csignal>
static volatile sig_atomic_t localExportMenu=1;
static void arm_host_export_menu(int){localExportMenu=1;}
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
  rockey::vlp::PinReauthentication pin;rockey::vlp::Approval answer;
 public:
  void begin(const rockey::vlp::Review& r)override {
    fprintf(stderr,"host-review:%s:pin=%d\n",r.operation.c_str(),r.requires_pin);answer={rockey::vlp::Approval::Once,0,false};
    if(r.requires_pin){require(pin.begin(),"pin-unavailable");for(char c:std::string("12345678")){for(char d='0';d<c;++d)pin.next();pin.select();}answer.pin_verified=pin.verified();}
  }
  rockey::vlp::Approval decision()override{return answer;}
  void clear()override{pin.clear();answer={};}
};
int main(int argc,char** argv){try {
  using rockey::keystore::KeyStore;using rockey::keystore::Status;
  require(rockey::store::Init()&&KeyStore::Init(),"storage-init");Bytes secret(32);secret[31]=1;
  require(KeyStore::SetPinAndWrap("12345678",8,secret.data(), rockey::keystore::BsvNetwork::Main)==Status::kOk&&KeyStore::Unlock("12345678",8)==Status::kOk,"key-init");wipe_bytes(secret);
  Pipe pipe;HostPinUI ui;rockey::vlp::PolicyStore policy;
  auto initialized=KeyStore::Info_();
  policy.save(encode(obj({{"version",uint64_t(2)},{"key",to_hex(Bytes(initialized.pubkey,initialized.pubkey+33))},
    {"channels",Value::list({})},{"sessions",Value::list({})},{"pending",Value::list({})},{"pools",Value::list({})}}),65536));
  // Local export-menu event belongs to this explicitly named HOST adapter.
  std::signal(SIGUSR1,arm_host_export_menu);
  rockey::vlp::Runtime runtime(pipe,random_os,1,ui,policy,[](const std::string&){return true;},[]{return 1;},[]{},[]{return localExportMenu!=0;},[]{localExportMenu=0;});
  std::unique_ptr<rockey::vlp::ErasedMigrationRuntime> erased;
  if(argc>1){
    require(argc==7&&(std::string(argv[1])=="erasing"||std::string(argv[1])=="erased"),"invalid-fixture");
    // Explicit commit-point fixture. Uses actual KeyStore erase/record storage;
    // it is not evidence that earlier browser/physical interactions took place.
    rockey::vlp::MigrationStore disk;MigrationJournal journal(disk);
    auto info=KeyStore::Info_();
    auto record=obj({{"version",uint64_t(1)},{"id",argv[2]},{"walletGeneration",argv[3]},
      {"publicKey",Bytes(info.pubkey,info.pubkey+33)},
      {"sourceHash",from_hex(argv[4])},{"policyHash",from_hex(argv[5])},{"direction","to-software"},{"phase","staged"},{"targetHash",Value()}});
    require(sha256(policy.load())==record.at("policyHash").binary(32),"invalid-fixture-bank");
    journal.begin(record);journal.advance(argv[2],"device-committed");journal.advance(argv[2],"host-committed",from_hex(argv[6]));
    journal.advance(argv[2],"erasing",from_hex(argv[6]));require(KeyStore::Erase(true),"fixture-erase-failed");
    if(std::string(argv[1])=="erased")journal.advance(argv[2],"erased",from_hex(argv[6]));
    runtime.lock();erased=std::make_unique<rockey::vlp::ErasedMigrationRuntime>(pipe,random_os,2,ui,[](const std::string&){return true;},[]{return 1;},[]{});
  }
  while(!pipe.eof){if(erased)erased->poll();else if(KeyStore::IsUnlocked())runtime.poll();else pipe.read_byte();usleep(1000);}
  runtime.lock();return 0;
}catch(const std::exception& e){fprintf(stderr,"failure:%s\n",e.what());return 1;}}
