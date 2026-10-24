// No business or signing replacements: only the host framebuffer/GPIO surface
// and storage environment. Exercise the actual App navigation and KeyStore.
#include "../controller.hpp"
#include "core/app.h"
#include "../../font-render-test/framebuffer.hpp"
#include <vector>
SerialStub Serial;EspClass ESP;
static std::vector<uint16_t> soundOutput;
static vaultlink::Bytes serialInput,serialOutput;
static size_t serialPosition=0;
static bool middleDown=false;
static void observeSound(uint16_t frequency){soundOutput.push_back(frequency);}
void pinMode(uint8_t,uint8_t){}int digitalRead(uint8_t pin){return middleDown&&pin==rockey::Board::kPinBtnB?LOW:HIGH;}
void SerialStub::begin(unsigned long){}size_t SerialStub::setRxBufferSize(size_t n){return n;}
bool SerialStub::setRxFIFOFull(uint8_t){return true;}
int SerialStub::available(){return serialPosition<serialInput.size();}int SerialStub::read(){return available()?serialInput[serialPosition++]:-1;}
int SerialStub::readBytes(uint8_t*,size_t){return 0;}
size_t SerialStub::write(const uint8_t* bytes,size_t n){serialOutput.insert(serialOutput.end(),bytes,bytes+n);return n;}
size_t SerialStub::println(const char*){return 0;}
uint32_t EspClass::getFreeHeap(){return 100000;}void EspClass::restart(){}
namespace rockey::secp {
bool VerifyDer(const uint8_t* pub,const uint8_t* hash,const uint8_t* der,size_t size){
  if(!pub||!hash||!der||!size)return false;
  try{vaultlink::channel_verify(vaultlink::Bytes(pub,pub+33),vaultlink::Bytes(hash,hash+32),vaultlink::Bytes(der,der+size));return true;}catch(...){return false;}
}
}
namespace rockey {
struct NavigationProbe {
  static void check(){
    using vaultlink::require;using keystore::KeyStore;
    require(store::Init()&&KeyStore::Init(),"storage-init");uint8_t key[32]{};key[31]=1;
    require(KeyStore::SetPinAndWrap("12345678",8,key, rockey::keystore::BsvNetwork::Main)==keystore::Status::kOk&&KeyStore::Unlock("12345678",8)==keystore::Status::kOk,"key-init");
    App app;app.buttons_.Init({});app.vaultlink_=std::make_unique<vlp::Controller>(app.buttons_);
    Display::Init();app.Go(App::Screen::kMenu);app.DrawMenu();
    require(app.menu_.count==9,"menu-count");
    // Actual encrypted pairing and possession proof across App::Loop(), with
    // host serial/GPIO adapters. Count menu fills through the whole handshake.
    auto frame=[](uint8_t type,uint32_t sequence,const vaultlink::Bytes& payload){
      vaultlink::Bytes bytes{0xa5,0x5a,2,type,0};auto seq=vaultlink::le32(sequence);
      bytes.insert(bytes.end(),seq.begin(),seq.end());bytes.push_back(payload.size()&255);bytes.push_back(payload.size()>>8);
      bytes.insert(bytes.end(),payload.begin(),payload.end());auto crc=vaultlink::le32(vaultlink::crc32(bytes.data()+2,bytes.size()-2));
      bytes.insert(bytes.end(),crc.begin(),crc.end());serialInput=bytes;serialPosition=0;
    };
    auto rng=+[](void*,unsigned char* bytes,size_t n){rand::Fill(bytes,n);return 0;};
    vaultlink::X25519 host(rng);
    const auto hello=vaultlink::obj({{"hostEph",host.public_key()},{"hostNonce",vaultlink::Bytes(32,1)},
      {"protocolVersion",uint64_t(2)},{"capabilities",vaultlink::Value::list({})},
      {"walletGeneration",uint64_t(1)},{"backendGeneration",uint64_t(1)},{"hostRunGeneration",uint64_t(1)}});
    frame(1,0,vaultlink::encode(hello));app.Loop();
    vaultlink::FrameReader reader;vaultlink::Frame ackFrame;bool gotAck=false;
    for(auto byte:serialOutput)if(reader.feed(byte,ackFrame))gotAck=true;
    require(gotAck&&ackFrame.type==2,"pairing-hello-ack-missing");
    const auto ack=vaultlink::decode(vaultlink::Bytes(ackFrame.payload.begin(),ackFrame.payload.begin()+ackFrame.size));
    static constexpr char handshakeLabel[]="vlp:handshake:v2\0";
    const auto digest=vaultlink::sha256(vaultlink::join({vaultlink::text_bytes(handshakeLabel,sizeof(handshakeLabel)-1),
      vaultlink::encode(vaultlink::obj({{"hello",hello},{"ack",ack}}),2048)}));
    const auto shared=host.shared(ack.at("deviceEph").binary(32));
    vaultlink::Record send(vaultlink::hkdf(shared,digest,"vlp:link:c2s:key:v2",32),
      vaultlink::hkdf(shared,digest,"vlp:link:c2s:nonce:v2",12),ack.at("deviceRunId").integer(),ack.at("connectionId").integer());
    static constexpr char pairingLabel[]="vlp:link:pairing:v2";
    const auto hash=vaultlink::sha256(vaultlink::join({vaultlink::text_bytes(pairingLabel,sizeof(pairingLabel)-1),digest}));
    auto code=std::to_string(((uint32_t(hash[0])<<16)|(uint32_t(hash[1])<<8)|hash[2])%1000000);code.insert(0,6-code.size(),'0');
    auto payload=send.seal(3,vaultlink::encode(vaultlink::obj({{"code",code}})));frame(3,send.sequence(),payload);app.Loop();
    auto& pairController=*app.vaultlink_;
    require(pairController.active_ui()&&!pairController.connected(),"pairing-page-not-open");
    const auto pairFills=fullScreenFills,pairClears=fullScreenRedraws;
    for(int tick=0;tick<8;++tick){delay(25);app.Loop();}
    middleDown=true;
    for(int tick=0;tick<100;++tick){delay(25);app.Loop();}
    require(pairController.pair_answer==1&&pairController.active_ui()&&!pairController.connected(),"pairing-closed-before-proof");
    require(fullScreenFills==pairFills&&fullScreenRedraws==pairClears,"pairing-confirmation-flashed-screen");
    middleDown=false;
    for(int tick=0;tick<8;++tick){delay(25);app.Loop();}
    require(pairController.pair_answer==1,"pairing-release-changed-decision");
    payload=send.seal(5,vaultlink::encode(vaultlink::obj({{"challenge",vaultlink::Bytes(32,2)}})));frame(5,send.sequence(),payload);app.Loop();
    require(pairController.connected()&&!pairController.active_ui()&&KeyStore::IsUnlocked(),"pairing-proof-did-not-connect");
    require(fullScreenFills==pairFills+1&&fullScreenRedraws==pairClears,"pairing-return-drew-menu-more-than-once");
    for(int tick=0;tick<8;++tick){delay(25);app.Loop();}
    require(fullScreenFills==pairFills+1,"pairing-idle-redrew-menu");
    serialInput.clear();serialOutput.clear();serialPosition=0;
    app.vaultlink_.reset();
    require(KeyStore::Unlock("12345678",8)==keystore::Status::kOk,"pairing-regression-cleanup-unlock");
    app.vaultlink_=std::make_unique<vlp::Controller>(app.buttons_);
    soundOutput.clear();
    sound::player=sound::Player(observeSound);
    require(sound::Enabled(false)&&sound::Enabled(true),"sound-not-default-on");
    app.menuSelected_=6;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(!sound::Enabled(false)&&sound::Enabled(true)&&KeyStore::IsUnlocked(),"auto-sound-toggle-changed-manual-or-key");
    sound::loaded=false;
    require(!sound::Enabled(false)&&sound::Enabled(true),"sound-preference-not-persisted");
    app.menuSelected_=7;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(!sound::Enabled(false)&&!sound::Enabled(true)&&KeyStore::IsUnlocked(),"manual-sound-toggle-changed-key");
    require(soundOutput.empty(),"disable-played-a-tone");
    app.menuSelected_=6;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(soundOutput==std::vector<uint16_t>{2600},"enable-auto-did-not-preview-single");
    app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require((soundOutput==std::vector<uint16_t>{2600,0}),"disable-auto-played-a-tone");
    soundOutput.clear();app.menuSelected_=7;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(soundOutput==std::vector<uint16_t>{1700},"enable-manual-did-not-preview");
    const auto previewTime=millis();sound::Poll(previewTime+100);sound::Poll(previewTime+180);
    require((soundOutput==std::vector<uint16_t>{1700,0,2300}),"enable-manual-did-not-preview-double");
    app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require((soundOutput==std::vector<uint16_t>{1700,0,2300,0}),"disable-manual-played-a-tone");
    // 真实本机二级菜单修改持久策略，USB 没有对应的修改能力。
    {vlp::PolicyStore files;vaultlink::Policy policy(files,vaultlink::to_hex(vaultlink::Bytes(KeyStore::PublicKey(),KeyStore::PublicKey()+33)),vaultlink::sha256,"main");
      policy.register_signing(vaultlink::Value::list({vaultlink::obj({{"id","identity.noise-proof"},{"owner","window-p2p"},{"kind","plugin"},{"operation","identity.noise-proof"},{"mode","automatic"},{"revision",vaultlink::Value(uint64_t(1))}})}),true);
      policy.configure(vaultlink::Channel{"checkout","p2pkh",100,0,1,true,"plugin","p2pkh"},true);
    }
    app.vaultlink_->poll();app.menuSelected_=8;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kChannels&&KeyStore::IsUnlocked(),"channel-menu-locked");
    app.OnButton(Btn::kB,BtnEvent::kShortPress);app.OnButton(Btn::kB,BtnEvent::kShortPress);
    app.OnButton(Btn::kC,BtnEvent::kShortPress);app.OnButton(Btn::kB,BtnEvent::kLongPress);app.OnButton(Btn::kB,BtnEvent::kHoldRepeat);app.OnButton(Btn::kB,BtnEvent::kRelease);
    // Known operations stay automatic; a physical menu cannot turn this
    // fixed policy into a manual channel or increment its revision.
    {vlp::PolicyStore files;auto bank=vaultlink::decode(files.load(),65536);require(bank.at("signing").array[0].at("mode").string()=="automatic"&&bank.at("signing").array[0].at("revision").integer()==1,"known-operation-mode-changed");}
    // Leave the read-only operation detail, select the payment channel and
    // edit its single-payment limit through the real button state machine.
    app.OnButton(Btn::kA,BtnEvent::kLongPress);app.OnButton(Btn::kA,BtnEvent::kHoldRepeat);app.OnButton(Btn::kA,BtnEvent::kRelease);
    app.OnButton(Btn::kC,BtnEvent::kShortPress);app.OnButton(Btn::kB,BtnEvent::kShortPress);
    app.OnButton(Btn::kC,BtnEvent::kShortPress);app.OnButton(Btn::kB,BtnEvent::kShortPress);
    app.OnButton(Btn::kC,BtnEvent::kShortPress);app.OnButton(Btn::kB,BtnEvent::kLongPress);app.OnButton(Btn::kB,BtnEvent::kHoldRepeat);app.OnButton(Btn::kB,BtnEvent::kRelease);
    {vlp::PolicyStore files;auto bank=vaultlink::decode(files.load(),65536);require(bank.at("channels").array[0].at("singleLimit").integer()==101,"channel-amount-not-persisted");}
    app.OnButton(Btn::kA,BtnEvent::kLongPress);require(app.screen_==App::Screen::kMenu&&KeyStore::IsUnlocked(),"channel-back-locked");
    app.menuSelected_=0;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kError&&KeyStore::IsUnlocked(),"empty-request-changed-key");
    app.OnButton(Btn::kC,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kMenu&&KeyStore::IsUnlocked(),"empty-request-back-locked");
    for(auto screen:{App::Screen::kInfo,App::Screen::kPubkey}){
      app.Go(screen);app.OnButton(Btn::kA,BtnEvent::kShortPress);
      require(KeyStore::IsUnlocked()&&app.screen_==screen,"left-button-locked");
      app.OnButton(Btn::kB,BtnEvent::kShortPress);
      require(KeyStore::IsUnlocked()&&app.screen_==App::Screen::kMenu,"page-back-locked");
    }
    app.menuSelected_=4;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kErase&&KeyStore::HasKey()&&KeyStore::IsUnlocked(),"erase-menu-only-opens-confirmation");
    app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kMenu&&KeyStore::HasKey(),"erase-menu-cancel-preserves-key");
    // The vacated lock slot must now open device info, never erase or lock.
    app.menuSelected_=2;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kInfo&&KeyStore::IsUnlocked(),"shifted-menu-action");
    for(auto screen:{App::Screen::kLock,App::Screen::kSetPin,App::Screen::kSetPinConfirm}){
      app.ResetPinEntry();app.Go(screen);app.Draw();
      for(auto button:{Btn::kC,Btn::kA}){
        const auto before=colors;const auto clears=fullScreenFills;
        const auto digit=app.pinDigit_;
        app.OnButton(button,BtnEvent::kShortPress);app.Draw();
        require(app.pinDigit_==(digit+(button==Btn::kC?1:9))%10,"pin-cursor-not-updated");
        require(fullScreenFills==clears,"pin-cursor-cleared-screen");
        bool changed=false;
        const int y=Board::kContentY+14,height=FontLineHeight(FontRole::kSmall);
        for(int row=0;row<240;++row)for(int col=0;col<320;++col){
          if(colors[row*320+col]==before[row*320+col])continue;
          changed=true;
          require(col>=16&&col<47&&row>=y&&row<y+height,"pin-cursor-redrew-outside-cell");
        }
        require(changed,"pin-cursor-pixels-unchanged");
      }
      app.OnButton(Btn::kB,BtnEvent::kLongPress);app.Draw();
      require(!app.pinRowDrawn_,"pin-menu-kept-row-cache");
    }
    KeyStore::Lock();app.ResetPinEntry();app.Go(App::Screen::kLock);
    memcpy(app.pin_,"1234567",8);app.pinLen_=7;app.pinDigit_=8;app.Draw();
    const auto lastDigitFrame=colors;
    ui::DrawFooter(i18n::T(i18n::Str::kBtnLess),i18n::T(i18n::Str::kLockUnlock),i18n::T(i18n::Str::kBtnMore2));
    require(colors==lastDigitFrame,"last-digit-footer-not-unlock");
    bool clearBeforeUnlock=false;
    onFullScreenClear=+[]{vaultlink::require(!KeyStore::IsUnlocked(),"busy-screen-drawn-after-unlock");};
    const auto clearsBeforeUnlock=fullScreenRedraws;
    app.OnButton(Btn::kB,BtnEvent::kShortPress);
    clearBeforeUnlock=fullScreenRedraws==clearsBeforeUnlock+1;
    onFullScreenClear=nullptr;
    require(clearBeforeUnlock&&KeyStore::IsUnlocked()&&app.screen_==App::Screen::kMenu,"final-digit-did-not-unlock");
    bool busyText=false;
    for(int row=0;row<240;++row)for(int col=0;col<320;++col){
      if(!colors[row*320+col])continue;
      busyText=true;require(row>=100&&row<=140,"busy-screen-kept-pin-ui");
    }
    require(busyText,"busy-screen-text-missing");app.Draw();
    app.vaultlink_.reset();KeyStore::Lock();
    // Persist an actual interrupted import, then recreate the controller as
    // on reboot. Idle polling must not start the erased-export EC runtime.
    const auto original=KeyStore::Info_();
    require(KeyStore::Erase(),"cleanup-before-import-regression");
    vlp::MigrationStore migrationFiles;vaultlink::MigrationJournal journal(migrationFiles);
    journal.begin(vaultlink::obj({{"version",uint64_t(1)},
      {"id","11111111-1111-4111-8111-111111111111"},
      {"walletGeneration","22222222-2222-4222-8222-222222222222"},
      {"publicKey",vaultlink::Bytes(original.pubkey,original.pubkey+33)},
      {"sourceHash",vaultlink::Bytes(32,1)},{"policyHash",vaultlink::Bytes(32,2)},
      {"direction","to-hardware"},{"phase","staged"},{"targetHash",vaultlink::Value()}}));
    for(int boot=0;boot<2;++boot){
      vlp::Controller recovered(app.buttons_);
      for(int tick=0;tick<100;++tick)recovered.poll();
      require(recovered.recovery_start_attempts==0,"staged-import-started-erased-runtime");
      require(journal.status().at("phase").string()=="staged"&&!KeyStore::HasKey(),"idle-poll-mutated-import");
      recovered.arm_import("12345678",8,keystore::BsvNetwork::Main);
      recovered.poll();
      require(bool(recovered.provision_runtime),"staged-import-cannot-resume");
      recovered.lock();
    }
    require(store::Remove("/vault/vlp-migration.bin"),"remove-regression-journal");
    app.vaultlink_=std::make_unique<vlp::Controller>(app.buttons_);
    app.Go(App::Screen::kInitializeChoice);app.vaultlink_->prepare_empty();
    app.vaultlink_->poll();
    require(!KeyStore::HasKey()&&!app.vaultlink_->provision_keys.has_pin(),"empty-home-created-key-or-pin");
    // Browser connection is a status, never a creation permission gate.
    app.vaultlink_->connected_=true;
    app.OnButton(Btn::kA,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kSetPin&&!KeyStore::HasKey(),"connected-empty-home-blocked-create");
    memcpy(app.newPin_,"12345678",9);app.newPinLen_=8;
    memcpy(app.pin_,"1234567",8);app.pinLen_=7;app.pinDigit_=8;app.Go(App::Screen::kSetPinConfirm);
    app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kNetworkChoice&&!KeyStore::HasKey(),"new-pin-persisted-before-final-choice");
    app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kNetworkChoice&&!KeyStore::HasKey(),"middle-button-created-key");
    app.OnButton(Btn::kC,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kMenu&&KeyStore::IsUnlocked()&&KeyStore::Info_().bsvNetwork==keystore::BsvNetwork::Test,"test-button-did-not-save-test-key");
    require(KeyStore::Erase(),"remove-native-test-key");
    memcpy(app.newPin_,"12345678",9);app.newPinLen_=8;app.Go(App::Screen::kNetworkChoice);
    app.OnButton(Btn::kA,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kMenu&&KeyStore::IsUnlocked()&&KeyStore::Info_().bsvNetwork==keystore::BsvNetwork::Main,"main-button-did-not-save-main-key");
    require(KeyStore::Erase(),"remove-native-created-key");
    app.Go(App::Screen::kInitializeChoice);
    auto& controller=*app.vaultlink_;controller.prepare_empty();
    vlp::Review importReview;importReview.operation="migration.import-key";importReview.requires_pin=true;importReview.creates_pin=true;
    controller.begin(importReview);controller.draw();
    const auto pinFills=fullScreenFills;
    controller.button(Btn::kC,BtnEvent::kShortPress);controller.draw();
    require(fullScreenFills==pinFills,"import-pin-digit-flashed-screen");
    controller.pin.previous();
    for(int phase=0;phase<2;++phase){
      for(char digit:std::string("12345678")){
        for(char n='0';n<digit;++n)controller.button(Btn::kC,BtnEvent::kShortPress);
        controller.button(Btn::kB,BtnEvent::kShortPress);
      }
      if(!phase)require(controller.entering_pin&&controller.confirming_new_pin&&!controller.provision_keys.has_pin(),"pin-not-repeated-before-save");
    }
    require(controller.answer.state==vlp::Approval::Once&&controller.answer.pin_verified&&controller.provision_keys.has_pin()&&!KeyStore::HasKey(),"import-pin-setup-not-local-or-prematurely-written");
    controller.lock();
    puts("App navigation: empty-request back, left buttons, page back and lock-free menu passed.");
  }
};
}
int main(){try{rockey::NavigationProbe::check();return 0;}catch(const std::exception& e){fprintf(stderr,"Navigation failed: %s\n",e.what());return 1;}}
