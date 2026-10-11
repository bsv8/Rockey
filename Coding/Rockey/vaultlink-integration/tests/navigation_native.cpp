// No business or signing replacements: only the host framebuffer/GPIO surface
// and storage environment. Exercise the actual App navigation and KeyStore.
#include "../controller.hpp"
#include "core/app.h"
#include "../../font-render-test/framebuffer.hpp"
#include <vector>
SerialStub Serial;EspClass ESP;
static std::vector<uint16_t> soundOutput;
static void observeSound(uint16_t frequency){soundOutput.push_back(frequency);}
void pinMode(uint8_t,uint8_t){}int digitalRead(uint8_t){return HIGH;}
void SerialStub::begin(unsigned long){}size_t SerialStub::setRxBufferSize(size_t n){return n;}
bool SerialStub::setRxFIFOFull(uint8_t){return true;}
int SerialStub::available(){return 0;}int SerialStub::read(){return -1;}
int SerialStub::readBytes(uint8_t*,size_t){return 0;}
size_t SerialStub::write(const uint8_t*,size_t n){return n;}
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
    require(KeyStore::SetPinAndWrap("12345678",8,key)==keystore::Status::kOk&&KeyStore::Unlock("12345678",8)==keystore::Status::kOk,"key-init");
    App app;app.buttons_.Init({});app.vaultlink_=std::make_unique<vlp::Controller>(app.buttons_);
    Display::Init();app.Go(App::Screen::kMenu);app.DrawMenu();
    require(app.menu_.count==10,"menu-count");
    sound::player=sound::Player(observeSound);
    require(sound::Enabled(false)&&sound::Enabled(true),"sound-not-default-on");
    app.menuSelected_=8;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(!sound::Enabled(false)&&sound::Enabled(true)&&KeyStore::IsUnlocked(),"auto-sound-toggle-changed-manual-or-key");
    sound::loaded=false;
    require(!sound::Enabled(false)&&sound::Enabled(true),"sound-preference-not-persisted");
    app.menuSelected_=9;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(!sound::Enabled(false)&&!sound::Enabled(true)&&KeyStore::IsUnlocked(),"manual-sound-toggle-changed-key");
    require(soundOutput.empty(),"disable-played-a-tone");
    app.menuSelected_=8;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(soundOutput==std::vector<uint16_t>{2600},"enable-auto-did-not-preview-single");
    app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require((soundOutput==std::vector<uint16_t>{2600,0}),"disable-auto-played-a-tone");
    soundOutput.clear();app.menuSelected_=9;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(soundOutput==std::vector<uint16_t>{1700},"enable-manual-did-not-preview");
    const auto previewTime=millis();sound::Poll(previewTime+100);sound::Poll(previewTime+180);
    require((soundOutput==std::vector<uint16_t>{1700,0,2300}),"enable-manual-did-not-preview-double");
    app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require((soundOutput==std::vector<uint16_t>{1700,0,2300,0}),"disable-manual-played-a-tone");
    app.menuSelected_=0;app.OnButton(Btn::kB,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kError&&KeyStore::IsUnlocked(),"empty-request-changed-key");
    app.OnButton(Btn::kC,BtnEvent::kShortPress);
    require(app.screen_==App::Screen::kMenu&&KeyStore::IsUnlocked(),"empty-request-back-locked");
    for(auto screen:{App::Screen::kInfo,App::Screen::kPubkey,App::Screen::kMigrate,App::Screen::kBackup}){
      app.Go(screen);app.OnButton(Btn::kA,BtnEvent::kShortPress);
      require(KeyStore::IsUnlocked()&&app.screen_==screen,"left-button-locked");
      app.OnButton(Btn::kB,BtnEvent::kShortPress);
      require(KeyStore::IsUnlocked()&&app.screen_==App::Screen::kMenu,"page-back-locked");
    }
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
    puts("App navigation: empty-request back, left buttons, page back and lock-free menu passed.");
  }
};
}
int main(){try{rockey::NavigationProbe::check();return 0;}catch(const std::exception& e){fprintf(stderr,"Navigation failed: %s\n",e.what());return 1;}}
