// Host GPIO/serial/framebuffer adapters; actual Controller, Buttons,
// HoldConfirm, Endpoint, KeyStore and rendering execute unchanged.
#include "../controller.hpp"
#include "../../font-render-test/framebuffer.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <csignal>
#include <cstdio>
static volatile sig_atomic_t pressRequested=0;
static uint32_t pressedUntil=0;
static bool eof=false;
static int pending=-1;
static void observe_sound(uint16_t frequency){fprintf(stderr,"host-tone:%u\n",frequency);}
static void press_middle(int){pressRequested=1;}
SerialStub Serial;
int SerialStub::available(){
  if(pending>=0)return 1;uint8_t byte;const auto count=::read(0,&byte,1);
  if(count==1){pending=byte;return 1;}if(count==0)eof=true;return 0;
}
int SerialStub::read(){const auto byte=pending;pending=-1;return byte;}
size_t SerialStub::write(const uint8_t* b,size_t size){size_t at=0;while(at<size){const auto n=::write(1,b+at,size-at);vaultlink::require(n>0,"host-write-failed");at+=n;}return at;}
void pinMode(uint8_t,uint8_t){}
int digitalRead(uint8_t pin){return pin==rockey::Board::kPinBtnB&&millis()<pressedUntil?LOW:HIGH;}
int main(){try{
  using rockey::keystore::KeyStore;using rockey::keystore::Status;using vaultlink::require;
  require(rockey::store::Init()&&KeyStore::Init(),"storage-init");
  uint8_t key[32]{};key[31]=1;
  require(KeyStore::SetPinAndWrap("12345678",8,key, rockey::keystore::BsvNetwork::Main)==Status::kOk&&KeyStore::Unlock("12345678",8)==Status::kOk,"host-key-init");
  rockey::Display::Init();rockey::Buttons buttons;buttons.Init({});rockey::vlp::Controller controller(buttons);
  rockey::sound::player=rockey::sound::Player(observe_sound);
  signal(SIGUSR2,press_middle);fcntl(0,F_SETFL,fcntl(0,F_GETFL)|O_NONBLOCK);
  bool wasVisible=false;unsigned long atPair=0;
  while(!eof){
    if(pressRequested){pressRequested=0;pressedUntil=millis()+2400;}
    rockey::sound::Poll(millis());buttons.Poll(millis());buttons.ClearGateIfSatisfied();controller.poll();
    const bool visible=controller.active_ui();
    if(visible&&!wasVisible){atPair=fullScreenRedraws;fprintf(stderr,"host-ui:pair-visible\n");}
    if(!visible&&wasVisible){fprintf(stderr,"host-ui:pair-confirmed:full-redraws=%lu\n",fullScreenRedraws-atPair);require(fullScreenRedraws-atPair==0,"hold-cleared-whole-screen");}
    wasVisible=visible;
    for(int i=0;i<3;++i){const auto button=static_cast<rockey::Btn>(i);const auto event=buttons.NextEvent(button,millis());if(event!=rockey::BtnEvent::kNone)controller.button(button,event);}
    delay(4);usleep(4000);
  }
  require(KeyStore::IsUnlocked(),"pairing-locked-key");return 0;
}catch(const std::exception& e){fprintf(stderr,"failure:%s\n",e.what());return 1;}}
