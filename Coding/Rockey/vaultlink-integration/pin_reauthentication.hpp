#pragma once
#include "store/keystore.h"
#include "crypto/secure.h"
#include <functional>
namespace rockey::vlp {
/** Device-only three-button PIN entry. The caller can display the selected
 * digit and number of entered digits, but cannot read the entered PIN back.
 * Authentication runs the real persistent KeyStore failure/wait gate. */
class PinReauthentication {
 public:
  enum Result { Pending, Verified, Failed };
 private:
  secure::SecretBytes<ROCKEY_PIN_MAX_DIGITS+1> pin;
  size_t length=0,digits=0;
  uint8_t selected=0;
  bool active=false;
  Result result_=Pending;
  std::function<bool(const char*,size_t)> authenticate;
 public:
  bool begin() {
    clear();const auto info=keystore::KeyStore::Info_();
    if(!keystore::KeyStore::IsUnlocked()||!info.initialized||info.pinDigits<ROCKEY_PIN_MIN_DIGITS
      ||info.pinDigits>ROCKEY_PIN_MAX_DIGITS)return false;
    return begin_local(info.pinDigits,[](const char* p,size_t n){return keystore::KeyStore::Unlock(p,n)==keystore::Status::kOk;});
  }
  bool begin_local(size_t count,std::function<bool(const char*,size_t)> verify){
    clear();if(count<ROCKEY_PIN_MIN_DIGITS||count>ROCKEY_PIN_MAX_DIGITS||!verify)return false;
    digits=count;authenticate=std::move(verify);active=true;return true;
  }
  void clear(){authenticate={};pin.Clear();length=digits=0;selected=0;active=false;result_=Pending;}
  size_t entered()const{return length;}
  size_t required()const{return digits;}
  uint8_t digit()const{return selected;}
  bool verified()const{return result_==Verified;}
  void previous(){if(active)selected=uint8_t((selected+9)%10);}
  void next(){if(active)selected=uint8_t((selected+1)%10);}
  void back(){if(active&&length)pin.data()[--length]=0;}
  Result select() {
    if(!active)return result_;
    pin.data()[length++]=uint8_t('0'+selected);selected=0;
    if(length<digits)return Pending;
    const bool ok=authenticate&&authenticate(reinterpret_cast<const char*>(pin.data()),length);
    pin.Clear();length=0;active=false;
    authenticate={};result_=ok?Verified:Failed;return result_;
  }
};
} // namespace rockey::vlp
