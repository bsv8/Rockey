#pragma once
// 板级提示音：GPIO25/DAC1（M5 Basic 官方 pinmap）。硬件生成波形，Loop
// 只推进有界时段，不 delay、不占用 USB/按键处理。宿主可注入声音输出观测。
#include <cstdint>
#include "store/vault_fs.h"
#if defined(ARDUINO_ARCH_ESP32)
#include <driver/dac.h>
#endif

namespace rockey::sound {
inline void HardwareTone(uint16_t frequency) {
#if defined(ARDUINO_ARCH_ESP32)
  if (!frequency) { dac_cw_generator_disable(); dac_output_voltage(DAC_CHANNEL_1,0); return; }
  dac_cw_config_t config{};
  config.en_ch=DAC_CHANNEL_1; config.scale=DAC_CW_SCALE_8;
  config.phase=DAC_CW_PHASE_0; config.freq=frequency; config.offset=0;
  dac_output_enable(DAC_CHANNEL_1);
  dac_cw_generator_config(&config); dac_cw_generator_enable();
#else
  (void)frequency; // 宿主没有扬声器，不能据此宣称实机声响验收通过。
#endif
}
class Player {
  void (*output_)(uint16_t);
  uint32_t automatic_=0,manual_=0,deadline_=0;
  uint8_t stage_=0;
  bool manualTone_=false;
 public:
  explicit Player(void (*output)(uint16_t)=HardwareTone):output_(output){}
  void stop(){automatic_=manual_=0;stage_=0;output_(0);}
  void cancel(bool manual){
    (manual?manual_:automatic_)=0;
    if(stage_&&manualTone_==manual){stage_=0;output_(0);}
  }
  void request(bool manual,uint32_t now){auto& count=manual?manual_:automatic_;if(count!=UINT32_MAX)++count;poll(now);}
  void poll(uint32_t now){
    if(stage_&&int32_t(now-deadline_)<0)return;
    if(stage_==1){output_(0);stage_=manualTone_?2:4;deadline_=now+80;return;}
    else if(stage_==2){output_(2300);stage_=3;deadline_=now+100;return;}
    else if(stage_==3){output_(0);stage_=4;deadline_=now+80;return;}
    else if(stage_==4)stage_=0;
    if(!stage_&&(manual_||automatic_)){
      manualTone_=manual_!=0;if(manualTone_)--manual_;else --automatic_;
      output_(manualTone_?1700:2600);stage_=1;deadline_=now+(manualTone_?100:65);
    }
  }
};
inline Player player;
inline bool loaded=false;
inline uint8_t enabledMask=3;
inline constexpr const char* path="/vault/sound.bin";
inline bool Enabled(bool manual){
  if(!loaded&&store::Available()){
    uint8_t value=3;size_t length=0;
    if(store::ReadRecord(path,&value,1,&length,nullptr)&&length==1&&value<=3)enabledMask=value;
    loaded=true; // 缺少或损坏的非安全偏好默认开启，不影响任何授权策略。
  }
  return (enabledMask&(manual?2:1))!=0;
}
inline bool SetEnabled(bool manual,bool value){
  Enabled(manual);
  const uint8_t bit=manual?2:1;
  const uint8_t bytes=value?(enabledMask|bit):(enabledMask&~bit);
  if(!store::WriteRecord(path,1,&bytes,1,nullptr))return false;
  loaded=true;enabledMask=bytes;if(!value)player.cancel(manual);return true;
}
inline void Notify(bool manual,uint32_t now){if(Enabled(manual))player.request(manual,now);}
inline void Poll(uint32_t now){player.poll(now);}
} // namespace rockey::sound
