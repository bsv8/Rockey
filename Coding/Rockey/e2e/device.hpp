#pragma once
#if defined(ROCKEY_DEV_BUTTON_API)
#include "wire.hpp"
#include "../vaultlink-sdk/device/sdk/endpoint.hpp"
#include "board/buttons.h"
#include <Arduino.h>
#include <deque>
namespace rockey::e2e {
// 只有这个对象读物理串口。UI 注入与 VLP 使用两个帧类别，不混入日志。
class DevButtonApi final {
  Reader reader;std::deque<uint8_t> business;
  std::function<vaultlink::Value(const Bytes&)> control;
 public:
  size_t dropped()const{return reader.dropped;}
  void bind(std::function<vaultlink::Value(const Bytes&)> fn){control=std::move(fn);}
  void pump(){
    // 每轮有界，不能被串口洪流饿死 UI、松键计时和协议失活检查。
    for(size_t n=0;n<8192&&Serial.available();++n)reader.feed(uint8_t(Serial.read()),[this](uint8_t kind,uint32_t id,const Bytes& body){
      if(kind==1){if(business.size()+body.size()>16384){business.clear();return;}business.insert(business.end(),body.begin(),body.end());}
      else if(kind==2&&id){
        vaultlink::Value result;
        try{vaultlink::require(bool(control),"test-not-ready");result=control(body);}
        catch(...){result=vaultlink::Value::object({{"error",vaultlink::Value("test-control-failed")}});}
        send(3,id,vaultlink::encode(result));
      }
    });
  }
  int read(){if(business.empty())return -1;int b=business.front();business.pop_front();return b;}
  void send(uint8_t kind,uint32_t id,const Bytes& body){auto bytes=frame(kind,id,body);Serial.write(bytes.data(),bytes.size());}
  void write(const vaultlink::Bytes& b){for(size_t at=0;at<b.size();at+=max_payload)send(1,0,Bytes(b.begin()+at,b.begin()+std::min(at+max_payload,b.size())));}
};
inline DevButtonApi& device(){static DevButtonApi api;return api;}
} // namespace rockey::e2e
#endif
