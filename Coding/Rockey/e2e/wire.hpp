#pragma once
// 测试固件的外层复用帧，不是 VLP 标准扩展。内层 VLP 字节完全不变。
// RKET | kind:u8 | id:u32le | size:u16le | payload | crc32(header+payload)
#include <array>
#include <cstdint>
#include <functional>
#include <vector>
#include <stdexcept>
namespace rockey::e2e {
using Bytes=std::vector<uint8_t>;
constexpr size_t max_payload=4096, header_size=11;
inline uint32_t crc(const uint8_t* p,size_t n){uint32_t c=0xffffffff;while(n--){c^=*p++;for(int j=0;j<8;++j)c=(c>>1)^((c&1)?0xedb88320:0);}return c^0xffffffff;}
inline uint32_t u32(const uint8_t* p){return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
inline void put32(Bytes& b,uint32_t v){for(int i=0;i<4;++i)b.push_back(uint8_t(v>>(i*8)));}
inline Bytes frame(uint8_t kind,uint32_t id,const Bytes& body){
  if(kind<1||kind>3||body.size()>max_payload)throw std::runtime_error("invalid-test-frame");
  Bytes b={'R','K','E','T',kind};put32(b,id);b.push_back(uint8_t(body.size()));b.push_back(uint8_t(body.size()>>8));
  b.insert(b.end(),body.begin(),body.end());put32(b,crc(b.data(),b.size()));return b;
}
class Reader {
  std::array<uint8_t,max_payload+15> buf{};size_t used=0;
  void shift(size_t n){for(size_t i=n;i<used;++i)buf[i-n]=buf[i];used-=n;}
 public:
  size_t dropped=0;
  void feed(uint8_t x,const std::function<void(uint8_t,uint32_t,const Bytes&)>& receive){
    if(used==buf.size())shift(1);buf[used++]=x;
    while(used>=4){
      if(buf[0]!='R'||buf[1]!='K'||buf[2]!='E'||buf[3]!='T'){shift(1);continue;}
      if(used<header_size)return;
      const size_t len=size_t(buf[9])|size_t(buf[10])<<8;
      if(len>max_payload||buf[4]<1||buf[4]>3){++dropped;shift(1);continue;}
      if(used<len+15)return;
      if(u32(buf.data()+header_size+len)!=crc(buf.data(),header_size+len)){++dropped;shift(1);continue;}
      const auto kind=buf[4];const auto id=u32(buf.data()+5);
      Bytes body(buf.begin()+header_size,buf.begin()+header_size+len);shift(len+15);receive(kind,id,body);
    }
  }
};
} // namespace rockey::e2e
