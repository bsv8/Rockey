#pragma once
#include "../vaultlink-sdk/device/sdk/cbor.hpp"
namespace rockey::vlp {
inline std::vector<std::string> display_chunks(const std::string &text,size_t width=26){
  vaultlink::require(width>=4&&vaultlink::utf8_valid(text),"invalid-display-text");
  std::vector<std::string> lines;
  for(size_t at=0;at<text.size();){
    size_t end=std::min(text.size(),at+width);
    while(end<text.size()&&(static_cast<unsigned char>(text[end])&0xc0)==0x80)--end;
    lines.push_back(text.substr(at,end-at));at=end;
  }
  return lines;
}
} // namespace rockey::vlp
