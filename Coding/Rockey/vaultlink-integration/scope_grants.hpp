#pragma once
#include "../vaultlink-sdk/device/sdk/cbor.hpp"
namespace rockey::vlp {
// 只在当前已证明持有权的 USB 连接内使用；不同操作/范围绝不共享许可。
// 容量与三按钮菜单一致，不自动淘汰用户的持续否决。
class ScopeGrants {
 public:
  enum Decision { Ask, Allow, Deny };
  struct Entry {std::string operation,scope;Decision decision;};
 private:
  std::vector<Entry> entries;
  uint64_t revision_=1;
  void changed(){vaultlink::require(revision_<UINT64_MAX,"grant-revision-exhausted");++revision_;}
 public:
  uint64_t revision() const{return revision_;}
  size_t count() const{return entries.size();}
  Entry get(size_t i) const{vaultlink::require(i<entries.size(),"invalid-grant");return entries[i];}
  Decision decision(const std::string &op,const std::string &scope) const {
    for(const auto &e:entries)if(e.operation==op&&e.scope==scope)return e.decision;
    return Ask;
  }
  void set(const std::string &op,const std::string &scope,Decision decision){
    vaultlink::require(decision==Allow||decision==Deny,"invalid-grant");
    for(auto &e:entries)if(e.operation==op&&e.scope==scope){changed();e.decision=decision;return;}
    vaultlink::require(entries.size()<8,"grant-capacity");changed();entries.push_back({op,scope,decision});
  }
  void cancel(size_t i){vaultlink::require(i<entries.size(),"invalid-grant");changed();entries.erase(entries.begin()+i);}
  void clear(){changed();entries.clear();}
};
} // namespace rockey::vlp
