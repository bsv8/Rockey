#pragma once
#include "../vaultlink-sdk/device/sdk/policy.hpp"
#include "board/buttons.h"
#include "board/display.h"
#include "ui/widgets.h"
#include "i18n/i18n.h"
#include <functional>
namespace rockey::ui {
/** A/C 浏览或修改，B 进入或移动数字，长按 B 保存，长按 A 返回。
 * 所有修改能力来自设备菜单，不是 USB 命令；修订号阻止旧页面覆盖新设置。 */
class ChannelSettings {
 public:
  std::function<vaultlink::Value()> signing,payments;
  std::function<void(const std::string&,const std::string&,uint64_t)> saveSigning;
  std::function<void(const vaultlink::Channel&)> savePayment;
 private:
  uint8_t selected=0,field=0,digit=0;
  bool detail=false,editing=false,changed=false,awaitRelease=false;
  Btn savedButton=Btn::kB;
  vaultlink::Value current;
  std::string proposed,error;
  vaultlink::Value rows(){auto rows=signing();auto more=payments();rows.array.insert(rows.array.end(),more.array.begin(),more.array.end());return rows;}
  bool payment(){return current.kind!=vaultlink::Value::Null&&std::any_of(current.map.begin(),current.map.end(),[](const auto& p){return p.first=="paymentType";});}
  const char* modeLabel(const std::string& mode){return i18n::T(mode=="automatic"?i18n::Str::kChannelAutomatic:i18n::Str::kChannelManual);}
  const char* fieldName(){using i18n::Str;return i18n::T(!payment()?Str::kChannelMode:field==0?Str::kChannelMode:Str::kChannelSingle);}
  void beginEdit(){
    if(!payment()&&vaultlink::automatic_signing_operation(current.at("operation").string()))return;
    if(!payment()||field==0){proposed=!payment()?current.at("mode").string():(current.at("enabled").flag()?"automatic":"manual");}
    else {proposed=std::to_string(current.at("singleLimit").integer());proposed=std::string(20-proposed.size(),'0')+proposed;}
    digit=19;editing=true;changed=false;
  }
  void save(){
    using namespace vaultlink;
    const auto rev=current.at("revision").integer();
    if(!payment())saveSigning(current.at("id").string(),proposed,rev);
    else {
      Channel c{current.at("id").string(),current.at("owner").string(),current.at("singleLimit").integer(),current.at("defaultSessionLimit").integer(),rev+1,current.at("enabled").flag(),current.at("kind").string(),current.at("paymentType").string()};
      if(field==0)c.enabled=proposed=="automatic";
      else {uint64_t n=0;for(char ch:proposed){require(n<=(UINT64_MAX-(ch-'0'))/10,"invalid-amount");n=n*10+(ch-'0');}c.single=n;}
      savePayment(c);
    }
    detail=false;editing=false;changed=false;
  }
 public:
  void reset(){selected=field=digit=0;detail=editing=changed=awaitRelease=false;current={};error.clear();}
  bool input(Btn b,BtnEvent ev){
    // 子页面返回/保存后必须先松开同一按钮，长按余下的重复事件不能移动列表。
    if(ev==BtnEvent::kRelease){if(b==savedButton)awaitRelease=false;return false;}
    if(awaitRelease)return false;
    if(ev==BtnEvent::kLongPress&&(b==Btn::kA||b==Btn::kB)){awaitRelease=true;savedButton=b;}
    if(ev!=BtnEvent::kShortPress&&ev!=BtnEvent::kHoldRepeat&&ev!=BtnEvent::kLongPress)return false;
    error.clear();
    if(b==Btn::kA&&ev==BtnEvent::kLongPress){if(editing){editing=false;return false;}if(detail){detail=false;return false;}return true;}
    try {
      if(!detail){auto all=rows();auto n=all.array.size();if(!n)return b==Btn::kB;
        selected%=n;if(b==Btn::kA)selected=(selected+n-1)%n;else if(b==Btn::kC)selected=(selected+1)%n;else if(b==Btn::kB&&ev==BtnEvent::kShortPress){current=all.array[selected];detail=true;field=0;}return false;}
      if(!editing){unsigned n=payment()?2:1;
        if(b==Btn::kA)field=(field+n-1)%n;else if(b==Btn::kC)field=(field+1)%n;else if(b==Btn::kB&&ev==BtnEvent::kShortPress)beginEdit();return false;}
      if(b==Btn::kB&&ev==BtnEvent::kLongPress){if(changed)save();else editing=false;return false;}
      if(b==Btn::kB&&ev==BtnEvent::kShortPress){if(payment()&&field>0)digit=(digit+19)%20;return false;}
      if(b==Btn::kA||b==Btn::kC){if(!payment()||field==0)proposed=proposed=="automatic"?"manual":"automatic";
        else proposed[digit]='0'+(proposed[digit]-'0'+(b==Btn::kC?1:9))%10;changed=true;}
    }catch(const std::exception& e){error=e.what();}
    return false;
  }
  void draw(){
    using namespace vaultlink;using i18n::Str;
    DrawHeader(i18n::T(Str::kChannelSettings),nullptr);Rect c{0,Board::kContentY,Board::kScreenW,Board::kContentH};Display::Fill(c,color::kBlack);
    unsigned row=0;
    try {
      if(!detail){auto all=rows();if(all.array.empty())DrawKeyValue(c,"",i18n::T(Str::kChannelEmpty),row++);
        else {selected%=all.array.size();const auto& x=all.array[selected];DrawKeyValue(c,"ID",x.at("id").string().c_str(),row++);DrawKeyValue(c,"Owner",x.at("owner").string().c_str(),row++);std::string count=std::to_string(selected+1)+" / "+std::to_string(all.array.size());DrawKeyValue(c,"",count.c_str(),row++);}}
      else {
        DrawKeyValue(c,"ID",current.at("id").string().c_str(),row++);
        std::string old=!payment()?current.at("mode").string():field==0?(current.at("enabled").flag()?"automatic":"manual"):std::to_string(current.at("singleLimit").integer());
        DrawKeyValue(c,fieldName(),(!payment()||field==0)?modeLabel(old):old.c_str(),row++);
        if(editing){DrawKeyValue(c,"->",(!payment()||field==0)?modeLabel(proposed):proposed.c_str(),row++);if(payment()&&field>0){auto marker=std::to_string(20-digit)+" : "+proposed[digit];DrawKeyValue(c,"Digit (right)",marker.c_str(),row++);}DrawKeyValue(c,"",i18n::T(Str::kChannelSave),row++);}
      }
      if(!error.empty())DrawKeyValue(c,"!",error.c_str(),row++);
    }catch(const std::exception& e){DrawKeyValue(c,"!",e.what(),row++);}
    DrawFooter(i18n::T(Str::kBtnPrev),i18n::T(editing?Str::kBtnEnter:Str::kBtnSelect),i18n::T(Str::kBtnNext));
  }
};
}
