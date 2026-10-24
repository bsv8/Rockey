#pragma once
#include "bsv.hpp"
#include "channel.hpp"
namespace vaultlink {
inline uint64_t connect_money(const Value& value){
  const auto& text=value.string();require(!text.empty()&&text.size()<=20&&(text.size()==1||text[0]!='0'),"invalid-connect-payment-template");
  uint64_t result=0;for(char c:text){require(c>='0'&&c<='9'&&result<=(UINT64_MAX-uint64_t(c-'0'))/10,"invalid-connect-payment-template");result=result*10+uint64_t(c-'0');}return result;
}
inline bool connect_p2pk(const Bytes& script){
  if(script.size()!=35||script.front()!=33||script.back()!=0xac)return false;
  try{channel_pub(to_hex(Bytes(script.begin()+1,script.end()-1)));return true;}catch(...){return false;}
}
struct ConnectPaymentReview {Review review;uint64_t business=0;std::string publisher,type,ownership,app,origin,name,purpose,label;};
inline ConnectPaymentReview inspect_connect_payment(const Bytes& raw,const std::vector<Bytes>& previous,const Bytes& pub,const Value& facts){
  facts.fields({"paymentId","clientRequestId","planDigest","paymentType","businessKind","appId","appName","origin","publisherPublicKeyHex","recipientOwnership","recipientLabel","businessScriptHex","businessAmountSats","changeAmountSats","feeSats","changeScriptHex","outputs"});
  ConnectPaymentReview result;auto& review=result.review;
  result.type=facts.at("paymentType").string();require(result.type=="p2pkh"||result.type=="p2pk","invalid-connect-payment-template");
  result.publisher=facts.at("publisherPublicKeyHex").string();const auto publisher=channel_pub(result.publisher);result.publisher=to_hex(publisher);
  result.app=facts.at("appId").string();result.name=facts.at("appName").string();result.origin=facts.at("origin").string();result.purpose=facts.at("businessKind").string();result.label=facts.at("recipientLabel").string();
  for(const auto* name:{"paymentId","clientRequestId","planDigest","appId","appName","origin","businessKind","recipientLabel"})require(!facts.at(name).string().empty()&&facts.at(name).string().size()<=1024,"invalid-connect-payment-template");
  const auto tx=parse_tx(raw,640);require(!tx.inputs.empty()&&tx.inputs.size()<=16&&previous.size()==tx.inputs.size(),"invalid-connect-payment-template");
  const auto own=own_script(pub);uint64_t inputs=0,outputs=0,role_change=0;std::vector<std::string> seen;
  for(size_t i=0;i<tx.inputs.size();++i){const auto& in=tx.inputs[i];require(in.script.empty(),"already-signed");const auto ref=to_hex(in.txid)+":"+std::to_string(in.vout);
    require(std::find(seen.begin(),seen.end(),ref)==seen.end(),"duplicate-input");seen.push_back(ref);
    auto prior=parse_tx(previous[i]);require(sha256d(previous[i])==in.txid&&in.vout<prior.outputs.size(),"invalid-prevout");const auto& output=prior.outputs[in.vout];require(output.script==own,"wrong-key");
    inputs=add(inputs,output.amount);review.digests.push_back(forkid_sighash(tx,i,output));}
  const auto& roles=facts.at("outputs");require(roles.kind==Value::Array&&roles.array.size()==tx.outputs.size(),"invalid-connect-payment-template");
  const auto business_script=from_hex(facts.at("businessScriptHex").string());unsigned businesses=0,changes=0;
  require(result.type=="p2pkh"?is_p2pkh(business_script):connect_p2pk(business_script),"invalid-connect-payment-template");
  for(size_t i=0;i<tx.outputs.size();++i){const auto& output=tx.outputs[i];const auto& role=roles.array[i];role.fields({"vout","scriptHex","valueSats","role"});
    require(role.at("vout").integer()==i&&from_hex(role.at("scriptHex").string())==output.script&&connect_money(role.at("valueSats"))==output.amount,"invalid-connect-payment-template");
    outputs=add(outputs,output.amount);if(output.script==own)review.change=add(review.change,output.amount);
    const auto kind=role.at("role").string();
    if(kind=="business"){++businesses;require(output.script==business_script,"invalid-connect-payment-template");result.business=add(result.business,output.amount);}
    else {require(kind=="change"&&output.script==own,"invalid-connect-payment-template");++changes;role_change=add(role_change,output.amount);}
  }
  require(businesses==1&&changes<=1&&inputs>=outputs&&result.business==connect_money(facts.at("businessAmountSats"))&&role_change==connect_money(facts.at("changeAmountSats")),"invalid-connect-payment-template");
  if(changes)require(facts.at("changeScriptHex").kind==Value::Text&&from_hex(facts.at("changeScriptHex").string())==own,"invalid-connect-payment-template");
  else require(facts.at("changeScriptHex").kind==Value::Null,"invalid-connect-payment-template");
  review.fee=inputs-outputs;review.amount=inputs-review.change;require(review.fee==connect_money(facts.at("feeSats")),"invalid-connect-payment-template");
  Bytes publisher_p2pk{33};publisher_p2pk.insert(publisher_p2pk.end(),publisher.begin(),publisher.end());publisher_p2pk.push_back(0xac);
  result.ownership=business_script==own_script(publisher)||business_script==publisher_p2pk?"app-publisher":"third-party";
  require(facts.at("recipientOwnership").string()==result.ownership,"invalid-connect-payment-template");
  return result;
}
inline std::string connect_payment_channel(const std::string& publisher,const std::string& type,const std::string& network){
  // All constituents are validated fixed ASCII; this is the exact host JSON hash.
  const auto text="[\"keymaster.app-payment-channel.v1\",\"publisher."+publisher+"\",\"publisher-single.v1\",\""+type+"\",\""+network+"\"]";
  return "pay."+to_hex(sha256(Bytes(text.begin(),text.end())));
}
}
