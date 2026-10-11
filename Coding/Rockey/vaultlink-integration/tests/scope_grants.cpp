// 宿主授权输入适配器，执行正式 PaymentService、实际密码和磁盘 Store。
// 这验证决策作用域与撤权，不宣称是设备实体按键证明。
#include "../operations.hpp"
#include "../display_text.hpp"
#include <fstream>
#include <cstdio>
using namespace vaultlink;
using namespace rockey::vlp;
class Disk final:public Store {
  std::string path;
 public:explicit Disk(std::string p):path(std::move(p)){}
  Bytes load() override{std::ifstream f(path,std::ios::binary);if(!f)return {};return Bytes(std::istreambuf_iterator<char>(f),{});}
  void save(const Bytes &b) override{std::ofstream f(path+".tmp",std::ios::binary);f.write(reinterpret_cast<const char *>(b.data()),b.size());f.close();require(std::rename((path+".tmp").c_str(),path.c_str())==0,"storage-failed");}
};
class HostDecision final:public ApprovalUI {
 public:Approval::State state=Approval::Once;unsigned prompts=0;
  void begin(const rockey::vlp::Review &r) override{require(r.can_remember,"not-scope-review");++prompts;}
  Approval decision() override{return {state,0};}
  void clear() override{}
};
int rng(void *,unsigned char *out,size_t n){std::ifstream f("/dev/urandom",std::ios::binary);f.read(reinterpret_cast<char *>(out),n);return f?0:-1;}
int main(int argc,char **argv){try{
 require(argc==2,"path-required");Disk store(argv[1]);Bytes secret(32);secret[31]=1;IdentityKey key(secret,rng);wipe_bytes(secret);
 HostDecision ui;PaymentService service(key,store,ui,"main");
 auto body=[](const std::string &scope){return obj({{"scope",scope},{"plaintext",Bytes(32,7)}});};
 auto prepare=[&](const std::string &op,const Value &b){return service.prepare(op,b,commitment("local-secret-v3",b));};
 auto run=[&](const std::string &op,const Value &b){auto p=prepare(op,b);require(p.operation->ready(),"not-ready");return p.operation->allowed()?p.operation->execute():obj({{"error","denied"}});};
 auto once=run("local-secret.seal",body("storage.test"));require(service.grant_count()==0&&ui.prompts==1,"once-became-session");
 ui.state=Approval::AllowSession;auto sealed=run("local-secret.seal",body("storage.test"));require(service.grant_count()==1&&ui.prompts==2,"grant-not-recorded");
 auto again=run("local-secret.seal",body("storage.test"));require(ui.prompts==2&&key.open_local("storage.test",again)==Bytes(32,7),"auto-grant-failed");
 ui.state=Approval::DenySession;auto open_body=obj({{"scope","storage.test"},{"sealed",sealed}});
 auto denied=run("local-secret.open",open_body);require(denied.at("error").string()=="denied"&&ui.prompts==3&&service.grant_count()==2,"cross-operation-grant");
 denied=run("local-secret.open",open_body);require(denied.at("error").string()=="denied"&&ui.prompts==3,"deny-prompted-again");
 auto delayed=prepare("local-secret.seal",body("storage.test"));service.cancel_grant(1);
 bool revoked=false;try{require(delayed.operation->ready(),"not-ready");delayed.operation->allowed();}catch(const Failure &e){revoked=std::string(e.what())=="permission-revoked";}require(revoked,"stale-grant-survived");
 ui.state=Approval::Once;auto opened=run("local-secret.open",open_body);require(opened.at("plaintext").binary()==Bytes(32,7)&&ui.prompts==4,"cancel-denial-did-not-prompt");
 auto prompt_count=ui.prompts;ui.state=Approval::Denied;
 denied=run("local-secret.open",open_body);require(denied.at("error").string()=="denied"&&service.grant_count()==1,"once-denial-persisted");
 ui.state=Approval::Once;opened=run("local-secret.open",open_body);require(opened.at("plaintext").binary()==Bytes(32,7)&&ui.prompts==prompt_count+2,"once-denial-did-not-prompt-again");
 service.cancel_grant(0);prompt_count=ui.prompts;run("local-secret.seal",body("storage.test"));require(service.grant_count()==0&&ui.prompts==prompt_count+1,"cancel-allow-did-not-prompt");
 ui.state=Approval::AllowSession;run("local-secret.seal",body("storage.test"));
 ui.state=Approval::AllowSession;for(unsigned i=0;i<7;i++)run("local-secret.seal",body("scope."+std::to_string(i)));
 require(service.grant_count()==8,"grant-count-wrong");bool capacity=false;try{run("local-secret.seal",body("scope.extra"));}catch(const Failure &e){capacity=std::string(e.what())=="grant-capacity";}require(capacity&&service.grant_count()==8,"silent-grant-eviction");
 service.cancel_grants();require(service.grant_count()==0,"clear-failed");
 ui.state=Approval::AllowSession;run("local-secret.seal",body("storage.test"));auto before_disconnect=prepare("local-secret.seal",body("storage.test"));service.disconnected();require(service.grant_count()==0,"disconnect-retained-grant");
 revoked=false;try{before_disconnect.operation->ready();before_disconnect.operation->allowed();}catch(const Failure &e){revoked=std::string(e.what())=="permission-revoked";}require(revoked,"disconnect-retained-pending");
 std::string unicode;for(unsigned i=0;i<30;i++)unicode+="秘";unicode+="data";std::string restored;for(const auto &line:display_chunks(unicode)){require(line.size()<=26&&utf8_valid(line),"broken-display-utf8");restored+=line;}require(restored==unicode,"scope-truncated");
 service.cancel_grants();
 Bytes peer_secret(32);peer_secret[31]=2;IdentityKey peer(peer_secret,rng);wipe_bytes(peer_secret);
 auto signed_channel=[&](IdentityKey &sender,const Bytes &recipient){
   auto channel="bsv8.inbox."+to_hex(recipient),pub=to_hex(sender.public_key());
   auto unsigned_json="{\"body\":{\"type\":\"ping\"},\"channel\":"+json_quote(channel)+",\"expires_at_ms\":61000,\"from_public_key\":"+json_quote(pub)+",\"issued_at_ms\":1000,\"message_id\":"+json_quote(channel_base64(Bytes(32,3)))+",\"protocol\":\"bsv8.ping.v1\"}";
   auto parsed=parse_jcs(json_bytes(unsigned_json));auto logical=json_bytes(channel_logical(parsed));
   auto signature=channel_base64(sender.sign(sha256(logical)));
   auto signed_json=unsigned_json.substr(0,unsigned_json.size()-1)+",\"signature\":"+json_quote(signature)+"}";
   return std::make_pair(logical,json_bytes(signed_json));
 };
 auto outgoing=signed_channel(key,peer.public_key());
 auto channel_prepare=[&](const std::string &op,const std::string &kind,const Bytes &raw){auto b=obj({{"message",raw}});return service.prepare(op,b,commitment("bsv8-channel-"+kind,b));};
 auto channel_run=[&](const std::string &op,const std::string &kind,const Bytes &raw){auto p=channel_prepare(op,kind,raw);require(p.operation->ready(),"not-ready");return p.operation->allowed()?p.operation->execute():obj({{"error","denied"}});};
 ui.state=Approval::AllowSession;prompt_count=ui.prompts;channel_run("channel.private-message","private",outgoing.first);
 auto cipher=channel_run("channel.seal","seal",outgoing.second).at("message").binary();
 require(ui.prompts==prompt_count+1&&service.grant_count()==1,"outbound-sign-seal-scope-not-shared");
 auto decoded=peer.open_channel(cipher);WipeBytes wipe_decoded{decoded};require(inspect_signed_channel(decoded,key.public_key()).peer==to_hex(peer.public_key()),"outbound-open-failed");
 auto incoming=signed_channel(peer,key.public_key());auto envelope=peer.seal_channel(incoming.second);
 ui.state=Approval::DenySession;auto denied_open=channel_run("channel.open","open",envelope);
 require(denied_open.at("error").string()=="denied"&&ui.prompts==prompt_count+2,"inbound-shared-outbound-grant");
 denied_open=channel_run("channel.open","open",envelope);require(denied_open.at("error").string()=="denied"&&ui.prompts==prompt_count+2,"inbound-denial-not-remembered");
 service.cancel_grant(1);ui.state=Approval::Once;auto approved_open=channel_run("channel.open","open",envelope).at("message").binary();WipeBytes wipe_opened{approved_open};
 require(approved_open==incoming.second&&ui.prompts==prompt_count+3,"inbound-denial-cancellation-failed");
 auto stale=channel_prepare("channel.seal","seal",outgoing.second);service.cancel_grant(0);revoked=false;
 try{stale.operation->ready();stale.operation->allowed();}catch(const Failure &e){revoked=std::string(e.what())=="permission-revoked";}require(revoked,"stale-channel-grant-survived");
 key.lock();peer.lock();std::puts("scope grant production service checks passed");return 0;
 }catch(const std::exception &e){std::fprintf(stderr,"failure:%s\n",e.what());return 1;}}
