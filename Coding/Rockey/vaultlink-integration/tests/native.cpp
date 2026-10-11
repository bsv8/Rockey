// 仅宿主互通验证：公开测试 Key，实际产品 PaymentService/Endpoint，非真机按钮证明。
#include "../migration_requests.hpp"
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <csignal>
static volatile sig_atomic_t localSettingsRequested=0;
static void local_settings(int){localSettingsRequested=1;}
using namespace vaultlink;
class Files final: public Store {std::string path;public:Files(std::string p):path(p){} Bytes load() override{if(!std::filesystem::exists(path))return {};std::ifstream f(path,std::ios::binary);require(bool(f),"read-failed");return Bytes(std::istreambuf_iterator<char>(f),{});} void save(const Bytes& b) override{auto tmp=path+".tmp";int fd=open(tmp.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0600);require(fd>=0,"write-failed");size_t at=0;while(at<b.size()){auto n=write(fd,b.data()+at,b.size()-at);require(n>0,"write-failed");at+=n;}require(fsync(fd)==0&&close(fd)==0&&rename(tmp.c_str(),path.c_str())==0,"write-failed");}};
class UI final:public rockey::vlp::ApprovalUI {public:rockey::vlp::Review review;bool active=false; void begin(const rockey::vlp::Review& r)override{review=r;active=true;fprintf(stderr,"review:%s:%s\n",r.operation.c_str(),r.can_raise?"total":"single");} rockey::vlp::Approval decision()override{if(review.operation.rfind("tx.",0)==0 && std::getenv("ROCKEY_HOST_HOLD_PAYMENT"))return {};return {rockey::vlp::Approval::Once,0};} void automatically_approved(const rockey::vlp::Review& r)override{fprintf(stderr,"auto-approved:%s\n",r.operation.c_str());} void clear()override{active=false;}};
int rng(void*,unsigned char* b,size_t n){int fd=open("/dev/urandom",O_RDONLY);if(fd<0)return -1;size_t at=0;while(at<n){auto k=read(fd,b+at,n-at);if(k<=0){close(fd);return -1;}at+=k;}return close(fd);}
class Pipe final:public ByteTransport {std::chrono::steady_clock::time_point start=std::chrono::steady_clock::now();public:bool eof=false;Pipe(){fcntl(0,F_SETFL,fcntl(0,F_GETFL)|O_NONBLOCK);}int read_byte()override{uint8_t b;auto n=read(0,&b,1);if(n==1)return b;if(n==0)eof=true;return -1;}void write(const Bytes& b)override{size_t at=0;while(at<b.size()){auto n=::write(1,b.data()+at,b.size()-at);require(n>0,"write-failed");at+=n;}if(b.size()>3 && b[3]==6 && std::getenv("ROCKEY_HOST_CLOSE_AFTER_PROOF"))eof=true;}uint64_t millis()override{return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();}};
int main(int argc,char** argv){try{require(argc==2,"path-required");Bytes secret(32);secret[31]=1;IdentityKey key(secret,rng);require(p2pkh_output_address(own_script(key.public_key()))=="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH","address-vector-failed");std::fill(secret.begin(),secret.end(),0);Files files(argv[1]);UI ui;rockey::vlp::PaymentService service(key,files,ui,"main");Files migrationFiles(std::string(argv[1])+".migration");MigrationJournal migration(migrationFiles);rockey::vlp::MigrationRequests requests(service,migration,key.public_key());Pipe pipe;Endpoint endpoint(pipe,key,rng,1,[&](const std::string& op,const Value& b,const Bytes& h){return requests.prepare(op,b,h);},[&]{service.disconnected();},[](const std::string&){return true;});endpoint.set_capabilities({Value(uint64_t(0x22f))});std::signal(SIGUSR1,local_settings);while(!pipe.eof){
 if(localSettingsRequested){localSettingsRequested=0;auto channels=service.payment_channels();for(const auto& row:channels.array){auto fresh=service.payment_channels();for(const auto& c:fresh.array)if(c.at("id").string()==row.at("id").string())service.configure_payment(Channel{c.at("id").string(),c.at("owner").string(),400,500,c.at("revision").integer()+1,true,c.at("kind").string(),c.at("paymentType").string()});}fprintf(stderr,"host-settings:saved\n");}
 endpoint.poll();usleep(1000);}return 0;}catch(const std::exception& e){fprintf(stderr,"failure:%s\n",e.what());return 1;}}
