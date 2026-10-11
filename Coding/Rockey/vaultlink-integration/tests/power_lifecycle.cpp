// Host transport adapter: real Runtime/KeyStore/SDK, real encrypted handshake
// and signature verification. Pairing approval is an explicit host test event;
// this is not evidence of physical buttons, VBUS wiring or battery behavior.
#include "../rockey_vaultlink.hpp"
#include <Arduino.h>
#include <deque>
#include <cstdio>
using namespace vaultlink;
extern "C" void esp_fill_random(void*, size_t);
int random_bytes(void*, unsigned char* data, size_t size) { esp_fill_random(data, size); return 0; }
class Pipe final : public ByteTransport {
 public:
  std::deque<uint8_t> input;
  std::deque<Frame> output;
  FrameReader reader;
  int read_byte() override { if (input.empty()) return -1; int c=input.front(); input.pop_front(); return c; }
  void write(const Bytes& b) override { Frame f; for (auto c:b) if(reader.feed(c,f)) output.push_back(f); }
  uint64_t millis() override { return ::millis(); }
  void send(uint8_t type, uint32_t seq, const Bytes& payload) {
    Bytes b{0xa5,0x5a,2,type,0}; auto s=le32(seq); b.insert(b.end(),s.begin(),s.end());
    b.push_back(payload.size()&255); b.push_back(payload.size()>>8); b.insert(b.end(),payload.begin(),payload.end());
    auto crc=le32(crc32(b.data()+2,b.size()-2)); b.insert(b.end(),crc.begin(),crc.end());
    input.insert(input.end(),b.begin(),b.end());
  }
  Frame take(uint8_t type) { require(!output.empty(),"missing-response"); auto f=output.front(); output.pop_front(); require(f.type==type,"wrong-response"); return f; }
};
class HostUI final : public rockey::vlp::ApprovalUI {
 public:
  unsigned clears=0;
  void begin(const rockey::vlp::Review&) override {}
  rockey::vlp::Approval decision() override { return {}; }
  void clear() override { ++clears; }
};
class HostPeer {
  Pipe& pipe;
  rockey::vlp::Runtime& device;
 public:
  std::unique_ptr<Record> send, receive;
  Value binding;
  HostPeer(Pipe& p, rockey::vlp::Runtime& d):pipe(p),device(d){}
  void message(uint8_t type,const Value& body) {
    auto cipher=send->seal(type,encode(body));pipe.send(type,send->sequence(),cipher);device.poll();
  }
  Value response(uint8_t type) { auto f=pipe.take(type); return decode(receive->open(type,f.seq,Bytes(f.payload.begin(),f.payload.begin()+f.size))); }
  void connect(uint32_t hostApprovalPause=0) {
    X25519 host(random_bytes);
    auto hello=obj({{"hostEph",host.public_key()},{"hostNonce",Bytes(32,7)},
      {"protocolVersion",uint64_t(2)},{"capabilities",Value::list({})},
      {"walletGeneration",uint64_t(1)},{"backendGeneration",uint64_t(1)},{"hostRunGeneration",uint64_t(1)}});
    pipe.send(1,0,encode(hello));device.poll();auto f=pipe.take(2);
    auto ack=decode(Bytes(f.payload.begin(),f.payload.begin()+f.size));
    static constexpr char label[]="vlp:handshake:v2\0";
    auto digest=sha256(join({text_bytes(label,sizeof(label)-1),encode(obj({{"hello",hello},{"ack",ack}}),2048)}));
    auto shared=host.shared(ack.at("deviceEph").binary(32));
    auto run=uint32_t(ack.at("deviceRunId").integer()), connection=uint32_t(ack.at("connectionId").integer());
    send=std::make_unique<Record>(hkdf(shared,digest,"vlp:link:c2s:key:v2",32),hkdf(shared,digest,"vlp:link:c2s:nonce:v2",12),run,connection);
    receive=std::make_unique<Record>(hkdf(shared,digest,"vlp:link:s2c:key:v2",32),hkdf(shared,digest,"vlp:link:s2c:nonce:v2",12),run,connection);
    static constexpr char pair_label[]="vlp:link:pairing:v2";
    auto h=sha256(join({text_bytes(pair_label,sizeof(pair_label)-1),digest}));
    auto code=std::to_string(((uint32_t(h[0])<<16)|(uint32_t(h[1])<<8)|h[2])%1000000); code.insert(0,6-code.size(),'0');
    message(3,obj({{"code",code}}));require(response(4).at("paired").boolean,"pair-denied");
    // User may approve on device first, then compare/approve in the browser.
    // This is still handshake waiting, not an idle established session.
    if(hostApprovalPause){delay(hostApprovalPause);device.poll();}
    Bytes challenge(32,9);message(5,obj({{"challenge",challenge}}));auto proof=response(6);
    static constexpr char proof_label[]="vlp:possession:v2\0";
    auto session=uint32_t(proof.at("sessionId").integer());auto pub=proof.at("publicKey").binary(33);
    auto hash=sha256d(join({text_bytes(proof_label,sizeof(proof_label)-1),digest,pub,be32(session),challenge}));
    channel_verify(pub,hash,proof.at("signature").binary());
    binding=obj({{"sessionId",std::to_string(session)},{"sessionEpoch",uint64_t(1)},
      {"connectionId",uint64_t(connection)},{"deviceRunId",uint64_t(run)}});
  }
  void close() { message(16,obj({{"op","system.close"},{"opVersion",uint64_t(1)},
    {"body",obj({})},{"requestId",uint64_t(1)},{"binding",binding},{"commitment",Bytes(32,1)}})); }
};
int main() { try {
  using rockey::keystore::KeyStore;using rockey::keystore::Status;
  require(rockey::store::Init()&&KeyStore::Init(),"storage-init");
  Bytes key(32);key[31]=1;
  require(KeyStore::SetPinAndWrap("12345678",8,key.data(), rockey::keystore::BsvNetwork::Main)==Status::kOk && KeyStore::Unlock("12345678",8)==Status::kOk,"key-init");wipe_bytes(key);
  Pipe pipe;HostUI ui;rockey::vlp::PolicyStore store;unsigned revoked=0,pairs=0;
  rockey::vlp::Runtime device(pipe,random_bytes,1,ui,store,[&](const std::string&){++pairs;return false;},[]{return 1;},[&]{++revoked;ui.clear();});
  delay(600000);device.poll();require(KeyStore::IsUnlocked(),"idle-locked");
  HostPeer a(pipe,device);a.connect(9000);unsigned before=revoked;
  delay(9000);device.poll();require(revoked>before&&ui.clears>0&&KeyStore::IsUnlocked(),"timeout-locked-or-retained-session");
  HostPeer b(pipe,device);b.connect();before=revoked;b.close();
  require(revoked>before&&KeyStore::IsUnlocked(),"close-locked-or-retained-session");
  HostPeer c(pipe,device);c.connect();
  // A new HELLO also replaces the active connection without losing unlock.
  HostPeer d(pipe,device);d.connect();require(pairs==4&&KeyStore::IsUnlocked(),"reconnect-failed");
  device.lock();require(!KeyStore::IsUnlocked()&&KeyStore::PrivateKey()==nullptr,"explicit-lock-retained-key");
  require(KeyStore::Init()&&!KeyStore::IsUnlocked(),"restart-unlocked");
  std::puts("Power lifecycle: idle, timeout, close, reconnect signatures, explicit lock and restart passed (host transport).");return 0;
} catch (const std::exception& e) { std::fprintf(stderr,"Power lifecycle failed: %s\n",e.what());return 1; } }
