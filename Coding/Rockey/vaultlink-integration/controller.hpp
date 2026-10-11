#pragma once
#include "../device-ui/authorization_sound.hpp"
#include "rockey_vaultlink.hpp"
#include "erased_migration.hpp"
#include "provision_runtime.hpp"
#include "display_text.hpp"
#include "board/buttons.h"
#include "board/display.h"
#include "crypto/rand.h"
#include "i18n/i18n.h"
#include "ui/widgets.h"
#include "pin_reauthentication.hpp"
#include <Arduino.h>
#include "../e2e/device.hpp"
namespace rockey::vlp {
class SerialTransport final : public vaultlink::ByteTransport {
 public:
  int read_byte() override {
#if defined(ROCKEY_DEV_BUTTON_API)
    return e2e::device().read();
#else
    return Serial.available() ? Serial.read() : -1;
#endif
  }
  void write(const vaultlink::Bytes& bytes) override {
#if defined(ROCKEY_DEV_BUTTON_API)
    e2e::device().write(bytes);
#else
    vaultlink::require(Serial.write(bytes.data(), bytes.size()) == bytes.size(), "transport-failed");
#endif
  }
  uint64_t millis() override { return ::millis(); }
};
// PIN 页面仍归 App；解锁后 USB 只有此控制器读串口，旧 wire 不降级接收。
class Controller final : public ApprovalUI {
  Buttons& buttons;
  PolicyStore store;
  SerialTransport transport;
  std::unique_ptr<Runtime> runtime;
  std::unique_ptr<ErasedMigrationRuntime> erased_runtime;
  ProvisionKeys provision_keys;
  std::unique_ptr<ProvisionRuntime> provision_runtime;
  uint32_t provision_started=0;
  Review review;
  Approval answer;
  std::vector<std::string> lines;
  size_t position = 0, furthest = 0;
  bool visible = false, pairing = false, redraw = false, raise = false, remember = false;
  int pair_answer = 0;
  uint64_t raised = 0;
  int drawn_percent = -1;
  ui::HoldConfirm hold;
  PinReauthentication pin;
  bool entering_pin=false;
  bool export_armed=false;
  static int random(void*, unsigned char* out, size_t count) { rand::Fill(out, count); return 0; }
  static const char* label(const std::string& key) {
    using i18n::Str;
    Str s = Str::kVlpChannel;
    if(key=="operation")s=Str::kSumOperation;
    else if(key=="risk")s=Str::kSumRisks;
    else if(key=="scope")s=Str::kSumScope;
    else if(key=="objectHash")s=Str::kSumObject;
    else if(key=="wireKind")s=Str::kBitfsKind;
    else if(key=="seedHash")s=Str::kBitfsSeed;
    else if(key=="seedPrice")s=Str::kBitfsSeedPrice;
    else if(key=="blockPrice")s=Str::kBitfsBlockPrice;
    else if(key=="quoteId")s=Str::kBitfsQuote;
    else if(key=="refundTxId")s=Str::kBitfsRefund;
    else if(key=="sequence")s=Str::kIdentitySequence;
    else if(key=="paymentSequence")s=Str::kBitfsSequence;
    else if(key=="authorizationId")s=Str::kBitfsAuthorization;
    else if(key=="claimId")s=Str::kBitfsClaim;
    else if(key=="arbiterAmount")s=Str::kBitfsArbiterAmount;
    else if(key=="result")s=Str::kBitfsResult;
    else if(key=="peer")s=Str::kChannelPeer;
    else if(key=="protocol")s=Str::kInfoProtocol;
    else if(key=="audience")s=Str::kConnectAudience;
    else if(key=="requestId")s=Str::kConnectRequest;
    else if(key=="issuedAt")s=Str::kConnectIssued;
    else if(key=="expiresAt")s=Str::kConnectExpires;
    else if(key=="claim")s=Str::kConnectClaim;
    else if(key=="contentType")s=Str::kConnectContentType;
    else if(key=="contentLength")s=Str::kConnectContentLength;
    else if(key=="contentHash")s=Str::kConnectContentHash;
    else if (key == "singleLimit") s = Str::kVlpSingleLimit;
    else if (key == "sessionLimit" || key == "defaultSessionLimit") s = Str::kVlpSessionLimit;
    else if (key == "used") s = Str::kVlpUsed;
    else if (key == "poolFamily") s = Str::kVlpPoolFamily;
    else if (key == "poolStage") s = Str::kVlpPoolStage;
    else if (key == "cumulativePaid") s = Str::kVlpPoolPaid;
    else if (key == "lockedAmount") s = Str::kVlpPoolLocked;
    else if (key == "fee") s = Str::kVlpFee;
    else if (key == "amount") s = Str::kVlpAmount;
    else if (key == "change" || key == "changeScript") s = Str::kVlpChange;
    else if (key == "recipientScript") s = Str::kTxPayees;
    else if (key == "singleExceeded") s = Str::kVlpSingleExceeded;
    else if (key == "sessionExceeded") s = Str::kVlpSessionExceeded;
    else if (key == "enabled") s = Str::kVlpEnabled;
    else if (key == "kind") s = Str::kVlpKind;
    else if (key == "sessionId") s = Str::kVlpSession;
    return i18n::T(s);
  }
  void add(const std::string& key, const std::string& value) {
    lines.push_back(key);
    // 实際对象不省略，按可显示的 ASCII 长度分行；A/C 可逐页读全。
    for(auto &line:display_chunks(value))lines.push_back(std::move(line));
  }
 public:
  explicit Controller(Buttons& b) : buttons(b) {}
  bool active_ui() const { return visible; }
#if defined(ROCKEY_DEV_BUTTON_API)
  uint32_t testReviews=0;
  char testFault[48]{};
  vaultlink::Value DevUiState() const {
    std::string code;if(pairing)for(const auto& fact:review.facts)if(fact.first=="pair")code=fact.second;
    return vaultlink::Value::object({{"visible",vaultlink::Value(visible)}, {"pairing",vaultlink::Value(pairing)},
      {"pairCode",vaultlink::Value(code)},{"operation",vaultlink::Value(visible?review.operation:"")},{"pin",vaultlink::Value(entering_pin)},
      {"lines",vaultlink::Value(uint64_t(lines.size()))},{"position",vaultlink::Value(uint64_t(position))},
      {"read",vaultlink::Value(lines.size()<=6||furthest+6>=lines.size())},
      {"canRaise",vaultlink::Value(review.can_raise)},{"raise",vaultlink::Value(raise)},
      {"reviews",vaultlink::Value(uint64_t(testReviews))},{"fault",vaultlink::Value(testFault)}});
  }
#endif
  void arm_export(){vaultlink::require(keystore::KeyStore::IsUnlocked(),"locked");cancel_grants();export_armed=true;}
  void arm_import(const char* p,size_t n){lock();provision_keys.arm(p,n);provision_started=::millis();}
  bool importing()const{return bool(provision_runtime)||provision_keys.ready();}
  void cancel_export(){export_armed=false;}
  size_t grant_count() const{return runtime?runtime->grant_count():0;}
  ScopeGrants::Entry grant(size_t i) const{
    vaultlink::require(bool(runtime),"locked");auto entry=runtime->grant(i);
    // This accessor is the device-menu presentation. The runtime retains its
    // exact protocol operation/scope; cancelling still addresses its index.
    using i18n::Str;
    if(entry.operation=="identity.noise-proof")entry.operation=i18n::T(Str::kOpNoiseProof);
    else if(entry.operation=="identity.peer-record")entry.operation=i18n::T(Str::kOpPeerRecord);
    else if(entry.operation=="channel.outbound")entry.operation=i18n::T(Str::kOpChannelPrivate);
    else if(entry.operation=="channel.inbound")entry.operation=i18n::T(Str::kOpChannelOpen);
    else if(entry.operation=="channel.public-message")entry.operation=i18n::T(Str::kOpChannelPublic);
    else if(entry.operation=="channel.hash-request")entry.operation=i18n::T(Str::kOpChannelHash);
    else if(entry.operation=="local-secret.seal")entry.operation=i18n::T(Str::kOpSecretSeal);
    else if(entry.operation=="local-secret.open")entry.operation=i18n::T(Str::kOpSecretOpen);
    return entry;
  }
  void cancel_grant(size_t i){if(runtime)runtime->cancel_grant(i);}
  void cancel_grants(){if(runtime)runtime->cancel_grants();}
  void start() {
    if (runtime || !keystore::KeyStore::IsUnlocked()) return;
    auto run = rand::U32(); if (!run) run = 1;
    runtime = std::make_unique<Runtime>(transport, random, run, *this, store,
      [this](const std::string& code) {
        begin(Review{"pair", "", "", {{"pair", code}}}); pairing = true; pair_answer = 0; return false;
      }, [this] { return pair_answer; }, [this] { clear(); },
      [this]{return export_armed;},[this]{export_armed=false;});
  }
  void lock() { runtime.reset();erased_runtime.reset();provision_runtime.reset();provision_keys.clear(); clear();export_armed=false; }
  void poll() {
    const bool importing_=importing();
    if(importing_&&uint32_t(::millis()-provision_started)>ROCKEY_REQUEST_TTL_MS){lock();return;}
    const bool erased=!keystore::KeyStore::HasKey()&&store::Exists("/vault/vlp-migration.bin");
    if(!importing_&&!erased&&!keystore::KeyStore::IsUnlocked()){lock();return;}
    try {
      if(importing_){
        if(!provision_runtime){auto run=rand::U32();if(!run)run=1;
          provision_runtime=std::make_unique<ProvisionRuntime>(transport,random,run,*this,provision_keys,
            [this](const std::string& code){begin(Review{"pair","","",{{"pair",code}}});pairing=true;pair_answer=0;return false;},
            [this]{return pair_answer;},[this]{clear();});}
        provision_runtime->poll();
      }else if(erased){
        if(!erased_runtime){auto run=rand::U32();if(!run)run=1;
          erased_runtime=std::make_unique<ErasedMigrationRuntime>(transport,random,run,*this,
            [this](const std::string& code){begin(Review{"pair","","",{{"pair",code}}});pairing=true;pair_answer=0;return false;},
            [this]{return pair_answer;},[this]{clear();});}
        erased_runtime->poll();
      }else{start();runtime->poll();}
    }
    catch (const std::exception& error) {
#if defined(ROCKEY_DEV_BUTTON_API)
      snprintf(testFault,sizeof(testFault),"%s",error.what());
#endif
      keystore::KeyStore::Lock(); lock();
    }
    catch (...) { keystore::KeyStore::Lock(); lock(); }
    if(!importing_&&!erased&&!keystore::KeyStore::IsUnlocked()){lock();return;}
    if (!visible) return;
    if(entering_pin){if(redraw)draw();return;}
    bool read = lines.size() <= 6 || furthest + 6 >= lines.size();
    hold.Update(buttons, ::millis(), read);
    if (hold.Fired()) {
      if (pairing) {
        pair_answer = 1; visible = false; hold.Reset(); buttons.ArmReleaseGate();
        // 确认后等待 Endpoint 发送 PAIR_OK，不能重画已经关闭的核对页。
        return;
      }
      else {
        answer = {remember ? Approval::AllowSession : raise ? Approval::Raise : Approval::Once, raised,pin.verified()};
        hold.Reset(); buttons.ArmReleaseGate();
      }
      redraw = true;
    }
    if (redraw) draw();
    const auto percent=hold.Percent(::millis());
    if(drawn_percent!=percent)draw_progress(percent);
  }
  bool button(Btn b, BtnEvent event) {
    if (!visible) return false;
    if(entering_pin) {
      if(b==Btn::kA&&event==BtnEvent::kLongPress) {
        pin.clear();entering_pin=false;answer.state=Approval::Denied;redraw=true;return true;
      }
      if(b==Btn::kB&&event==BtnEvent::kLongPress){pin.back();buttons.ArmReleaseGate();redraw=true;return true;}
      if(event==BtnEvent::kShortPress||event==BtnEvent::kHoldRepeat) {
        if(b==Btn::kA)pin.previous();
        if(b==Btn::kC)pin.next();
        if(b==Btn::kB&&event==BtnEvent::kShortPress) {
          auto result=pin.select();
          if(result!=PinReauthentication::Pending) {
            entering_pin=false;hold.Reset();buttons.ArmReleaseGate();
            if(result==PinReauthentication::Failed)answer.state=Approval::Denied;
          }
        }
        redraw=true;
      }
      return true;
    }
    if (b == Btn::kA && event == BtnEvent::kLongPress) {
      if (pairing) pair_answer = -1;
      else answer.state = remember ? Approval::DenySession : Approval::Denied;
      return true;
    }
    if (event == BtnEvent::kShortPress || event == BtnEvent::kHoldRepeat) {
      if (raise && (b == Btn::kA || b == Btn::kC)) {
        const uint64_t step = std::max<uint64_t>(1, review.minimum_limit / 10);
        if (b == Btn::kC && raised <= UINT64_MAX - step) raised += step;
        if (b == Btn::kA) raised = raised > step && raised - step >= review.minimum_limit ? raised - step : review.minimum_limit;
        redraw = true; return true;
      }
      const auto before=position;
      if (b == Btn::kA && position) --position;
      if (b == Btn::kC && position + 6 < lines.size()) ++position;
      if (b==Btn::kB && event==BtnEvent::kShortPress && review.can_remember && furthest+6>=lines.size()) {
        remember=!remember;hold.Reset();buttons.ArmReleaseGate();
        redraw=true;
      }
      // Only a deliberate short B selects an increased limit. Hold-repeat
      // belongs to scrolling/amount adjustment; it must not turn confirmation
      // into an implicit change of the spending policy.
      if (b == Btn::kB && event == BtnEvent::kShortPress && review.can_raise && furthest + 6 >= lines.size()) {
        raise = !raise;
        // 最小增额到本次后累计，之后可继续通过同一批准入口提高。
        raised = raise ? review.minimum_limit : 0;
        hold.Reset(); buttons.ArmReleaseGate();
        redraw=true;
      }
      furthest = std::max(furthest, position); if(before!=position)redraw = true;
    }
    return true;
  }
  void begin(const Review& r) override {
    sound::Notify(true,::millis());
#if defined(ROCKEY_DEV_BUTTON_API)
    ++testReviews;
#endif
    review = r; answer = {}; raised = 0; raise = false; remember = false; pairing = false;
    pin.clear();entering_pin=r.requires_pin;
    if(entering_pin){
      vaultlink::require(!r.can_remember&&!r.can_raise,"physical-confirmation-required");
      const bool ok=provision_keys.ready()?pin.begin_local(provision_keys.digits(),[this](const char* p,size_t n){return provision_keys.authenticate(p,n,::millis());}):pin.begin();
      vaultlink::require(ok,"locked");
    }
    position = furthest = 0; lines.clear();
    if (!r.channel.empty()) add(i18n::T(i18n::Str::kVlpChannel), r.channel);
    if (!r.owner.empty()) add(i18n::T(i18n::Str::kVlpOwner), r.owner);
    for (const auto& fact : r.facts) {
      auto value=fact.second;
      if(fact.first=="operation")value=i18n::T(value=="migration.import-key"?i18n::Str::kImportTitle:value=="migration.export"?i18n::Str::kOpMigrationExport:(value=="migration.erase"||value=="migration.recover-erased")?i18n::Str::kEraseTitle:value=="local-secret.seal"?i18n::Str::kOpSecretSeal:value=="local-secret.open"?i18n::Str::kOpSecretOpen:value=="connect.identity-sign"?i18n::Str::kOpIdentityProve:value=="identity.noise-proof"?i18n::Str::kOpNoiseProof:value=="identity.peer-record"?i18n::Str::kOpPeerRecord:value=="bitfs.wire-sign"?i18n::Str::kOpBitfsWire:value=="channel.public-message"?i18n::Str::kOpChannelPublic:value=="channel.hash-request"?i18n::Str::kOpChannelHash:value=="channel.private-message"?i18n::Str::kOpChannelPrivate:value=="channel.seal"?i18n::Str::kOpChannelSeal:value=="channel.open"?i18n::Str::kOpChannelOpen:i18n::Str::kOpIdentityAuthorize);
      else if(fact.first=="wireKind")value=i18n::T(value=="1"?i18n::Str::kBitfsQuoteSign:value=="5"?i18n::Str::kBitfsAuthorizeSign:value=="6"?i18n::Str::kBitfsDeliverySign:value=="8"?i18n::Str::kBitfsClaimSign:value=="9"?i18n::Str::kBitfsReceiptSign:value=="10"?i18n::Str::kBitfsRetrievalSign:i18n::Str::kBitfsResultSign);
      else if(fact.first=="poolStage")value=i18n::T(value=="fund"?i18n::Str::kVlpFunding:i18n::Str::kVlpPoolState);
      else if(fact.first=="poolFamily")value=value=="connect"?"Connect":"BitFS";
      add(fact.first == "pair" ? i18n::T(i18n::Str::kPairHint) : label(fact.first), value);
    }
    visible = redraw = true; drawn_percent=-1; hold.Reset(); buttons.ArmReleaseGate();
  }
  Approval decision() override { return answer; }
  void clear() override { visible = false; pairing = false; lines.clear(); hold.Reset(); answer = {};pin.clear();entering_pin=false; }
  void automatically_approved(const Review&) override { sound::Notify(false,::millis()); }
  void draw() {
    Display::FillScreen(color::kBlack);
    if(entering_pin) {
      ui::DrawHeader(i18n::T(i18n::Str::kLockTitle),nullptr);
      const auto hidden=std::string(pin.entered(),'*')+"_"+std::string(pin.required()-pin.entered()-1,'_');
      Display::DrawText(FontRole::kSmall,12,70,hidden.data(),hidden.size(),color::kWhite,color::kBlack);
      const char digit=char('0'+pin.digit());
      Display::DrawText(FontRole::kSmall,150,112,&digit,1,color::kYellow,color::kBlack);
      ui::DrawFooter(i18n::T(i18n::Str::kBtnLess),i18n::T(i18n::Str::kBtnEnter),i18n::T(i18n::Str::kBtnMore2));
      redraw=false;return;
    }
    ui::DrawHeader(i18n::T(pairing ? i18n::Str::kPairTitle : i18n::Str::kVlpReview), nullptr);
    for (size_t i = 0; i < 6 && position + i < lines.size(); ++i) {
      const auto& line = lines[position + i];
      Display::DrawText(FontRole::kSmall, 6, 36 + int(i) * 23, line.data(), line.size(), color::kWhite, color::kBlack);
    }
    if (review.can_raise) {
      auto value = std::string(i18n::T(i18n::Str::kVlpRaise)) + ": " + (raise ? std::to_string(raised) + " A-/C+" : "-");
      Display::DrawText(FontRole::kSmall, 6, 176, value.data(), value.size(), color::kYellow, color::kBlack);
    }
    if(review.can_remember){
      const char *mode=i18n::T(remember?i18n::Str::kVlpDecisionSession:i18n::Str::kVlpDecisionOnce);
      Display::DrawText(FontRole::kSmall,6,176,mode,strlen(mode),color::kYellow,color::kBlack);
    }
    ui::DrawFooter(i18n::T(i18n::Str::kVlpDenyScroll), i18n::T(review.can_remember?i18n::Str::kVlpDecisionToggle:i18n::Str::kBtnHoldConfirm), i18n::T(i18n::Str::kBtnScrollNext));
    // 页脚已显示长按提示；进度放在其上方，不能被页脚覆盖。
    draw_progress(hold.Percent(::millis()));
    redraw = false;
  }
  void draw_progress(uint8_t percent) {
    Display::DrawProgress(Rect{6,198,308,8},percent,color::kYellow,color::kBlack);
    drawn_percent=percent;
  }
};
} // namespace rockey::vlp
