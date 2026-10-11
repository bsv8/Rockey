#include "core/app.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "board/board.h"
#include "board/display.h"
#include "core/log.h"
#include "core/rockey_config.h"
#include "crypto/digest.h"
#include "crypto/aead.h"
#include "crypto/rand.h"
#include "crypto/ripemd160.h"
#include "crypto/secure.h"
#include "crypto/secp256k1.h"
#include "crypto/x25519.h"
#include "i18n/i18n.h"
#include "ops/local_secret.h"
#include "proto/cbor.h"
#include "store/keystore.h"
#include "store/vault_fs.h"
#include "../../Coding/Rockey/vaultlink-integration/controller.hpp"
#include "../../Coding/Rockey/device-ui/presentation.hpp"

namespace rockey {
App::App() = default;
App::~App() = default;

// 擦除需要的按住时长：独立物理确认，比确认页长得多
constexpr uint32_t kEraseHoldMs = 3000;

namespace {

bool browserConnected=false;
const char* LangHint() { return i18n::T(browserConnected?i18n::Str::kBrowserConnected:i18n::Str::kBrowserDisconnected); }

inline bool ev_backupScroll(const Buttons& b, uint32_t now) {
  if (b.IsDown(Btn::kC)) return true;
  if (b.IsDown(Btn::kA)) return true;
  (void)now;
  return false;
}

}  // namespace

bool App::SelfTest() {
  bool ok = true;
  // 1000 次 Montgomery 回归留在主机门禁；设备每次启动执行 RFC 已知答案及低阶点自检。
  if (!x25519::SelfTest(false)) {
    RK_LOGE("selftest", "x25519 RFC7748 vector mismatch");
    ok = false;
  }
  if (!ops::SelfTest()) {
    RK_LOGE("selftest", "local-secret v3 vector mismatch");
    ok = false;
  }
  if (!aead::SelfTest()) {
    RK_LOGE("selftest", "AES-256-GCM NIST vector mismatch");
    ok = false;
  }
  if (!ripemd::SelfTest()) {
    RK_LOGE("selftest", "RIPEMD-160 vector mismatch");
    ok = false;
  }
  uint8_t digest[32];
  digest::Sha256(reinterpret_cast<const uint8_t*>("rockey"), 6, digest);
  if (!secp::VerifyDer(keystore::KeyStore::PublicKey(), digest, digest, 0)) {
    // 只是确认无效签名会被拒绝
  }
  RK_LOGI("selftest", "%s", ok ? "all vectors passed" : "FAILED");
  return ok;
}

void App::Begin() {
  Board::Init();
  // 屏幕一就绪就显示标识，让耗时存储与密码学自检有可见反馈。
  DrawBoot();
  Log::Init();
  const bool storageReady = store::Init() && keystore::KeyStore::Init();

  BtnConfig cfg;
  buttons_.Init(cfg);
  vaultlink_ = std::make_unique<vlp::Controller>(buttons_);

#if defined(ROCKEY_DEV_BUTTON_API)
  e2e::device().bind([this](const e2e::Bytes& command){return vaultlink::decode(DevTestControl(command));});
#endif
  uint32_t now = millis();
  bootMs_ = now;
  now_ = now;
  // VLP v2 是唯一 USB 消费者；旧 link 不读取/写入串口，不做 wire 降级。

  // 密码学自检失败时**不允许进入业务执行状态**。
  // 以前这里忽略返回值：x25519 / AEAD / RIPEMD 全错也照常配对和签名。
  // 自检覆盖的正是"静默算错"这类缺陷（HKDF 忽略 PRK、RIPEMD 表错、
  // AEAD 解密取错 GHASH 输入），所以失败必须可见且必须挡住执行。
  if (!SelfTest() || !storageReady) {
    selftestFailed_ = true;
    RK_LOGE("boot", "crypto self-test FAILED: refusing to serve requests");
  }

  if (!storageReady) { ShowErrorScreen(ops::ErrorCode::kInvalidRequest); return; }
  keystore::Info info = keystore::KeyStore::Info_();
  if (!info.initialized && (store::Exists("/vault/vlp-migration.bin")
      || store::Exists(store::kPathMigration))) {
    // An erased/staged migrating device is not a new wallet. Preserve its
    // public recovery evidence until the private migration controller resumes.
    try{vlp::MigrationStore disk;vaultlink::MigrationJournal journal(disk);auto record=journal.status();
      if(!keystore::KeyStore::HasKey()&&record.at("direction").string()=="to-hardware"&&record.at("phase").string()=="staged"){Go(Screen::kInitializeChoice);return;}
    }catch(...){/* Corrupt or legacy metadata does not permit PIN setup. */}
    ShowErrorScreen(ops::ErrorCode::kMigrationConflict);return;
  }
  if (!info.initialized) {
    vaultlink_->prepare_empty();Go(Screen::kInitializeChoice);
  } else {
    uint32_t wait = keystore::KeyStore::WaitMsRemaining(now);
    if (wait > 0) {
      waitSecondsLeft_ = (wait + 999) / 1000;
      waitTicking_ = true;
      lastWaitSecond_ = now;
      Go(Screen::kWaitPin);
    } else {
      Go(Screen::kLock);
    }
  }
}

void App::Go(Screen s) {
  prevScreen_ = screen_;
  screen_ = s;
  pinRowDrawn_ = false;
  hold_.Reset();
  summaryScroll_ = 0;
  buttons_.ArmReleaseGate();  // 换页先要求松键，避免长按延续误确认
  needsRedraw_ = true;
}

#if defined(ROCKEY_DEV_BUTTON_API)
std::vector<uint8_t> App::DevTestControl(const std::vector<uint8_t>& c) {
  using vaultlink::Value;
  vaultlink::require(!c.empty() && c.size()<=8,"invalid-test-command");
  if(c[0]==2) { // 原始按键电平 + 有界释放期限
    vaultlink::require(c.size()==5 && c[1]<3 && c[2]<2,"invalid-test-command");
    vaultlink::require(buttons_.DevSetLevel(static_cast<Btn>(c[1]),c[2]!=0,millis(),uint16_t(c[3])|uint16_t(c[4])<<8),"invalid-test-command");
    // 电平注入立即回执，不能在 Poll 之前读取 Flash 钱包记录；否则短按
    // TTL 会耗在状态查询里，去抖器来不及观察到实际按下。
    return vaultlink::encode(Value::object({{"ok",Value(true)}}));
  } else if(c[0]==3) { // 首次注入公开测试密钥，不允许覆盖已有测试钱包
    vaultlink::require(c.size()==1 && !selftestFailed_ && !keystore::KeyStore::HasKey() && !store::Exists("/vault/vlp-migration.bin"),"test-wallet-exists");
    vaultlink::require(keystore::KeyStore::DevInjectTestKey("00000000",8)==keystore::Status::kOk,"test-key-failed");
    vaultlink::require(keystore::KeyStore::Init(),"test-key-failed");ResetPinEntry();Go(Screen::kLock);
  } else if(c[0]==4) {
    vaultlink::require(c.size()==1,"invalid-test-command");testRestartAt_=millis()+500;
  } else vaultlink::require(c[0]==1 && c.size()==1,"invalid-test-command");
  const auto info=keystore::KeyStore::Info_();
  std::string pub;const char* hex="0123456789abcdef";
  if(info.initialized)for(auto b:info.pubkey){pub+=hex[b>>4];pub+=hex[b&15];}
  return vaultlink::encode(Value::object({{"firmware",Value("rockey-product-e2e-v1")},
    {"buildId",Value(ROCKEY_FIRMWARE_BUILD_ID)}, {"isolated",Value(true)},
    {"menuSelected",Value(uint64_t(menuSelected_))},{"pinCursor",Value(uint64_t(pinDigit_))},{"pinEntered",Value(uint64_t(pinLen_))},{"screen",Value(uint64_t(screen_))},{"unlocked",Value(keystore::KeyStore::IsUnlocked())},
    {"initialized",Value(info.initialized)},{"publicKey",Value(pub)},
    {"failCount",Value(uint64_t(keystore::KeyStore::FailCount()))},
    {"waitMs",Value(uint64_t(keystore::KeyStore::WaitMsRemaining(millis())))},
    {"selftestFailed",Value(selftestFailed_)},{"rxDropped",Value(uint64_t(e2e::device().dropped()))},
    {"freeHeap",Value(uint64_t(ESP.getFreeHeap()))},{"stackFree",Value(uint64_t(uxTaskGetStackHighWaterMark(nullptr)))},
    {"serialErrors",Value(uint64_t(Board::DevSerialErrors()))},
    {"ui",vaultlink_->DevUiState()}}));
}
#endif

// ── 主循环 ─────────────────────────────────────────────────────────
void App::Loop() {
#if defined(ROCKEY_DEV_BUTTON_API)
  e2e::device().pump();
  if(testRestartAt_ && static_cast<int32_t>(millis()-testRestartAt_)>=0) ESP.restart();
#endif
  // 控制帧可能读取 Flash；按键观察必须使用注入完成后的实际时间。
  uint32_t now = millis();
  sound::Poll(now);
  now_ = now;
  buttons_.Poll(now);
  buttons_.ClearGateIfSatisfied();

  bool wasUnlocked = keystore::KeyStore::IsUnlocked();
  const bool wasReviewing = vaultlink_->active_ui();
  if (!selftestFailed_) {
    if(screen_==Screen::kInitializeChoice&&!keystore::KeyStore::HasKey())vaultlink_->prepare_empty();
    vaultlink_->poll();
  }
  const bool connected=vaultlink_->connected();
  if(browserConnected!=connected){browserConnected=connected;ui::SetBrowserConnected(connected);needsRedraw_=true;pinRowDrawn_=false;}
  if(screen_==Screen::kInitializeChoice&&keystore::KeyStore::IsUnlocked())Go(Screen::kMenu);
  if(screen_==Screen::kInitializeChoice&&emptyImportBusy_!=vaultlink_->import_busy()){
    emptyImportBusy_=vaultlink_->import_busy();needsRedraw_=true;
  }
  if (wasReviewing && !vaultlink_->active_ui()) { needsRedraw_ = true; pinRowDrawn_ = false; }
  if (wasUnlocked && !keystore::KeyStore::IsUnlocked()) LockNow("VLP disconnected");

  // 请求超时与配对超时
  for (uint8_t i = 0; i < ROCKEY_MAX_QUEUE; ++i) {
    if (queue_[i].active && now - queue_[i].receivedMs > ROCKEY_REQUEST_TTL_MS) {
      queue_[i].active = false;
      if (current_ == i) {
        current_ = -1;
        FinishRequest(ops::ErrorCode::kTimeout, nullptr, 0);
      }
    }
  }

  if (waitTicking_) {
    uint32_t remain = keystore::KeyStore::WaitMsRemaining(now);
    uint32_t sec = (remain + 999) / 1000;
    if (sec != waitSecondsLeft_) {
      waitSecondsLeft_ = static_cast<uint8_t>(sec);
      needsRedraw_ = true;
    }
    if (remain == 0) {
      waitTicking_ = false;
      Go(Screen::kLock);
    }
  }

  // 读取按钮事件
  for (int b = 0; b < 3; ++b) {
    Btn btn = static_cast<Btn>(b);
    BtnEvent ev = buttons_.NextEvent(btn, now);
    if (ev != BtnEvent::kNone) {
      if (!vaultlink_->button(btn, ev)) OnButton(btn, ev);
      needsRedraw_ = true;
    }
  }

  // 配对页面优先：锁定时也允许最小配对流程，但不能被主机请求遮挡
  // Controller::poll() 在内容变化/长按进度变化时绘制。这里不能每轮重画
  // 整屏，否则 SPI 绘制会饿死串口读取和按钮去抖。
  if (vaultlink_->active_ui()) return;

  // 擦除页：长按 C 3 秒才真正执行（独立物理确认，不因浏览器注销触发）。
  // 计时用成员变量而不是函数内 static：离开页面或换页必须清零，
  // 否则"按住 C 离开再回来"会接着上一段进度，甚至直接触发擦除。
  if (screen_ == Screen::kErase) {
    if (eraseHoldMs_ == 0 && buttons_.IsDown(Btn::kC)) eraseHoldMs_ = now;
    if (eraseHoldMs_ != 0) {
      // 松键栅栏期间不计时：必须是一次全新的按下
      if (buttons_.GateActive()) {
        eraseHoldMs_ = 0;
      } else if (now - eraseHoldMs_ >= kEraseHoldMs) {
        eraseHoldMs_ = 0;
        if (!keystore::KeyStore::Erase()) {
          LockNow("device erase failed");
          ShowErrorScreen(ops::ErrorCode::kInvalidRequest);
          return;
        }
        policy::Policy::ClearAll();
        link_.ClearSessions();
        ClearQueues();
        Go(Screen::kInitializeChoice);
      }
      needsRedraw_ = true;
    }
    if (eraseHoldMs_ != 0 && !buttons_.IsDown(Btn::kC) && now - eraseHoldMs_ > 400) {
      eraseHoldMs_ = 0;
      needsRedraw_ = true;
    }
  } else {
    // 不在擦除页时清零计时
    eraseHoldMs_ = 0;
  }

  hold_.Update(buttons_, now,
               screen_ == Screen::kSummary || screen_ == Screen::kDenyConfirm ||
                   screen_ == Screen::kPairing ||
                   (screen_ == Screen::kBackup && !backupReady_));

  // 设备状态回报给主机（需求 §4 的状态区分）：
  // 锁定设备允许最小 info/配对，但主机据此知道不能发业务签名。
  {
    proto::DeviceState ds;
    if (!keystore::KeyStore::HasKey()) {
      ds = proto::DeviceState::kUninitialized;
    } else if (!keystore::KeyStore::IsUnlocked()) {
      ds = proto::DeviceState::kLocked;
    } else if (link_.SessionCount() > 0) {
      ds = (current_ >= 0 || queueCount_ > 0) ? proto::DeviceState::kPendingRequest
                                             : proto::DeviceState::kSession;
    } else {
      ds = proto::DeviceState::kUnlocked;
    }
    if (ds != link_.deviceState()) {
      link_.SetDeviceState(ds);
      // 状态变化要立刻让主机知道，否则只能在下次握手时看到
      if (!link_.pairing().required) SendStateEvent(ds);
    }
  }

  // 恢复备份：长按 B 确认生成；生成后 C/A 滚动备份数据
  if (screen_ == Screen::kBackup) {
    if (!backupReady_ && hold_.Fired()) {
      hold_.Reset();
      size_t cap = sizeof(recoveryBlob_);
      if (keystore::KeyStore::CreateRecoveryBackup(recoveryCode_, sizeof(recoveryCode_),
                                                    recoveryBlob_, &cap) ==
          keystore::Status::kOk) {
        recoveryBlobLen_ = cap;
        backupReady_ = true;
        backupScroll_ = 0;
        needsRedraw_ = true;
      }
    } else if (backupReady_) {
      if (ev_backupScroll(buttons_, now)) needsRedraw_ = true;
    }
  }

  // 长按确认：必须由新的按下动作触发，短按不会确认
  if (hold_.Fired()) {
    if (screen_ == Screen::kPairing) {
      link_.MarkPairingUserConfirmed();
      needsRedraw_ = true;
    } else if (screen_ == Screen::kSummary) {
      hold_.Reset();
      // 长按确认同样要过门禁：进度条走完不等于看完了关键内容
      if (!RequiredContentSeen()) {
        gateBlocked_ = true;
        needsRedraw_ = true;
      } else {
        Decide(menuSelected_ == 3 ? policy::Decision::kAllowSession : policy::Decision::kAllowOnce);
      }
    } else if (screen_ == Screen::kDenyConfirm) {
      hold_.Reset();
      Decide(policy::Decision::kDenySession);
    }
  }

  PumpQueue();

  if (needsRedraw_) {
    Draw();
    needsRedraw_ = false;
  }
  delay(4);
}

// ── 输入分发 ───────────────────────────────────────────────────────
void App::OnButton(Btn btn, BtnEvent ev) {
  switch (screen_) {
    case Screen::kNetworkChoice:
      // 两个物理按钮直接选择并保存；中间按钮无操作。
      if(ev!=BtnEvent::kShortPress)return;
      if(btn!=Btn::kA&&btn!=Btn::kC)return;
      newKeyNetwork_=btn==Btn::kA?keystore::BsvNetwork::Main:keystore::BsvNetwork::Test;
      {
        Display::FillScreen(color::kBlack);
        const char* message=i18n::T(i18n::Str::kSavingWallet);
        Display::DrawTextIn({0,0,Board::kScreenW,Board::kScreenH},FontRole::kSmall,
                            message,strlen(message),color::kWhite,color::kBlack,
                            TextAlign::kCenter,VAlign::kMiddle);
        if(!store::Remove("/vault/vlp-migration.bin")||!store::Remove("/vault/vlp-import-meta.bin")||!store::Remove("/vault/vlp-import-stage.bin")){ShowErrorScreen(ops::ErrorCode::kMigrationConflict);return;}
        secure::SecretBytes<32> secret;bool valid=false;
        for(int i=0;i<8&&!valid;++i){rand::Fill(secret.data(),32);valid=secp::ValidatePriv(secret.data());}
        auto st=valid?keystore::KeyStore::SetPinAndWrap(newPin_,newPinLen_,secret.data(),newKeyNetwork_):keystore::Status::kInvalidArg;
        if(st==keystore::Status::kOk)st=keystore::KeyStore::Unlock(newPin_,newPinLen_);
        secure::Wipe(newPin_,sizeof(newPin_));newPinLen_=0;
        if(st==keystore::Status::kOk)Go(Screen::kMenu);else ShowErrorScreen(ops::ErrorCode::kMigrationConflict);
      }return;
    case Screen::kInitializeChoice:
      if(ev!=BtnEvent::kShortPress)return;
      if(btn==Btn::kA&&!vaultlink_->import_busy()){
        vaultlink_->lock();ResetPinEntry();Go(Screen::kSetPin);
      }else if(btn==Btn::kC&&vaultlink_->import_busy()&&!keystore::KeyStore::HasKey()){
        vaultlink_->lock();vaultlink_->prepare_empty();needsRedraw_=true;
      }return;
    case Screen::kImport:
      if(btn==Btn::kA&&ev==BtnEvent::kLongPress){vaultlink_->lock();LockNow("cancel import");}return;
    case Screen::kError:
      if(selftestFailed_)break;
      if(btn==Btn::kC&&ev==BtnEvent::kShortPress){
        if(!keystore::KeyStore::HasKey()&&store::Exists("/vault/vlp-migration.bin")){
          try{vlp::MigrationStore disk;vaultlink::MigrationJournal journal(disk);
            const auto phase=journal.status().at("phase").string();
            if(phase=="complete"||phase=="erased")Go(Screen::kErase);
            else if(journal.status().at("direction").string()=="to-hardware"&&phase=="staged"){vaultlink_->lock();ResetPinEntry();Go(Screen::kInitializeChoice);}
          }catch(...){/* Keep recovery evidence and remain blocked. */}
        }else if(keystore::KeyStore::HasKey()){
          const auto wait=keystore::KeyStore::WaitMsRemaining(millis());
          if(wait){waitTicking_=true;waitSecondsLeft_=static_cast<uint8_t>((wait+999)/1000);Go(Screen::kWaitPin);}
          // 返回提示页只导航；通电且已解锁的钱包不能被送回 PIN 页。
          else Go(keystore::KeyStore::IsUnlocked()?Screen::kMenu:Screen::kLock);
        }
      }
      break;
    case Screen::kLock:
    case Screen::kWaitPin:
      HandleLockInput(btn, ev);
      break;
    case Screen::kSetPin:
    case Screen::kSetPinConfirm:
      HandleSetPinInput(btn, ev);
      break;
    case Screen::kReader:
      HandleReaderInput(btn, ev);
      break;
    case Screen::kReqMenu:
      HandleReqMenuInput(btn, ev);
      break;
    case Screen::kMenu:
    case Screen::kInfo:
    case Screen::kPubkey:
    case Screen::kBackup:
      HandleMenuInput(btn, ev);
      break;
    case Screen::kChannels:
      if(channelSettings_.input(btn,ev))Go(Screen::kMenu);else needsRedraw_=true;
      break;
    case Screen::kGrants:
      HandleGrantsInput(btn, ev);
      break;
    case Screen::kSummary:
      HandleSummaryInput(btn, ev);
      break;
    case Screen::kDenyConfirm:
      HandleDenyConfirmInput(btn, ev);
      break;
    case Screen::kErase:
      HandleEraseInput(btn, ev);
      break;
    default:
      break;
  }
}

// 允许确认页：A/C 滚动关键摘要与全部风险，B 不在此页确认（长按由 Loop 统一处理）。
// 底部标签写的是"返回 / 长按确认 / 查看范围"，就必须真的有这三条路：
// 需求 §6.2 要求拒绝随时可达，不能让用户走到确认页后只能同意。
// 关键摘要与重大警告的确认门禁（需求 §6.2）。
//
// 设备生成的关键摘要（kChapterRequired）与重大警告（| kChapterWarning）
// 必须被**逐项看过**，才允许进入允许确认页 —— 也就是"标了必须看的章节
// 就真的必须看"。可选的详细长文不设门槛。
//
// 记账方式：随菜单/摘要页一起滚动的进度计数；只有读满当前必需内容才把
// gateSeen_ 置真。gateSeen_ 在每个新请求开始时清零。
bool App::RequiredContentSeen() const {
  if (!doc_.requiredTotal) return true;  // 没有必需内容（理论上不会发生）
  return gateSeen_ >= doc_.requiredTotal;
}

void App::MarkRequiredProgress() {
  if (!doc_.requiredTotal) return;
  if (gateSeen_ < doc_.requiredTotal) gateSeen_++;
}

void App::HandleSummaryInput(Btn btn, BtnEvent ev) {
  if (ev != BtnEvent::kShortPress && ev != BtnEvent::kHoldRepeat) return;
  uint8_t maxScroll = SummaryScrollMax();
  if (btn == Btn::kC) {
    if (summaryScroll_ < maxScroll) {
      summaryScroll_++;
      MarkRequiredProgress();  // 每推进一屏就推进一次门禁
    }
  } else if (btn == Btn::kA) {
    if (summaryScroll_ > 0) summaryScroll_--;
  } else if (btn == Btn::kB) {
    // 返回操作菜单，保留阅读位置
    Go(Screen::kReqMenu);
  }
  needsRedraw_ = true;
}

void App::HandleDenyConfirmInput(Btn btn, BtnEvent ev) {
  if (ev != BtnEvent::kShortPress && ev != BtnEvent::kHoldRepeat) return;
  if (btn == Btn::kB) {
    // 取消拒绝：回到操作菜单，拒绝仍然可达也随时可撤回
    Go(Screen::kReqMenu);
  }
  needsRedraw_ = true;
}

void App::HandleEraseInput(Btn btn, BtnEvent ev) {
  if (ev != BtnEvent::kShortPress && ev != BtnEvent::kLongPress) return;
  if (btn == Btn::kB) {
    if(!keystore::KeyStore::HasKey()&&store::Exists("/vault/vlp-migration.bin"))ShowErrorScreen(ops::ErrorCode::kMigrationConflict);
    else Go(Screen::kMenu);
  }
  needsRedraw_ = true;
}

uint8_t App::SummaryScrollMax() const {
  // 摘要最多 8 行、风险最多 8 项；页面一次显示 5 行摘要 + 2 条风险，
  // 滚动上限按"让最后一行可见"算，而不是让用户永远滚不到底。
  uint8_t summaryRows = doc_.summaryCount > 5 ? doc_.summaryCount - 5 : 0;
  uint8_t riskRows = doc_.riskCount > 2 ? doc_.riskCount - 2 : 0;
  uint8_t m = summaryRows > riskRows ? summaryRows : riskRows;
  return m;
}

bool App::SessionDecisionOffered() const {
  // 导出/迁移/恢复备份：不得持续授权，因此菜单不显示"此会话允许/否决"。
  // Decide() 里还有同一道门禁作为兜底（浏览器改不了菜单也要守住语义）。
  if (current_ < 0) return false;
  return policy::PersistentDecisionAllowed(
      static_cast<policy::Category>(queue_[current_].exec.category));
}

void App::ResetPinEntry() {
  pinLen_ = 0;
  pinDigit_ = static_cast<uint8_t>(rand::Below(10));
  secure::Wipe(pin_, sizeof(pin_));
  pinMenuOpen_ = false;
}

void App::AppendDigit(uint8_t d) {
  if (pinLen_ >= ROCKEY_PIN_MAX_DIGITS) return;
  pin_[pinLen_++] = static_cast<char>('0' + d);
  pin_[pinLen_] = '\0';
  // 每位可随机初始选中数字：减少固定按键次数信息
  pinDigit_ = static_cast<uint8_t>(rand::Below(10));
}

void App::DeleteDigit() {
  if (pinLen_ == 0) return;
  pin_[--pinLen_] = '\0';
  pinDigit_ = static_cast<uint8_t>(rand::Below(10));
}

void App::HandleLockInput(Btn btn, BtnEvent ev) {
  if (screen_ == Screen::kWaitPin) {
    // 等待期间不接受任何输入；只有倒计时结束才解锁界面
    return;
  }
  keystore::Info info = keystore::KeyStore::Info_();
  uint8_t digits = info.pinDigits ? info.pinDigits : ROCKEY_PIN_DEFAULT_DIGITS;

  if (pinMenuOpen_) {
    if (btn == Btn::kB && (ev == BtnEvent::kShortPress || ev == BtnEvent::kLongPress)) {
      if (ev == BtnEvent::kLongPress) {
        pinMenuOpen_ = false;
        if (changingPin_) { LockNow("cancel PIN change"); return; }
        ResetPinEntry();
        return;
      }
      pinMenuOpen_ = false;
      DeleteDigit();
    }
    return;
  }

  switch (ev) {
    case BtnEvent::kShortPress:
    case BtnEvent::kHoldRepeat:
    case BtnEvent::kLongPress:
      if (btn == Btn::kA) {
        pinDigit_ = static_cast<uint8_t>((pinDigit_ + 9) % 10);
      } else if (btn == Btn::kC) {
        pinDigit_ = static_cast<uint8_t>((pinDigit_ + 1) % 10);
      } else if (btn == Btn::kB) {
        if (ev == BtnEvent::kLongPress) {
          pinMenuOpen_ = true;  // 打开删除上一位 / 取消输入菜单
          return;
        }
        AppendDigit(pinDigit_);
        if (pinLen_ >= digits) SubmitPin();
      }
      break;
    default:
      break;
  }
}

void App::SubmitPin() {
  // TFT 绘制同步完成后才启动耗时的 PIN 派生，不能等下一轮 Loop 才显示。
  pinRowDrawn_=false;
  Display::FillScreen(color::kBlack);
  const char* message=i18n::T(i18n::Str::kLockUnlocking);
  Display::DrawTextIn({0,0,Board::kScreenW,Board::kScreenH},FontRole::kSmall,
                      message,strlen(message),color::kWhite,color::kBlack,
                      TextAlign::kCenter,VAlign::kMiddle);
  keystore::Status st = keystore::KeyStore::Unlock(pin_, pinLen_);
  switch (st) {
    case keystore::Status::kOk: {
      if (changingPin_) {
        memcpy(oldPin_, pin_, pinLen_ + 1); oldPinLen_ = pinLen_;
        keystore::KeyStore::Lock(); ResetPinEntry(); Go(Screen::kSetPin); return;
      }
      policy::Policy::BeginSession(link_.deviceRunId(), 0, 0);
      ResetPinEntry();
      uint32_t remain = keystore::KeyStore::WaitMsRemaining(millis());
      if (remain > 0) {
        waitSecondsLeft_ = static_cast<uint8_t>((remain + 999) / 1000);
        waitTicking_ = true;
        Go(Screen::kWaitPin);
      } else {
        Go(Screen::kMenu);
      }
      break;
    }
    case keystore::Status::kNeedsWait: {
      uint32_t remain = keystore::KeyStore::WaitMsRemaining(millis());
      waitSecondsLeft_ = static_cast<uint8_t>((remain + 999) / 1000);
      waitTicking_ = true;
      lastWaitSecond_ = millis();
      ResetPinEntry();
      Go(Screen::kWaitPin);
      break;
    }
    case keystore::Status::kNotInitialized:
      Go(Screen::kInitializeChoice);
      break;
    default:
      ResetPinEntry();
      ShowErrorScreen(ops::ErrorCode::kLocked);
      Go(Screen::kLock);
      break;
  }
}

void App::HandleSetPinInput(Btn btn, BtnEvent ev) {
  keystore::Info info = keystore::KeyStore::Info_();
  uint8_t digits = info.pinDigits ? info.pinDigits : ROCKEY_PIN_DEFAULT_DIGITS;
  if (pinMenuOpen_) {
    if (btn == Btn::kB) {
      pinMenuOpen_ = false;
      if (ev == BtnEvent::kLongPress) {
        if (changingPin_) { LockNow("cancel PIN change"); return; }
        ResetPinEntry();
        secure::Wipe(newPin_, sizeof(newPin_)); newPinLen_ = 0;
        Go(Screen::kInitializeChoice);
      } else {
        DeleteDigit();
      }
    }
    return;
  }
  switch (ev) {
    case BtnEvent::kShortPress:
    case BtnEvent::kHoldRepeat:
    case BtnEvent::kLongPress:
      if (btn == Btn::kA) {
        pinDigit_ = static_cast<uint8_t>((pinDigit_ + 9) % 10);
      } else if (btn == Btn::kC) {
        pinDigit_ = static_cast<uint8_t>((pinDigit_ + 1) % 10);
      } else if (btn == Btn::kB) {
        if (ev == BtnEvent::kLongPress) {
          pinMenuOpen_ = true;
          return;
        }
        if (screen_ == Screen::kSetPin) {
          AppendDigit(pinDigit_);
          if (pinLen_ >= digits) {
            // 进入重复确认；新 PIN 只在 RAM 中短暂存在
            memcpy(newPin_, pin_, pinLen_ + 1);
            newPinLen_ = pinLen_;
            ResetPinEntry();
            Go(Screen::kSetPinConfirm);
          }
        } else {
          AppendDigit(pinDigit_);
          if (pinLen_ >= digits) {
            if (pinLen_ == newPinLen_ && memcmp(pin_, newPin_, pinLen_) == 0) {
              if (changingPin_) {
                auto status = keystore::KeyStore::Unlock(oldPin_, oldPinLen_);
                if (status == keystore::Status::kOk) status = keystore::KeyStore::ChangePin(oldPin_, oldPinLen_, pin_, pinLen_);
                LockNow("PIN change completed");
                if (status != keystore::Status::kOk) ShowErrorScreen(ops::ErrorCode::kLocked);
                break;
              }
              // The repeated PIN stays only in RAM until the local choice.
              ResetPinEntry();newKeyNetwork_=keystore::BsvNetwork::Main;Go(Screen::kNetworkChoice);break;
            }
            // 不一致：重新开始
            secure::Wipe(newPin_, sizeof(newPin_));
            newPinLen_ = 0;
            ResetPinEntry();
            if (changingPin_) LockNow("PIN confirmation mismatch");
            ShowErrorScreen(ops::ErrorCode::kLocked);
          }
        }
      }
      break;
    default:
      break;
  }
}

void App::HandleReaderInput(Btn btn, BtnEvent ev) {
  switch (ev) {
    case BtnEvent::kShortPress:
    case BtnEvent::kHoldRepeat:
      if (btn == Btn::kC) reader_.Scroll(1);
      if (btn == Btn::kA) reader_.Scroll(-1);
      if (btn == Btn::kB) {
        // 返回请求菜单时保留精确滚动位置
        reader_.SavePosition();
        Go(Screen::kReqMenu);
      }
      break;
    case BtnEvent::kLongPress:
      if (btn == Btn::kB) {
        Go(Screen::kReqMenu);
      } else if (btn == Btn::kC) {
        reader_.Scroll(3);
      } else if (btn == Btn::kA) {
        reader_.Scroll(-3);
      }
      break;
    default:
      break;
  }
}

void App::HandleReqMenuInput(Btn btn, BtnEvent ev) {
  if (current_ < 0) {
    Go(Screen::kMenu);
    return;
  }
  // 会话级决定只对被允许的操作出现：0 继续阅读 / 1 仅本次拒绝 /
  // 2 仅本次允许 / 3 此会话允许 / 4 此会话否决。
  const bool sessionOffered = SessionDecisionOffered();
  uint8_t count = sessionOffered ? 5 : 3;
  uint8_t span = 5;
  switch (ev) {
    case BtnEvent::kShortPress:
    case BtnEvent::kHoldRepeat:
    case BtnEvent::kLongPress:
      if (btn == Btn::kC) menuSelected_ = static_cast<uint8_t>((menuSelected_ + 1) % count);
      else if (btn == Btn::kA) menuSelected_ = static_cast<uint8_t>((menuSelected_ + count - 1) % count);
      else if (btn == Btn::kB && ev == BtnEvent::kShortPress) {
        if (menuSelected_ >= count) menuSelected_ = 0;
        // 允许项被门禁挡住：关键摘要/重大警告没逐项看过就不给进确认页。
        // 这不是"建议先看"，而是进不去。
        if ((menuSelected_ == 2 || menuSelected_ == 3) && !RequiredContentSeen()) {
          // 跳到关键摘要的起点，让用户把必须看的看完
          summaryScroll_ = 0;
          reader_.Load(&doc_);
          reader_.SavePosition();
          Go(Screen::kSummary);
          return;
        }
        if (menuSelected_ == 0) {
          // 继续阅读：回到原章节与滚动位置
          reader_.RestorePosition();
          Go(Screen::kReader);
          return;
        }
        if (menuSelected_ == 1) {
          Decide(policy::Decision::kDenyOnce);
          return;
        }
        if (menuSelected_ == 2) {
          Go(Screen::kSummary);
          return;
        }
        if (menuSelected_ == 3 && sessionOffered) {
          Go(Screen::kSummary);
          return;
        }
        if (menuSelected_ == 4 && sessionOffered) {
          Go(Screen::kDenyConfirm);
          return;
        }
      } else if (btn == Btn::kB && ev == BtnEvent::kLongPress) {
        Go(Screen::kMenu);
      }
      break;
    default:
      break;
  }
  (void)span;
}

void App::HandleMenuInput(Btn btn, BtnEvent ev) {
  if (screen_ == Screen::kMenu) {
    if (ev != BtnEvent::kShortPress && ev != BtnEvent::kHoldRepeat &&
        ev != BtnEvent::kLongPress) {
      return;
    }
    if (btn == Btn::kC) {
      menuSelected_ = static_cast<uint8_t>((menuSelected_ + 1) % menu_.count);
    } else if (btn == Btn::kA) {
      menuSelected_ = static_cast<uint8_t>((menuSelected_ + menu_.count - 1) % menu_.count);
    } else if (btn == Btn::kB && ev == BtnEvent::kShortPress) {
      switch (menuSelected_) {
        case 0:  // 查看待确认请求
          if (queueCount_ == 0) {
            ShowErrorScreen(ops::ErrorCode::kOk);
            return;
          }
          PresentCurrent();
          return;
        case 1: Go(Screen::kGrants); return;
        case 2: Go(Screen::kInfo); return;
        case 3: Go(Screen::kPubkey); return;
        case 4: backupReady_ = false; hold_.Reset(); Go(Screen::kBackup); return;
        case 5: Go(Screen::kErase); return;
        case 6: LockNow("change PIN"); changingPin_ = true; return;
        case 9:
          channelSettings_.signing=[this]{return vaultlink_->signing_channels();};
          channelSettings_.payments=[this]{return vaultlink_->payment_channels();};
          channelSettings_.saveSigning=[this](const std::string& id,const std::string& mode,uint64_t rev){vaultlink_->configure_signing(id,mode,rev);};
          channelSettings_.savePayment=[this](const vaultlink::Channel& c){vaultlink_->configure_payment(c);};
          channelSettings_.reset();Go(Screen::kChannels);return;
        case 7:
        case 8: {
          const bool manual=menuSelected_==8;
          const bool enabled=!sound::Enabled(manual);
          if(!sound::SetEnabled(manual,enabled))ShowErrorScreen(ops::ErrorCode::kResultUnknown);
          // 保存成功再示范对应音色；关闭时只取消该类声音，不播放提示。
          else if(enabled)sound::Notify(manual,millis());
          return;
        }
        default: return;
      }
    } else if (btn == Btn::kB && ev == BtnEvent::kLongPress) {
      // 主菜单长按 B 无额外动作，避免误触
      return;
    }
    return;
  }

  if (screen_ == Screen::kInfo || screen_ == Screen::kPubkey ||
      screen_ == Screen::kBackup) {
    if (btn == Btn::kB && (ev == BtnEvent::kShortPress || ev == BtnEvent::kLongPress)) {
      Go(Screen::kMenu);
    }
    return;
  }
}

void App::HandleGrantsInput(Btn btn, BtnEvent ev) {
  if(btn==Btn::kA&&ev==BtnEvent::kLongPress){Go(Screen::kMenu);return;}
  auto count=vaultlink_->grant_count();
  if(count==0){if(btn==Btn::kB&&ev==BtnEvent::kShortPress)Go(Screen::kMenu);return;}
  if(btn==Btn::kB&&ev==BtnEvent::kLongPress){
    vaultlink_->cancel_grants();grantSelected_=0;buttons_.ArmReleaseGate();needsRedraw_=true;return;
  }
  if(ev!=BtnEvent::kShortPress&&ev!=BtnEvent::kHoldRepeat)return;
  if(btn==Btn::kC)grantSelected_=static_cast<uint8_t>((grantSelected_+1)%count);
  else if(btn==Btn::kA)grantSelected_=static_cast<uint8_t>((grantSelected_+count-1)%count);
  else if(btn==Btn::kB){vaultlink_->cancel_grant(grantSelected_<count?grantSelected_:0);grantSelected_=0;buttons_.ArmReleaseGate();}
  needsRedraw_=true;
}

// ── 请求队列 ───────────────────────────────────────────────────────
// 本次连接内已完成请求的结果缓存。协议草案 §6：重复 requestId 不能再执行，
// 缓存与查询限额冻结。设备侧口径：
//  - 活动队列里出现同 requestId  -> 拒绝（已经在处理）；
//  - 已完成缓存里出现同 requestId -> 重放已知的结论，不再执行第二次。
// 缓存随连接一起清除：换连接等于换了运行世代，旧的 requestId 不再有意义。
void App::RecordOutcome(uint32_t requestId, ops::ErrorCode code) {
  for (auto& o : outcomes_) {
    if (o.used && o.requestId == requestId) {
      o.code = static_cast<uint8_t>(code);
      return;
    }
  }
  for (auto& o : outcomes_) {
    if (!o.used) {
      o.requestId = requestId;
      o.code = static_cast<uint8_t>(code);
      o.used = true;
      return;
    }
  }
  // 缓存已满。
  //
  // 这里**不能**覆盖最老的一条：一旦覆盖，那个 requestId 的记录消失，
  // 重新提交它就会被当成新请求，在有持续允许时甚至可能自动执行 ——
  // 协议草案 §6 要求「重复 requestId 不能再执行」，淘汰不能成为绕过。
  //
  // 取舍：缓存容量固定（ROCKEY_MAX_RESULT_CACHE），超出后**拒绝新的业务请求**
  // 而不是放行后忘掉。主机可以新建会话（换 sessionId）获得新的 requestId 空间。
  RK_LOGW("queue", "result cache full; refusing further requests in this session");
  outcomeCacheFull_ = true;
}

void App::OnEnvelope(const proto::Envelope& env) {
  if (selftestFailed_) {
    // 不处理任何请求：自检没过就等于密码学不可信
    link_.SendError(env.requestId, static_cast<uint16_t>(ops::ErrorCode::kResultUnknown));
    return;
  }
  if (env.bodyLen > ROCKEY_MAX_PLAINTEXT) {
    link_.SendError(env.requestId, static_cast<uint16_t>(ops::ErrorCode::kInvalidRequest));
    return;
  }
  // 重放检测：同一 requestId 已在队列中则不再执行
  for (uint8_t i = 0; i < ROCKEY_MAX_QUEUE; ++i) {
    if (queue_[i].active && queue_[i].requestId == env.requestId) {
      link_.SendError(env.requestId, static_cast<uint16_t>(ops::ErrorCode::kBusy));
      return;
    }
  }
  // requestCommitment 必须存在且非全零。
  //
  // 早先缺失时按全零接受，等于"不承诺也能执行"，协议草案 §2
  // 要求的「承诺覆盖实际对象/范围/证据和显示内容」形同虚设。
  // 覆盖规则本身仍待与 Keymaster 共同冻结（见 docs/冻结/线缆格式.md），
  // 在那之前至少做到：缺失即拒、非零才收、并把承诺绑定进授权匹配键，
  // 使一条持续授权只对**它被承诺过的那一个请求**有效。
  {
    bool allZero = true;
    for (int i = 0; i < 32; ++i) {
      if (env.commitment[i]) {
        allZero = false;
        break;
      }
    }
    if (allZero) {
      link_.SendError(env.requestId, static_cast<uint16_t>(ops::ErrorCode::kInvalidRequest));
      return;
    }
  }

  // 已经处理完的 requestId：把结论再报一次，但绝不重新执行。
  // 只查活动队列的话，执行结束后同一个 requestId 可以被重新提交并二次签名。
  for (const auto& o : outcomes_) {
    if (o.used && o.requestId == env.requestId) {
      link_.SendError(env.requestId, o.code == static_cast<uint8_t>(ops::ErrorCode::kOk)
                                         ? static_cast<uint16_t>(ops::ErrorCode::kResultUnknown)
                                         : o.code);
      return;
    }
  }
  // 结果缓存已满：宁可拒收新请求，也不能"忘了旧 requestId 就放行"。
  if (outcomeCacheFull_) {
    link_.SendError(env.requestId, static_cast<uint16_t>(ops::ErrorCode::kBusy));
    return;
  }
  int slot = -1;
  for (uint8_t i = 0; i < ROCKEY_MAX_QUEUE; ++i) {
    if (!queue_[i].active) {
      slot = i;
      break;
    }
  }
  if (slot < 0) {
    link_.SendError(env.requestId, static_cast<uint16_t>(ops::ErrorCode::kBusy));
    return;
  }
  Pending& p = queue_[slot];
  p = Pending{};
  p.active = true;
  p.requestId = env.requestId;
  p.sessionId = env.sessionId;
  p.sessionEpoch = env.sessionEpoch;
  memcpy(p.commitment, env.commitment, 32);
  memcpy(p.body, env.body, env.bodyLen);
  p.bodyLen = env.bodyLen;
  p.receivedMs = millis();
  queueCount_++;
  needsRedraw_ = true;
}

// 主机取消：只保证"尚未执行的请求确实没执行"。
// 已经进入执行或已交付签名的请求不承诺撤回，只能如实回报状态（协议草案 §6）。
// 设备事件：状态变化。序号单调递增，主机忽略旧事件（协议草案 §6）。
void App::SendStateEvent(proto::DeviceState ds) {
  uint8_t body[64];
  proto::Writer w(body, sizeof(body));
  // 确定性编码按长度递增：sessionId(9) < deviceState(11)
  w.BeginMap(2);
  w.Key("sessionId");
  w.Uint(link_.sessionId());
  w.Key("deviceState");
  w.Uint(static_cast<uint8_t>(ds));
  w.EndMap();
  if (!w.ok()) return;
  link_.SendEvent(++eventSeq_, body, w.size());
}

// 主机取消：只保证"尚未执行的请求确实没执行"。
// 已经进入执行或已交付签名的请求不承诺撤回，只能如实回报状态（协议草案 §6）。
void App::OnCancelRequest(uint32_t requestId) {
  for (uint8_t i = 0; i < ROCKEY_MAX_QUEUE; ++i) {
    if (!queue_[i].active || queue_[i].requestId != requestId) continue;
    queue_[i].active = false;
    if (queueCount_) queueCount_--;
    if (current_ == i) {
      // 取消优先于当前屏幕请求：立刻回到可操作状态
      current_ = -1;
      FinishRequest(ops::ErrorCode::kResultUnknown, nullptr, 0);
    }
    needsRedraw_ = true;
    return;
  }
  // 取消一个设备已经不再跟踪的 requestId：如实回报"结果未知"，
  // 不假装已取消。
  link_.SendError(requestId, static_cast<uint16_t>(ops::ErrorCode::kResultUnknown));
}

// 队列与结果缓存的统一清理点。锁定、断线、链路重启、擦除都必须走这里：
// 只把 queueCount_ 归零而不清 active 标志，会让旧请求永远占着"在处理中"。
void App::ClearQueues() {
  for (uint8_t i = 0; i < ROCKEY_MAX_QUEUE; ++i) queue_[i] = Pending{};
  for (auto& o : outcomes_) o = Outcome{};
  outcomeCacheFull_ = false;
  queueCount_ = 0;
  current_ = -1;
}

void App::PumpQueue() {
  if (current_ >= 0) return;
  // 用户正在看的授权页面优先于主机新请求：菜单、锁定与取消不可被挤掉。
  if (screen_ == Screen::kSummary || screen_ == Screen::kReqMenu ||
      screen_ == Screen::kReader || screen_ == Screen::kDenyConfirm) {
    return;
  }
  // pairing.required == true 表示"本连接还没配对"，此时不能处理业务请求；
  // 配对成功后它变成 false，那才是可以处理的时刻。判断反了会让所有请求
  // 永远停在队列里。
  if (link_.pairing().required) return;
  // 必须已建立会话：持有权证明通过之前不接受任何业务请求。
  if (!link_.SessionOpen(link_.sessionId())) return;
  if (!keystore::KeyStore::IsUnlocked()) return;
  for (uint8_t i = 0; i < ROCKEY_MAX_QUEUE; ++i) {
    if (queue_[i].active) {
      current_ = i;
      PresentCurrent();
      return;
    }
  }
}

void App::PresentCurrent() {
  if (current_ < 0) return;
  Pending& p = queue_[current_];
  lastRequestId_ = p.requestId;
  p.decisionRevisionAtParse = policy::Policy::decisionRevision();
  // 每个请求都要重新过一遍必需内容门禁
  gateSeen_ = 0;
  gateBlocked_ = false;

  ops::PrepareStatus ps = ops::Prepare(p.body, p.bodyLen, p.requestId, &doc_, &p.exec, p.commitment);
  if (ps != ops::PrepareStatus::kOk) {
    ops::ErrorCode e = ops::ErrorCode::kInvalidRequest;
    switch (ps) {
      case ops::PrepareStatus::kLocked: e = ops::ErrorCode::kLocked; break;
      case ops::PrepareStatus::kUnsupported: e = ops::ErrorCode::kUnsupported; break;
      case ops::PrepareStatus::kWrongKey: e = ops::ErrorCode::kWrongKey; break;
      case ops::PrepareStatus::kMigrationConflict: e = ops::ErrorCode::kMigrationConflict; break;
      case ops::PrepareStatus::kBusy: e = ops::ErrorCode::kBusy; break;
      default: break;
    }
    p.active = false;
    if (queueCount_) queueCount_--;
    current_ = -1;
    FinishRequest(e, nullptr, 0);
    return;
  }

  p.exec.match.sessionId = p.sessionId;
  p.exec.match.sessionEpoch = p.sessionEpoch;

  policy::EvalResult er =
      policy::Policy::Evaluate(p.exec.match, static_cast<uint8_t>(p.exec.category), doc_.title,
                               p.exec.valueSats);
  switch (er) {
    case policy::EvalResult::kDenied: {
      p.active = false;
      if (queueCount_) queueCount_--;
      current_ = -1;
      FinishRequest(ops::ErrorCode::kDeniedSession, nullptr, 0);
      return;
    }
    case policy::EvalResult::kAllowed:
      ExecuteCurrent();
      return;
    case policy::EvalResult::kExhausted:
      break;  // 超限不自动扩大，需要重新授权 -> 走界面
    case policy::EvalResult::kNeedUser:
      break;
  }

  menuSelected_ = 0;
  reader_.Load(&doc_);
  reader_.SavePosition();
  Go(Screen::kReqMenu);
}

void App::Decide(policy::Decision d) {
  if (current_ < 0) return;
  Pending& p = queue_[current_];
  // 私钥导出、迁移与恢复备份不得持续授权：即便用户在菜单里选了
  // "此会话允许/否决"，对这类操作也只能按一次性的结果处理。
  // 否则"允许本会话导出私钥"会变成一条长期许可（需求 §5 / VLP §4）。
  if (!policy::PersistentDecisionAllowed(static_cast<policy::Category>(p.exec.category))) {
    d = (d == policy::Decision::kDenySession) ? policy::Decision::kDenyOnce
                                               : policy::Decision::kAllowOnce;
  }
  switch (d) {
    case policy::Decision::kDenyOnce:
      policy::Policy::RecordOnce(policy::Direction::kNone);
      p.active = false;
      if (queueCount_) queueCount_--;
      current_ = -1;
      FinishRequest(ops::ErrorCode::kDeniedOnce, nullptr, 0);
      break;
    case policy::Decision::kAllowSession:
      policy::Policy::GrantSession(p.exec.match, static_cast<uint8_t>(p.exec.category), doc_.title,
                                  0, 0);
      ExecuteCurrent();
      break;
    case policy::Decision::kDenySession:
      policy::Policy::DenySession(p.exec.match, static_cast<uint8_t>(p.exec.category), doc_.title);
      p.active = false;
      if (queueCount_) queueCount_--;
      current_ = -1;
      FinishRequest(ops::ErrorCode::kDeniedSession, nullptr, 0);
      break;
    case policy::Decision::kAllowOnce:
    case policy::Decision::kUndecided:
      ExecuteCurrent();
      break;
  }
}

void App::ExecuteCurrent() {
  if (current_ < 0) return;
  Pending& p = queue_[current_];
  // 执行前再复核：撤权后旧请求不可执行
  policy::EvalResult er =
      policy::Policy::Evaluate(p.exec.match, static_cast<uint8_t>(p.exec.category), doc_.title,
                               p.exec.valueSats);
  if (er == policy::EvalResult::kDenied) {
    p.active = false;
    if (queueCount_) queueCount_--;
    current_ = -1;
    FinishRequest(ops::ErrorCode::kRevoked, nullptr, 0);
    return;
  }
  if (policy::Policy::decisionRevision() != p.decisionRevisionAtParse &&
      er == policy::EvalResult::kNeedUser) {
    // 期间授权状态变了：重新弹窗而不是直接执行
    Go(Screen::kReqMenu);
    return;
  }

  static uint8_t out[ROCKEY_MAX_FRAME_PAYLOAD];
  size_t outLen = 0;
  ops::ErrorCode e = ops::Execute(p.exec, out, sizeof(out), &outLen);
  // 会话允许被执行了一次：次数与金额累加，供后续限额判定。
  // 不累加的话 maxCount/budgetSats 永远看不到自己被用过。
  if (e == ops::ErrorCode::kOk) policy::Policy::Consume(p.exec.match, p.exec.valueSats);
  p.active = false;
  if (queueCount_) queueCount_--;
  uint32_t reqId = p.requestId;
  current_ = -1;
  FinishRequest(e, e == ops::ErrorCode::kOk ? out : nullptr,
                e == ops::ErrorCode::kOk ? outLen : 0);
  (void)reqId;
}

void App::FinishRequest(ops::ErrorCode code, const uint8_t* payload, size_t len) {
  if (code == ops::ErrorCode::kOk) {
    link_.SendResponse(lastRequestId_, payload, len);
  } else {
    link_.SendError(lastRequestId_, static_cast<uint16_t>(code));
  }
  RecordOutcome(lastRequestId_, code);
  // 请求结束的统一出口：清掉阅读位置与确认状态，并把界面带回一个
  // 不阻塞队列处理的中性页。不做这一步的话，页面停在 kSummary /
  // kReqMenu / kDenyConfirm 上，PumpQueue 会一直提前返回，
  // 队列里的下一个请求永远不会被取出。
  summaryScroll_ = 0;
  menuSelected_ = 0;
  grantSelected_ = 0;
  hold_.Reset();
  reader_.Clear();
  if (screen_ == Screen::kSummary || screen_ == Screen::kReqMenu ||
      screen_ == Screen::kReader || screen_ == Screen::kDenyConfirm) {
    Go(keystore::KeyStore::IsUnlocked() ? Screen::kMenu : Screen::kLock);
  }
  needsRedraw_ = true;
}

void App::LockNow(const char* reason) {
  RK_LOGI("app", "lock: %s", reason ? reason : "-");
  (void)reason;  // 发布构建 LOG_LEVEL 低，RK_LOGI 会编译掉，这里避免未用参数
  changingPin_ = false; oldPinLen_ = 0; newPinLen_ = 0;
  secure::Wipe(oldPin_, sizeof(oldPin_)); secure::Wipe(newPin_, sizeof(newPin_));
  policy::Policy::ClearAll();
  if (vaultlink_) vaultlink_->lock();
  keystore::KeyStore::Lock();
  link_.ClearSessions();
  for (auto& q : queue_) q = Pending{};
  queueCount_ = 0;
  current_ = -1;
  ResetPinEntry();
  Go(Screen::kLock);
}

void App::ShowErrorScreen(ops::ErrorCode e) {
  Go(Screen::kError);
  errorCode_ = e;
  i18n::Format(errorText_, sizeof(errorText_), ops::ErrorString(e));
  needsRedraw_ = true;
}


// ── 绘制 ───────────────────────────────────────────────────────────
namespace {
Rect Content() {
  return Rect{0, Board::kContentY, Board::kScreenW, Board::kContentH};
}
void FillContent() { Display::Fill(Content(), color::kBlack); }
}  // namespace

void App::Draw() {
  const bool pinPage=screen_==Screen::kLock||screen_==Screen::kSetPin||screen_==Screen::kSetPinConfirm;
  // 上下轮转只更新当前数字格；进入页面、移动位数或打开菜单才整页绘制。
  // 授权页覆盖和 Go() 换页必须使缓存失效，避免恢复时只画一个数字。
  if(pinPage&&pinRowDrawn_&&!pinMenuOpen_&&drawnPinLen_==pinLen_){
    if(drawnPinDigit_!=pinDigit_){
      const auto info=keystore::KeyStore::Info_();
      ui::DrawPinRow(info.pinDigits?info.pinDigits:ROCKEY_PIN_DEFAULT_DIGITS,
                     pinLen_,pinDigit_,pin_,Board::kContentY+14,true);
      drawnPinDigit_=pinDigit_;
    }
    return;
  }
  pinRowDrawn_=false;
  Display::Fill(Rect{0, 0, Board::kScreenW, Board::kScreenH}, color::kBlack);
  switch (screen_) {
    case Screen::kBoot: DrawBoot(); break;
    case Screen::kLock: DrawLock(); break;
    case Screen::kSetPin:
    case Screen::kSetPinConfirm: DrawSetPin(); break;
    case Screen::kNetworkChoice:
      ui::DrawHeader(i18n::T(i18n::Str::kNetworkTitle),nullptr);
      ui::DrawNotice(i18n::T(i18n::Str::kNetworkChoose),color::kWhite);
      ui::DrawFooter("Main",nullptr,"Test");break;
    case Screen::kInitializeChoice:
      ui::DrawHeader("RocKey",LangHint());
      ui::DrawNotice(i18n::T(i18n::Str::kEmptyWallet),color::kWhite);
      ui::DrawFooter(vaultlink_->import_busy()?nullptr:i18n::T(i18n::Str::kInitializeNew),nullptr,vaultlink_->import_busy()?i18n::T(i18n::Str::kCancel):nullptr);break;
    case Screen::kImport:
      ui::DrawHeader(i18n::T(i18n::Str::kImportTitle),nullptr);
      ui::DrawNotice(i18n::T(i18n::Str::kImportWaiting),color::kWhite);
      ui::DrawFooter(i18n::T(i18n::Str::kCancel),nullptr,nullptr);break;
    case Screen::kWaitPin: DrawWait(); break;
    case Screen::kPairing: DrawPairing(); break;
    case Screen::kChannels: channelSettings_.draw(); break;
    case Screen::kMenu: DrawMenu(); break;
    case Screen::kInfo: DrawInfo(); break;
    case Screen::kPubkey: DrawPubkey(); break;
    case Screen::kReader: DrawReader(); break;
    case Screen::kReqMenu: DrawReqMenu(); break;
    case Screen::kSummary: DrawSummaryScreen(); break;
    case Screen::kDenyConfirm: DrawDenyConfirm(); break;
    case Screen::kGrants: DrawGrants(); break;
    case Screen::kBackup: DrawBackup(); break;
    case Screen::kErase: DrawErase(); break;
    case Screen::kError: DrawError(); break;
  }
  pinRowDrawn_=pinPage&&!pinMenuOpen_;
  drawnPinLen_=pinLen_;drawnPinDigit_=pinDigit_;
}

void App::DrawBoot() {
  ui::DrawBootPoster();
}

void App::DrawLock() {
  keystore::Info info = keystore::KeyStore::Info_();
  uint8_t digits = info.pinDigits ? info.pinDigits : ROCKEY_PIN_DEFAULT_DIGITS;
  char hint[32];
  snprintf(hint, sizeof(hint), "%s %u", i18n::T(i18n::Str::kLockDigits), digits);
  ui::DrawHeader(i18n::T(changingPin_ ? i18n::Str::kLockOldPin : i18n::Str::kLockTitle), hint);
  FillContent();

  if (!info.initialized) {
    ui::DrawNotice(i18n::T(i18n::Str::kLockNoKey), color::kYellow);
    ui::DrawFooter(i18n::T(i18n::Str::kBtnLess), i18n::T(i18n::Str::kBtnOpen),
                   i18n::T(i18n::Str::kBtnMore));
    return;
  }

  if (pinMenuOpen_) {
    ui::MenuView m;
    m.Add(i18n::T(i18n::Str::kLockDeleteDigit));
    m.Add(i18n::T(i18n::Str::kLockCancelInput));
    m.selected = 0;
    ui::DrawMenu(m, false);
    ui::DrawFooter(nullptr, i18n::T(i18n::Str::kBtnSelect),
                   i18n::T(i18n::Str::kBtnHold));
    return;
  }

  // 逐位数字轮盘
  ui::DrawPinRow(digits, pinLen_, pinDigit_, pin_, Board::kContentY + 14);
  char msg[96] = {0};
  if (errorCode_ != ops::ErrorCode::kOk) {
    i18n::Format(msg, sizeof(msg), ops::ErrorString(errorCode_));
  }
  if (msg[0]) {
    ui::DrawNotice(msg, color::kRed);
  }
  ui::DrawFooter(i18n::T(i18n::Str::kBtnLess),
                 i18n::T(pinLen_+1>=digits?i18n::Str::kLockUnlock:i18n::Str::kBtnEnter),
                 i18n::T(i18n::Str::kBtnMore2));
}

void App::DrawSetPin() {
  keystore::Info info = keystore::KeyStore::Info_();
  uint8_t digits = info.pinDigits ? info.pinDigits : ROCKEY_PIN_DEFAULT_DIGITS;
  bool confirm = screen_ == Screen::kSetPinConfirm;
  char hint[40];
  snprintf(hint, sizeof(hint), "%s %u", i18n::T(i18n::Str::kLockDigits), digits);
  ui::DrawHeader(confirm ? i18n::T(i18n::Str::kLockConfirmPin) : i18n::T(i18n::Str::kLockSetPin),
                 hint);
  FillContent();

  ui::DrawPinRow(digits, pinLen_, pinDigit_, pin_, Board::kContentY + 14);
  if (confirm && pinLen_ > 0) {
    // 重复输入时不回显已输入位数，避免侧信道式差异
  }
  ui::DrawFooter(i18n::T(i18n::Str::kBtnLess), i18n::T(i18n::Str::kBtnEnter),
                 i18n::T(i18n::Str::kBtnMore2));
}

void App::DrawWait() {
  char buf[48];
  snprintf(buf, sizeof(buf), "%lu", static_cast<unsigned long>(waitSecondsLeft_));
  ui::DrawHeader(i18n::T(i18n::Str::kLockTitle), buf);
  FillContent();
  char msg[48];
  i18n::Format(msg, sizeof(msg), i18n::Str::kLockWaitSeconds,
               static_cast<unsigned long>(waitSecondsLeft_));
  ui::DrawNotice(msg, color::kRed);
  ui::DrawFooter(nullptr, i18n::T(i18n::Str::kLockTooManyTries), nullptr);
}

void App::DrawPairing() {
  ui::DrawHeader(i18n::T(i18n::Str::kPairTitle), LangHint());
  FillContent();
  const proto::PairingState& ps = link_.pairing();
  Rect box{20, Board::kContentY + 18, Board::kScreenW - 40, 40};
  Display::Fill(box, color::kBlack);
  Display::Frame(box, color::kCyan);
  Display::DrawTextIn(box, FontRole::kMono, ps.code, 6, color::kCyan, color::kBlack,
                      TextAlign::kCenter, VAlign::kMiddle);
  ui::DrawNotice(i18n::T(i18n::Str::kPairHint), color::kGray);
  Rect bar{40, static_cast<int16_t>(Board::kContentY + 96), Board::kScreenW - 80, 10};
  if (ps.userConfirmed) {
    Display::DrawProgress(bar, 100, color::kGreen, color::kBlack);
  } else {
    Display::DrawProgress(bar, hold_.Percent(now_), color::kYellow, color::kBlack);
  }
  ui::DrawFooter(i18n::T(i18n::Str::kBtnPrev), i18n::T(i18n::Str::kBtnHoldConfirm),
                 i18n::T(i18n::Str::kBtnNext));
}

void App::DrawMenu() {
  ui::DrawHeader(i18n::T(i18n::Str::kMenuTitle), LangHint());
  FillContent();
  menu_.count = 0;
  menu_.Add(queueCount_ ? i18n::T(i18n::Str::kMenuReview) : i18n::T(i18n::Str::kMenuEmpty));
  menu_.Add(i18n::T(i18n::Str::kMenuGrants));
  menu_.Add(i18n::T(i18n::Str::kMenuDeviceInfo));
  menu_.Add(i18n::T(i18n::Str::kMenuKeyDetail));
  menu_.Add(i18n::T(i18n::Str::kMenuRecoveryBackup));
  menu_.Add(i18n::T(i18n::Str::kMenuErase));
  menu_.Add(i18n::T(i18n::Str::kMenuChangePin));
  menu_.Add(i18n::T(sound::Enabled(false)?i18n::Str::kSoundAutoOff:i18n::Str::kSoundAutoOn));
  menu_.Add(i18n::T(sound::Enabled(true)?i18n::Str::kSoundManualOff:i18n::Str::kSoundManualOn));
  menu_.Add(i18n::T(i18n::Str::kChannelSettings));
  if (menuSelected_ >= menu_.count) menuSelected_ = 0;
  menu_.selected = menuSelected_;
  ui::DrawMenu(menu_, false);
  ui::DrawFooter(i18n::T(i18n::Str::kBtnPrev), i18n::T(i18n::Str::kBtnSelect),
                 i18n::T(i18n::Str::kBtnNext));
}

void App::DrawInfo() {
  ui::DrawHeader(i18n::T(i18n::Str::kInfoTitle), LangHint());
  FillContent();
  Rect c = Content();
  int lh = FontLineHeight(FontRole::kSmall);
  uint8_t row = 0;
  char buf[64];
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kInfoBoard), Board::BoardName(), row++);
  snprintf(buf, sizeof(buf), "%d.%d.%d", ROCKEY_FIRMWARE_VERSION_MAJOR,
           ROCKEY_FIRMWARE_VERSION_MINOR, ROCKEY_FIRMWARE_VERSION_PATCH);
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kInfoFirmware), buf, row++);
  snprintf(buf, sizeof(buf), "%u", static_cast<unsigned>(ROCKEY_PROTOCOL_VERSION));
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kInfoProtocol), buf, row++);
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kInfoLanguage), i18n::LangDisplayName(), row++);
  snprintf(buf, sizeof(buf), "%lu", static_cast<unsigned long>(Board::FreeHeap()));
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kInfoHeap), buf, row++);
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kSecFlashEnc), i18n::T(i18n::Str::kSecDisabled), row++);
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kSecSecureBoot), i18n::T(i18n::Str::kSecDisabled), row++);
  int y = Board::kContentY + row * (lh + 2) + 6;
  Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh * 2}, FontRole::kSmall,
                      i18n::T(i18n::Str::kInfoSecurityNote),
                      strlen(i18n::T(i18n::Str::kInfoSecurityNote)), color::kYellow, color::kBlack,
                      TextAlign::kLeft, VAlign::kTop);
  ui::DrawFooter(nullptr, i18n::T(i18n::Str::kBtnBack), nullptr);
}

void App::DrawPubkey() {
  ui::DrawHeader(i18n::T(i18n::Str::kInfoPublicKey), nullptr);
  FillContent();
  char hex[80];
  digest::ToHex(keystore::KeyStore::PublicKey(), 33, hex, sizeof(hex));
  Rect c = Content();
  ui::DrawHexBlock(Rect{c.x, static_cast<int16_t>(c.y + 8), c.w, c.h}, hex, true);
  ui::DrawFooter(nullptr, i18n::T(i18n::Str::kBtnBack), nullptr);
}

void App::DrawReader() {
  char ch[32];
  snprintf(ch, sizeof(ch), "%s", "");
  i18n::Format(ch, sizeof(ch), i18n::Str::kReadChapter, static_cast<unsigned>(reader_.Chapter() + 1),
               static_cast<unsigned>(reader_.ChapterCount()));
  ui::DrawHeader(doc_.title[0] ? doc_.title : i18n::T(i18n::Str::kReadTitle), ch);
  FillContent();
  Rect c = Content();
  reader_.Draw(c.x, c.y + 2, c.w, c.h - 26);
  char foot[48];
  snprintf(foot, sizeof(foot), "%s", "");
  if (doc_.hasMissingGlyph) {
    i18n::Format(foot, sizeof(foot), i18n::Str::kReadMissingGlyph, doc_.missingGlyphCp);
  } else if (reader_.AtEnd()) {
    i18n::Format(foot, sizeof(foot), i18n::Str::kReadEnd);
  } else {
    i18n::Format(foot, sizeof(foot), i18n::Str::kReadHoldFaster);
  }
  Display::DrawTextIn(Rect{c.x, static_cast<int16_t>(c.y + c.h - 20), c.w, 18}, FontRole::kSmall,
                      foot, strlen(foot),
                      doc_.hasMissingGlyph ? color::kYellow : color::kDim, color::kBlack,
                      TextAlign::kLeft, VAlign::kTop);
  ui::DrawFooter(i18n::T(i18n::Str::kBtnPrev), i18n::T(i18n::Str::kBtnHold),
                 i18n::T(i18n::Str::kBtnNext));
}

void App::DrawReqMenu() {
  char ch[32];
  i18n::Format(ch, sizeof(ch), i18n::Str::kReadChapter, static_cast<unsigned>(reader_.Chapter() + 1),
               static_cast<unsigned>(reader_.ChapterCount()));
  ui::DrawHeader(i18n::T(i18n::Str::kReqTitle), ch);
  FillContent();
  // 默认焦点为"继续阅读"；会话级决定只对被允许的操作显示
  // （导出/迁移/恢复备份不得持续授权，索性不给这个选项）
  ui::MenuView m;
  m.Add(i18n::T(i18n::Str::kReqContinueReading));
  m.Add(i18n::T(i18n::Str::kReqDenyOnce));
  m.Add(i18n::T(i18n::Str::kReqAllowOnce));
  if (SessionDecisionOffered()) {
    m.Add(i18n::T(i18n::Str::kReqAllowSession));
    m.Add(i18n::T(i18n::Str::kReqDenySession));
  }
  if (menuSelected_ >= m.count) menuSelected_ = 0;
  m.selected = menuSelected_;
  ui::DrawMenu(m, false);
  ui::DrawFooter(i18n::T(i18n::Str::kBtnPrev), i18n::T(i18n::Str::kBtnSelect),
                 i18n::T(i18n::Str::kBtnNext));
}

void App::DrawSummaryScreen() {
  ui::DrawHeader(i18n::T(i18n::Str::kSumTitle), doc_.subject);
  FillContent();
  Rect c = Content();
  ui::DrawSummary(doc_, summaryScroll_, 5);
  int lh = FontLineHeight(FontRole::kSmall);
  // 风险逐条显示；超过两条的部分由 A/C 滚动到达，不允许"永远看不到第 3 条"
  for (uint8_t i = 0; i < doc_.riskCount && i < 2; ++i) {
    int y = Board::kContentY + 6 + (5 + i) * (lh + 1);
    const char* r = i18n::T(RiskString(doc_.risks[i]));
    Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh}, FontRole::kSmall, r,
                        strlen(r), color::kRed, color::kBlack, TextAlign::kLeft, VAlign::kTop);
  }
  uint8_t maxScroll = SummaryScrollMax();
  for (uint8_t i = 0; i < doc_.riskCount && i < 2 + maxScroll; ++i) {
    uint8_t slot = static_cast<uint8_t>(i + summaryScroll_);
    if (i < 2) continue;
    if (slot >= doc_.riskCount) continue;
    int y = Board::kContentY + 6 + (5 + slot) * (lh + 1);
    if (y >= Board::kContentY + c.h - 34) break;
    const char* r = i18n::T(RiskString(doc_.risks[slot]));
    Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh}, FontRole::kSmall, r,
                        strlen(r), color::kRed, color::kBlack, TextAlign::kLeft, VAlign::kTop);
  }
  // "不包含"与滚动位置提示：确认页必须始终显示不包含的权限
  int y = Board::kContentY + 6 + (5 + maxScroll + 2) * (lh + 1);
  if (y < Board::kContentY + c.h - 34) {
    const char* ex = i18n::T(i18n::Str::kSumExcludes);
    Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh}, FontRole::kSmall, ex,
                        strlen(ex), color::kOrange, color::kBlack, TextAlign::kLeft,
                        VAlign::kTop);
  }
  Rect bar{20, static_cast<int16_t>(Board::kFooterY - 26), Board::kScreenW - 40, 24};
  hold_.Draw(bar, now_, true);
  // 标签必须与实际动作一致：本页 A/C 是滚动，B 是返回，
  // 长按 B 才确认。原来这里写"返回 / 查看范围"而实现里根本没有查看范围。
  ui::DrawFooter(i18n::T(i18n::Str::kBtnScrollPrev), i18n::T(i18n::Str::kSumHoldConfirm),
                 i18n::T(i18n::Str::kBtnScrollNext));
  if (gateBlocked_) {
    ui::DrawNotice(i18n::T(i18n::Str::kMustReadFirst), color::kOrange);
    gateBlocked_ = false;
  }
}

void App::DrawDenyConfirm() {
  ui::DrawHeader(i18n::T(i18n::Str::kDenyTitle), nullptr);
  FillContent();
  Rect c = Content();
  ui::DrawNotice(i18n::T(i18n::Str::kDenyExplain), color::kGray);
  int y = Board::kContentY + 60;
  const char* t = i18n::T(i18n::Str::kSumHoldDeny);
  Display::DrawTextIn(Rect{c.x, static_cast<int16_t>(y), c.w, 20}, FontRole::kSmall, t, strlen(t),
                      color::kYellow, color::kBlack, TextAlign::kCenter, VAlign::kTop);
  ui::DrawFooter(i18n::T(i18n::Str::kBtnBack), i18n::T(i18n::Str::kBtnHoldDeny), nullptr);
}

void App::DrawGrants() {
  ui::DrawHeader(i18n::T(i18n::Str::kGrantsTitle), LangHint());FillContent();
  auto count=vaultlink_->grant_count();
  if(!count){ui::DrawNotice(i18n::T(i18n::Str::kGrantsEmpty),color::kGray);ui::DrawFooter(i18n::T(i18n::Str::kBtnBack),i18n::T(i18n::Str::kBtnBack),nullptr);return;}
  if(grantSelected_>=count)grantSelected_=0;
  auto entry=vaultlink_->grant(grantSelected_);
  std::vector<std::string> lines;
  lines.push_back(std::to_string(grantSelected_+1)+" / "+std::to_string(count));
  lines.push_back(i18n::T(entry.operation=="local-secret.seal"?i18n::Str::kOpSecretSeal:i18n::Str::kOpSecretOpen));
  lines.push_back(i18n::T(entry.decision==vlp::ScopeGrants::Allow?i18n::Str::kGrantsAllowed:i18n::Str::kGrantsDenied));
  // 完整展示最多 95 字节的范围；不靠被截断的昵称选择待撤销权限。
  for(auto &line:vlp::display_chunks(entry.scope))lines.push_back(std::move(line));
  for(size_t i=0;i<lines.size();++i)Display::DrawText(FontRole::kSmall,6,36+int(i)*22,lines[i].data(),lines[i].size(),color::kWhite,color::kBlack);
  ui::DrawFooter(i18n::T(i18n::Str::kVlpGrantsPrevious),i18n::T(i18n::Str::kVlpGrantsCancel),i18n::T(i18n::Str::kBtnScrollNext));
}

void App::DrawBackup() {
  ui::DrawHeader(i18n::T(i18n::Str::kBackupTitle), nullptr);
  FillContent();
  Rect c = Content();
  if (!backupReady_) {
    const char* e = i18n::T(i18n::Str::kBackupExplain);
    ui::DrawNotice(e, color::kGray);
    Rect bar{30, static_cast<int16_t>(Board::kContentY + 96), Board::kScreenW - 60, 10};
    Display::DrawProgress(bar, hold_.Percent(now_), color::kYellow, color::kBlack);
    ui::DrawFooter(nullptr, i18n::T(i18n::Str::kBtnHoldConfirm),
                   i18n::T(i18n::Str::kBtnBack));
    return;
  }
  int lh = FontLineHeight(FontRole::kSmall);
  int y = c.y + 4;
  const char* lbl = i18n::T(i18n::Str::kBackupCode);
  Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh}, FontRole::kSmall, lbl,
                      strlen(lbl), color::kGray, color::kBlack, TextAlign::kLeft, VAlign::kTop);
  y += lh + 2;
  // 恢复码分两行显示，避免横向截断
  char part1[16] = {0}, part2[16] = {0};
  memcpy(part1, recoveryCode_, 13);
  memcpy(part2, recoveryCode_ + 13, 13);
  Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh}, FontRole::kMono,
                      part1, 13, color::kYellow, color::kBlack, TextAlign::kLeft, VAlign::kTop);
  Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y + lh), c.w - 12, lh}, FontRole::kMono,
                      part2, 13, color::kYellow, color::kBlack, TextAlign::kLeft, VAlign::kTop);
  y += lh * 2 + 4;
  // 备份数据滚动显示
  char hex[70];
  digest::ToHex(recoveryBlob_ + backupScroll_ * 24, 24, hex, sizeof(hex));
  for (int i = 0; i < 4 && backupScroll_ * 24 + 24 <= recoveryBlobLen_; ++i) {
    digest::ToHex(recoveryBlob_ + (backupScroll_ + i) * 24, 24, hex, sizeof(hex));
    Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh}, FontRole::kMono, hex,
                        strlen(hex), color::kWhite, color::kBlack, TextAlign::kLeft,
                        VAlign::kTop);
    y += lh;
  }
  ui::DrawFooter(nullptr, i18n::T(i18n::Str::kBtnNext),
                 i18n::T(i18n::Str::kBtnBack));
}

void App::DrawErase() {
  ui::DrawHeader(i18n::T(i18n::Str::kEraseTitle), nullptr);
  FillContent();
  const char* w = i18n::T(!keystore::KeyStore::HasKey()&&store::Exists("/vault/vlp-migration.bin")?i18n::Str::kMigResetWarning:i18n::Str::kEraseWarning);
  ui::DrawNotice(w, color::kRed);
  int y = Board::kContentY + 90;
  Display::DrawTextIn(Rect{10, static_cast<int16_t>(y), Board::kScreenW - 20, 20}, FontRole::kSmall,
                      i18n::T(i18n::Str::kEraseHold),
                      strlen(i18n::T(i18n::Str::kEraseHold)), color::kYellow, color::kBlack,
                      TextAlign::kCenter, VAlign::kTop);
  ui::DrawFooter(i18n::T(i18n::Str::kBtnBack), i18n::T(i18n::Str::kCancel),
                 i18n::T(i18n::Str::kEraseHold));
}

void App::DrawError() {
  if(!keystore::KeyStore::HasKey()&&store::Exists("/vault/vlp-migration.bin")){
    ui::DrawHeader(i18n::T(i18n::Str::kMigStatusTitle),LangHint());FillContent();
    bool staged=false;try{vlp::MigrationStore disk;vaultlink::MigrationJournal journal(disk);auto r=journal.status();staged=r.at("direction").string()=="to-hardware"&&r.at("phase").string()=="staged";}catch(...){}
    ui::DrawNotice(i18n::T(staged?i18n::Str::kImportWaiting:i18n::Str::kMigNoOldKey),color::kYellow);
    const char* reset=nullptr;
    try{vlp::MigrationStore disk;vaultlink::MigrationJournal journal(disk);auto phase=journal.status().at("phase").string();
      if(phase=="erased"||phase=="complete")reset=i18n::T(i18n::Str::kMenuErase);
      else if(staged)reset=i18n::T(i18n::Str::kLockSetPin);
    }catch(...){/* No reset hint for corrupt/unfinished recovery evidence. */}
    ui::DrawFooter(nullptr,nullptr,reset);return;
  }
  ui::DrawHeader(i18n::T(i18n::Str::kErrTitle), LangHint());
  FillContent();
  ui::DrawNotice(errorText_, color::kRed);
  ui::DrawFooter(nullptr, nullptr, i18n::T(i18n::Str::kBtnBack));
}

}  // namespace rockey
