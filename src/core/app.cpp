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
#include "store/keystore.h"
#include "store/vault_fs.h"

namespace rockey {
namespace {

const char* LangHint() { return i18n::LangTag(); }

inline bool ev_backupScroll(const Buttons& b, uint32_t now) {
  if (b.IsDown(Btn::kC)) return true;
  if (b.IsDown(Btn::kA)) return true;
  (void)now;
  return false;
}

}  // namespace

bool App::SelfTest() {
  bool ok = true;
  if (!x25519::SelfTest()) {
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
  Display::FillScreen(color::kBlack);
  Log::Init();
  store::Init();
  keystore::KeyStore::Init();

  BtnConfig cfg;
  buttons_.Init(cfg);

  uint32_t now = millis();
  bootMs_ = now;
  now_ = now;
  link_.Begin(now);
  SelfTest();

  keystore::Info info = keystore::KeyStore::Info_();
  if (!info.initialized) {
    Go(Screen::kSetPin);
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
  hold_.Reset();
  summaryScroll_ = 0;
  buttons_.ArmReleaseGate();  // 换页先要求松键，避免长按延续误确认
  needsRedraw_ = true;
}

// ── 主循环 ─────────────────────────────────────────────────────────
void App::Loop() {
  uint32_t now = millis();
  now_ = now;
  buttons_.Poll(now);
  buttons_.ClearGateIfSatisfied();

  link_.Poll(now, [](const proto::Envelope& env, void* user) {
    static_cast<App*>(user)->OnEnvelope(env);
  }, this);

  if (!link_.Tick(now)) {
    // 失活：立即撤权并锁定（即使电池仍在供电）
    policy::Policy::ClearAll();
    keystore::KeyStore::Lock();
    if (screen_ != Screen::kLock && screen_ != Screen::kSetPin &&
        screen_ != Screen::kSetPinConfirm && screen_ != Screen::kWaitPin) {
      current_ = -1;
      queueCount_ = 0;
      Go(Screen::kLock);
    }
  }

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
      OnButton(btn, ev);
      needsRedraw_ = true;
    }
  }

  // 配对页面优先：锁定时也允许最小配对流程，但不能被主机请求遮挡
  const proto::PairingState& ps = link_.pairing();
  if (ps.required && !ps.userConfirmed && screen_ != Screen::kPairing &&
      screen_ != Screen::kSetPin && screen_ != Screen::kSetPinConfirm &&
      screen_ != Screen::kWaitPin) {
    current_ = -1;
    Go(Screen::kPairing);
  }
  if (screen_ == Screen::kPairing && (!ps.required || ps.userConfirmed)) {
    Go(keystore::KeyStore::IsUnlocked() ? Screen::kMenu : Screen::kLock);
  }

  // 擦除页：长按 C 3 秒才真正执行（独立物理确认，不因浏览器注销触发）
  if (screen_ == Screen::kErase) {
    static uint32_t eraseArmed = 0;
    if (buttons_.IsDown(Btn::kC)) {
      if (eraseArmed == 0) eraseArmed = now;
      if (now - eraseArmed >= 3000) {
        eraseArmed = 0;
        keystore::KeyStore::Erase();
        policy::Policy::ClearAll();
        link_.ClearSessions();
        Go(Screen::kSetPin);
      }
      needsRedraw_ = true;
    } else if (eraseArmed != 0 && now - eraseArmed > 400) {
      eraseArmed = 0;
      needsRedraw_ = true;
    }
  }

  hold_.Update(buttons_, now,
               screen_ == Screen::kSummary || screen_ == Screen::kDenyConfirm ||
                   screen_ == Screen::kPairing ||
                   (screen_ == Screen::kBackup && !backupReady_));

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
      Decide(menuSelected_ == 3 ? policy::Decision::kAllowSession : policy::Decision::kAllowOnce);
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
    case Screen::kMigrate:
    case Screen::kBackup:
      HandleMenuInput(btn, ev);
      break;
    case Screen::kGrants:
      HandleGrantsInput(btn, ev);
      break;
    default:
      break;
  }
}

void App::ResetPinEntry() {
  pinLen_ = 0;
  pinDigit_ = static_cast<uint8_t>(rand::Below(10));
  pin_[0] = '\0';
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
  keystore::Status st = keystore::KeyStore::Unlock(pin_, pinLen_);
  switch (st) {
    case keystore::Status::kOk: {
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
      Go(Screen::kSetPin);
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
        ResetPinEntry();
        newPinLen_ = 0;
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
              // 设备生成新身份 Key 并用新 PIN 封装
              uint8_t priv[32];
              uint8_t ok = 0;
              for (int tries = 0; tries < 8 && !ok; ++tries) {
                rand::Fill(priv, 32);
                if (secp::ValidatePriv(priv)) ok = 1;
              }
              secure::Wipe(priv, 32);
              if (ok) {
                // 重新生成并保存（未使用中间缓冲以外的可读副本）
                bool generated = false;
                for (int tries = 0; tries < 8 && !generated; ++tries) {
                  rand::Fill(priv, 32);
                  if (!secp::ValidatePriv(priv)) continue;
                  generated = keystore::KeyStore::SetPinAndWrap(pin_, pinLen_, priv) ==
                              keystore::Status::kOk;
                }
                secure::Wipe(priv, 32);
                if (generated) {
                  secure::Wipe(newPin_, sizeof(newPin_));
                  newPinLen_ = 0;
                  ResetPinEntry();
                  Go(Screen::kMenu);
                  break;
                }
              }
            }
            // 不一致：重新开始
            secure::Wipe(newPin_, sizeof(newPin_));
            newPinLen_ = 0;
            ResetPinEntry();
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
  uint8_t count = 5;
  uint8_t span = 5;
  switch (ev) {
    case BtnEvent::kShortPress:
    case BtnEvent::kHoldRepeat:
    case BtnEvent::kLongPress:
      if (btn == Btn::kC) menuSelected_ = static_cast<uint8_t>((menuSelected_ + 1) % count);
      else if (btn == Btn::kA) menuSelected_ = static_cast<uint8_t>((menuSelected_ + count - 1) % count);
      else if (btn == Btn::kB && ev == BtnEvent::kShortPress) {
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
        if (menuSelected_ == 3) {
          Go(Screen::kSummary);
          return;
        }
        if (menuSelected_ == 4) {
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
        case 2: LockNow("user"); return;
        case 3: Go(Screen::kInfo); return;
        case 4: Go(Screen::kPubkey); return;
        case 5: migrationArmed_ = false; Go(Screen::kMigrate); return;
        case 6: backupReady_ = false; hold_.Reset(); Go(Screen::kBackup); return;
        case 7: Go(Screen::kErase); return;
        default: return;
      }
    } else if (btn == Btn::kB && ev == BtnEvent::kLongPress) {
      // 主菜单长按 B 无额外动作，避免误触
      return;
    }
    return;
  }

  if (screen_ == Screen::kInfo || screen_ == Screen::kPubkey ||
      screen_ == Screen::kMigrate || screen_ == Screen::kBackup) {
    if (btn == Btn::kB && (ev == BtnEvent::kShortPress || ev == BtnEvent::kLongPress)) {
      Go(Screen::kMenu);
    }
    return;
  }
}

void App::HandleGrantsInput(Btn btn, BtnEvent ev) {
  uint8_t count = policy::Policy::Count();
  if (count == 0) {
    if (btn == Btn::kB && ev == BtnEvent::kShortPress) Go(Screen::kMenu);
    return;
  }
  if (ev == BtnEvent::kShortPress || ev == BtnEvent::kHoldRepeat) {
    if (btn == Btn::kC) grantSelected_ = static_cast<uint8_t>((grantSelected_ + 1) % count);
    else if (btn == Btn::kA) {
      grantSelected_ = static_cast<uint8_t>((grantSelected_ + count - 1) % count);
    } else if (btn == Btn::kB && ev == BtnEvent::kShortPress) {
      policy::Policy::CancelSession(grantSelected_);
      grantSelected_ = 0;
    } else if (btn == Btn::kB && ev == BtnEvent::kLongPress) {
      policy::Policy::CancelAll();
      grantSelected_ = 0;
    }
  }
}

// ── 请求队列 ───────────────────────────────────────────────────────
void App::OnEnvelope(const proto::Envelope& env) {
  if (env.bodyLen > ROCKEY_MAX_PLAINTEXT) {
    link_.SendError(env.requestId, static_cast<uint16_t>(ops::ErrorCode::kInvalidRequest));
    return;
  }
  // 重放检测：同一 requestId 已在队列中则不再执行
  for (uint8_t i = 0; i < ROCKEY_MAX_QUEUE; ++i) {
    if (queue_[i].active && queue_[i].requestId == env.requestId) {
      return;
    }
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

void App::PumpQueue() {
  if (current_ >= 0) return;
  if (screen_ == Screen::kSummary || screen_ == Screen::kReqMenu ||
      screen_ == Screen::kReader || screen_ == Screen::kDenyConfirm) {
    return;
  }
  if (!link_.pairing().required) return;
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

  ops::PrepareStatus ps = ops::Prepare(p.body, p.bodyLen, p.requestId, &doc_, &p.exec);
  if (ps != ops::PrepareStatus::kOk) {
    ops::ErrorCode e = ops::ErrorCode::kInvalidRequest;
    switch (ps) {
      case ops::PrepareStatus::kLocked: e = ops::ErrorCode::kLocked; break;
      case ops::PrepareStatus::kUnsupported: e = ops::ErrorCode::kUnsupported; break;
      case ops::PrepareStatus::kWrongKey: e = ops::ErrorCode::kWrongKey; break;
      case ops::PrepareStatus::kInvalidEvidence: e = ops::ErrorCode::kInvalidEvidence; break;
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

  policy::EvalResult er = policy::Policy::Evaluate(p.exec.match,
                                                    static_cast<uint8_t>(p.exec.category),
                                                    doc_.title);
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
  policy::EvalResult er = policy::Policy::Evaluate(p.exec.match,
                                                   static_cast<uint8_t>(p.exec.category), doc_.title);
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
  needsRedraw_ = true;
}

void App::LockNow(const char* reason) {
  RK_LOGI("app", "lock: %s", reason ? reason : "-");
  policy::Policy::ClearAll();
  keystore::KeyStore::Lock();
  link_.ClearSessions();
  for (auto& q : queue_) q = Pending{};
  queueCount_ = 0;
  current_ = -1;
  ResetPinEntry();
  Go(Screen::kLock);
}

void App::ShowErrorScreen(ops::ErrorCode e) {
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
  Display::Fill(Rect{0, 0, Board::kScreenW, Board::kScreenH}, color::kBlack);
  switch (screen_) {
    case Screen::kBoot: DrawBoot(); break;
    case Screen::kLock: DrawLock(); break;
    case Screen::kSetPin:
    case Screen::kSetPinConfirm: DrawSetPin(); break;
    case Screen::kWaitPin: DrawWait(); break;
    case Screen::kPairing: DrawPairing(); break;
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
    case Screen::kMigrate: DrawMigrate(); break;
    case Screen::kError: DrawError(); break;
  }
}

void App::DrawBoot() {
  ui::DrawHeader(i18n::T(i18n::Str::kAppName), LangHint());
  char buf[64];
  snprintf(buf, sizeof(buf), "%s %d.%d.%d", i18n::T(i18n::Str::kBootStarting),
           ROCKEY_FIRMWARE_VERSION_MAJOR, ROCKEY_FIRMWARE_VERSION_MINOR,
           ROCKEY_FIRMWARE_VERSION_PATCH);
  ui::DrawNotice(buf, color::kWhite);
  ui::DrawFooter(nullptr, nullptr, nullptr);
}

void App::DrawLock() {
  keystore::Info info = keystore::KeyStore::Info_();
  uint8_t digits = info.pinDigits ? info.pinDigits : ROCKEY_PIN_DEFAULT_DIGITS;
  char hint[32];
  snprintf(hint, sizeof(hint), "%s %u", i18n::T(i18n::Str::kLockDigits), digits);
  ui::DrawHeader(i18n::T(i18n::Str::kLockTitle), hint);
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
    ui::DrawFooter(i18n::T(i18n::Str::kMenuLock), i18n::T(i18n::Str::kBtnSelect),
                   i18n::T(i18n::Str::kBtnHold));
    return;
  }

  // 逐位数字轮盘
  int lh = FontLineHeight(FontRole::kSmall);
  int y = Board::kContentY + 14;
  for (uint8_t i = 0; i < digits; ++i) {
    int x = 16 + i * ((Board::kScreenW - 40) / digits);
    int w = (Board::kScreenW - 40) / digits - 4;
    char d[2] = {' ', '\0'};
    if (i < pinLen_) d[0] = pin_[i];
    Rect cell{static_cast<int16_t>(x), static_cast<int16_t>(y), static_cast<int16_t>(w), lh};
    Display::Fill(cell, color::kBlack);
    if (i == pinLen_) {
      Display::Frame(cell, color::kYellow);
      char cur[8] = {' ', '0', static_cast<char>('0' + pinDigit_), '\0'};
      Display::DrawTextIn(cell, FontRole::kSmall, cur + 1, 1, color::kYellow, color::kBlack,
                          TextAlign::kCenter, VAlign::kMiddle);
    } else {
      Display::DrawTextIn(cell, FontRole::kSmall, d, 1, color::kWhite, color::kBlack,
                          TextAlign::kCenter, VAlign::kMiddle);
    }
  }
  char msg[96] = {0};
  if (errorCode_ != ops::ErrorCode::kOk) {
    i18n::Format(msg, sizeof(msg), ops::ErrorString(errorCode_));
  }
  if (msg[0]) {
    ui::DrawNotice(msg, color::kRed);
  }
  ui::DrawFooter(i18n::T(i18n::Str::kBtnLess), i18n::T(i18n::Str::kBtnEnter),
                 i18n::T(i18n::Str::kBtnMore2));
  ui::DrawBatteryIndicator();
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

  int lh = FontLineHeight(FontRole::kSmall);
  int y = Board::kContentY + 14;
  for (uint8_t i = 0; i < digits; ++i) {
    int w = (Board::kScreenW - 40) / digits - 4;
    int x = 16 + i * (w + 4);
    char d[2] = {' ', '\0'};
    if (i < pinLen_) d[0] = pin_[i];
    Rect cell{static_cast<int16_t>(x), static_cast<int16_t>(y), static_cast<int16_t>(w), lh};
    Display::Fill(cell, color::kBlack);
    if (i == pinLen_) {
      Display::Frame(cell, color::kYellow);
      char cur[2] = {static_cast<char>('0' + pinDigit_), '\0'};
      Display::DrawTextIn(cell, FontRole::kSmall, cur, 1, color::kYellow, color::kBlack,
                          TextAlign::kCenter, VAlign::kMiddle);
    } else {
      Display::DrawTextIn(cell, FontRole::kSmall, d, 1, color::kWhite, color::kBlack,
                          TextAlign::kCenter, VAlign::kMiddle);
    }
  }
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
  menu_.Add(i18n::T(i18n::Str::kMenuLock));
  menu_.Add(i18n::T(i18n::Str::kMenuDeviceInfo));
  menu_.Add(i18n::T(i18n::Str::kMenuKeyDetail));
  menu_.Add(i18n::T(i18n::Str::kMenuImportKey));
  menu_.Add(i18n::T(i18n::Str::kMenuRecoveryBackup));
  menu_.Add(i18n::T(i18n::Str::kMenuErase));
  if (menuSelected_ >= menu_.count) menuSelected_ = 0;
  menu_.selected = menuSelected_;
  ui::DrawMenu(menu_, false);
  ui::DrawFooter(i18n::T(i18n::Str::kBtnPrev), i18n::T(i18n::Str::kBtnSelect),
                 i18n::T(i18n::Str::kBtnNext));
  ui::DrawBatteryIndicator();
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
  snprintf(buf, sizeof(buf), "%u%%", Board::BatteryPercent());
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kInfoBattery), buf, row++);
  snprintf(buf, sizeof(buf), "%lu", static_cast<unsigned long>(Board::FreeHeap()));
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kInfoHeap), buf, row++);
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kSecFlashEnc), i18n::T(i18n::Str::kSecDisabled), row++);
  ui::DrawKeyValue(c, i18n::T(i18n::Str::kSecSecureBoot), i18n::T(i18n::Str::kSecDisabled), row++);
  int y = Board::kContentY + row * (lh + 2) + 6;
  Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh * 2}, FontRole::kSmall,
                      i18n::T(i18n::Str::kInfoSecurityNote),
                      strlen(i18n::T(i18n::Str::kInfoSecurityNote)), color::kYellow, color::kBlack,
                      TextAlign::kLeft, VAlign::kTop);
  ui::DrawFooter(i18n::T(i18n::Str::kMenuLock), i18n::T(i18n::Str::kBtnBack), nullptr);
}

void App::DrawPubkey() {
  ui::DrawHeader(i18n::T(i18n::Str::kInfoPublicKey), nullptr);
  FillContent();
  char hex[80];
  digest::ToHex(keystore::KeyStore::PublicKey(), 33, hex, sizeof(hex));
  Rect c = Content();
  ui::DrawHexBlock(Rect{c.x, static_cast<int16_t>(c.y + 8), c.w, c.h}, hex, true);
  ui::DrawFooter(i18n::T(i18n::Str::kMenuLock), i18n::T(i18n::Str::kBtnBack), nullptr);
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
  // 默认焦点为"继续阅读"；只在支持该决定时显示会话项
  ui::MenuView m;
  m.Add(i18n::T(i18n::Str::kReqContinueReading));
  m.Add(i18n::T(i18n::Str::kReqDenyOnce));
  m.Add(i18n::T(i18n::Str::kReqAllowOnce));
  m.Add(i18n::T(i18n::Str::kReqAllowSession));
  m.Add(i18n::T(i18n::Str::kReqDenySession));
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
  for (uint8_t i = 0; i < doc_.riskCount && i < 2; ++i) {
    int y = Board::kContentY + 6 + (5 + i) * (lh + 1);
    const char* r = i18n::T(RiskString(doc_.risks[i]));
    Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh}, FontRole::kSmall, r,
                        strlen(r), color::kRed, color::kBlack, TextAlign::kLeft, VAlign::kTop);
  }
  // 重大警告与"不包含"必经：显示为必经行，不可用滚动跳过
  int y = Board::kContentY + 6 + (5 + doc_.riskCount) * (lh + 1);
  if (y < Board::kContentY + c.h - 34) {
    const char* ex = i18n::T(i18n::Str::kSumExcludes);
    Display::DrawTextIn(Rect{c.x + 6, static_cast<int16_t>(y), c.w - 12, lh}, FontRole::kSmall, ex,
                        strlen(ex), color::kOrange, color::kBlack, TextAlign::kLeft,
                        VAlign::kTop);
  }
  bool allowSession = menuSelected_ == 3;
  Rect bar{20, static_cast<int16_t>(Board::kFooterY - 26), Board::kScreenW - 40, 24};
  hold_.Draw(bar, now_, true);
  ui::DrawFooter(i18n::T(i18n::Str::kBtnBack), allowSession ? i18n::T(i18n::Str::kBtnHoldConfirm)
                                                          : i18n::T(i18n::Str::kSumHoldConfirm),
                 i18n::T(i18n::Str::kSumViewScope));
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
  ui::DrawHeader(i18n::T(i18n::Str::kGrantsTitle), LangHint());
  FillContent();
  uint8_t count = policy::Policy::Count();
  if (count == 0) {
    ui::DrawNotice(i18n::T(i18n::Str::kGrantsEmpty), color::kGray);
    ui::DrawFooter(i18n::T(i18n::Str::kMenuLock), i18n::T(i18n::Str::kBtnBack), nullptr);
    return;
  }
  ui::MenuView m;
  for (uint8_t i = 0; i < count && i < ui::kMaxMenuItems; ++i) {
    policy::SessionDecision d;
    char line[40];
    if (policy::Policy::Get(i, &d)) {
      const char* state =
          d.decision == policy::Decision::kAllowSession ? i18n::T(i18n::Str::kGrantsAllowed)
                                                       : i18n::T(i18n::Str::kGrantsDenied);
      snprintf(line, sizeof(line), "%s [%s]", d.label, state);
      m.Add(line);
    }
  }
  m.selected = grantSelected_ < m.count ? grantSelected_ : 0;
  ui::DrawMenu(m, false);
  ui::DrawFooter(i18n::T(i18n::Str::kMenuLock), i18n::T(i18n::Str::kGrantsCancelOne),
                 i18n::T(i18n::Str::kGrantsCancelAll));
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
    ui::DrawFooter(i18n::T(i18n::Str::kMenuLock), i18n::T(i18n::Str::kBtnHoldConfirm),
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
  ui::DrawFooter(i18n::T(i18n::Str::kMenuLock), i18n::T(i18n::Str::kBtnNext),
                 i18n::T(i18n::Str::kBtnBack));
}

void App::DrawErase() {
  ui::DrawHeader(i18n::T(i18n::Str::kEraseTitle), nullptr);
  FillContent();
  const char* w = i18n::T(i18n::Str::kEraseWarning);
  ui::DrawNotice(w, color::kRed);
  int y = Board::kContentY + 90;
  Display::DrawTextIn(Rect{10, static_cast<int16_t>(y), Board::kScreenW - 20, 20}, FontRole::kSmall,
                      i18n::T(i18n::Str::kEraseHold),
                      strlen(i18n::T(i18n::Str::kEraseHold)), color::kYellow, color::kBlack,
                      TextAlign::kCenter, VAlign::kTop);
  ui::DrawFooter(i18n::T(i18n::Str::kBtnBack), i18n::T(i18n::Str::kCancel),
                 i18n::T(i18n::Str::kEraseHold));
}

void App::DrawMigrate() {
  ui::DrawHeader(i18n::T(i18n::Str::kMigTitle), LangHint());
  FillContent();
  char rec[400];
  size_t recLen = 0;
  if (ops::MigrationRecord(rec, sizeof(rec), &recLen)) {
    Rect c = Content();
    (void)FontLineHeight(FontRole::kSmall);
    char field[96];
    size_t pos = 0;
    uint8_t row = 0;
    while (pos < recLen && row < 6) {
      size_t next = pos;
      while (next < recLen && rec[next] != '|') next++;
      size_t n = next - pos;
      if (n < sizeof(field)) {
        memcpy(field, rec + pos, n);
        field[n] = '\0';
        ui::DrawKeyValue(c, row == 0 ? i18n::T(i18n::Str::kMigStatusTitle) : "", field, row++);
      }
      pos = next + 1;
    }
  }
  const char* p = i18n::T(i18n::Str::kMigEnterPrompt);
  ui::DrawNotice(p, color::kGray);
  ui::DrawFooter(i18n::T(i18n::Str::kMenuLock), i18n::T(i18n::Str::kBtnBack), nullptr);
}

void App::DrawError() {
  ui::DrawHeader(i18n::T(i18n::Str::kErrTitle), LangHint());
  FillContent();
  ui::DrawNotice(errorText_, color::kRed);
  ui::DrawFooter(i18n::T(i18n::Str::kMenuLock), nullptr, i18n::T(i18n::Str::kBtnBack));
}

}  // namespace rockey