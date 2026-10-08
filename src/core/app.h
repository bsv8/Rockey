// 设备主状态机：屏幕、请求队列、授权流程与锁定生命周期。
#ifndef ROCKEY_CORE_APP_H
#define ROCKEY_CORE_APP_H

#include <stdint.h>

#include "board/buttons.h"
#include "store/keystore.h"
#include "ops/dispatch.h"
#include "ops/review.h"
#include "proto/link.h"
#include "ui/widgets.h"

namespace rockey {

class App {
 public:
  enum class Screen : uint8_t {
    kBoot,
    kLock,
    kSetPin,
    kSetPinConfirm,
    kWaitPin,
    kPairing,
    kMenu,
    kInfo,
    kPubkey,
    kReader,
    kReqMenu,
    kSummary,
    kDenyConfirm,
    kGrants,
    kBackup,
    kErase,
    kMigrate,
    kError,
  };

  void Begin();
  void Loop();

  bool SelfTest();

 private:
  // 屏幕
  void Go(Screen s);
  void Draw();
  void DrawBoot();
  void DrawLock();
  void DrawSetPin();
  void DrawWait();
  void DrawPairing();
  void DrawMenu();
  void DrawInfo();
  void DrawPubkey();
  void DrawReader();
  void DrawReqMenu();
  void DrawSummaryScreen();
  void DrawDenyConfirm();
  void DrawGrants();
  void DrawBackup();
  void DrawErase();
  void DrawMigrate();
  void DrawError();

  void OnButton(Btn btn, BtnEvent ev);
  void HandleLockInput(Btn btn, BtnEvent ev);
  void HandleSetPinInput(Btn btn, BtnEvent ev);
  void HandleReaderInput(Btn btn, BtnEvent ev);
  void HandleReqMenuInput(Btn btn, BtnEvent ev);
  void HandleMenuInput(Btn btn, BtnEvent ev);
  void HandleGrantsInput(Btn btn, BtnEvent ev);

  // 请求
  void OnEnvelope(const proto::Envelope& env);
  void PumpQueue();
  void PresentCurrent();
  void Decide(policy::Decision d);
  void ExecuteCurrent();
  void FinishRequest(ops::ErrorCode code, const uint8_t* payload, size_t len);
  void LockNow(const char* reason);

  void ResetPinEntry();
  void AppendDigit(uint8_t d);
  void DeleteDigit();
  void SubmitPin();

  void ShowErrorScreen(ops::ErrorCode e);

  // 状态
  Screen screen_ = Screen::kBoot;
  Screen prevScreen_ = Screen::kBoot;
  bool needsRedraw_ = true;
  uint32_t now_ = 0;
  uint32_t lastRequestId_ = 0;
  uint32_t bootMs_ = 0;

  Buttons buttons_;
  proto::Link link_;
  ui::Reader reader_;
  ui::HoldConfirm hold_;
  ui::MenuView menu_;
  ops::ReviewDoc doc_;

  // PIN
  char pin_[ROCKEY_PIN_MAX_DIGITS + 1] = {0};
  uint8_t pinLen_ = 0;
  uint8_t pinDigit_ = 0;
  char newPin_[ROCKEY_PIN_MAX_DIGITS + 1] = {0};
  uint8_t newPinLen_ = 0;
  bool pinMenuOpen_ = false;
  uint8_t waitSecondsLeft_ = 0;
  bool waitTicking_ = false;
  uint32_t lastWaitSecond_ = 0;

  // 请求队列
  struct Pending {
    bool active = false;
    uint32_t requestId = 0;
    uint32_t sessionId = 0;
    uint8_t sessionEpoch = 0;
    uint32_t decisionRevisionAtParse = 0;
    uint8_t commitment[32] = {0};
    uint8_t body[ROCKEY_MAX_PLAINTEXT] = {0};
    size_t bodyLen = 0;
    ops::ExecContext exec{};
    uint32_t receivedMs = 0;
  };
  Pending queue_[ROCKEY_MAX_QUEUE];
  uint8_t queueCount_ = 0;
  int current_ = -1;

  // 评审页状态
  uint8_t summaryScroll_ = 0;
  uint8_t menuSelected_ = 0;
  uint8_t grantSelected_ = 0;
  ops::ErrorCode errorCode_ = ops::ErrorCode::kOk;
  char errorText_[96] = {0};
  char infoLine_[64] = {0};
  bool migrationArmed_ = false;
  // 恢复备份
  char recoveryCode_[27] = {0};
  uint8_t recoveryBlob_[192] = {0};
  size_t recoveryBlobLen_ = 0;
  bool backupReady_ = false;
  uint8_t backupScroll_ = 0;
};

}  // namespace rockey

#endif  // ROCKEY_CORE_APP_H