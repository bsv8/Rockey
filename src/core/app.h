// 设备主状态机：屏幕、请求队列、授权流程与锁定生命周期。
#ifndef ROCKEY_CORE_APP_H
#define ROCKEY_CORE_APP_H

#include <stdint.h>
#include <memory>
#include <vector>

#include "board/buttons.h"
#include "store/keystore.h"
#include "ops/dispatch.h"
#include "ops/review.h"
#include "proto/link.h"
#include "ui/widgets.h"
#include "../../Coding/Rockey/device-ui/channel_settings.hpp"

namespace rockey {
namespace vlp { class Controller; }

class App {
 public:
  App();
  ~App();
  enum class Screen : uint8_t {
    kBoot,
    kLock,
    kSetPin,
    kSetPinConfirm,
    kNetworkChoice,
    kInitializeChoice,
    kImport,
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
    kChannels,
    kBackup,
    kErase,
    kMigrate,
    kError,
  };

  void Begin();
  void Loop();

  bool SelfTest();

 private:
#if defined(ROCKEY_HOST_UI_TEST)
  // 宿主界面回归访问实际导航器；正式固件不编译该入口。
  friend struct NavigationProbe;
#endif
#if defined(ROCKEY_DEV_BUTTON_API)
  // 只在隔离测试固件链接，不能变成正常钱包 RPC。
  std::vector<uint8_t> DevTestControl(const std::vector<uint8_t>& command);
  uint32_t testRestartAt_=0;
#endif
  ui::ChannelSettings channelSettings_;
  // 屏幕
  void Go(Screen s);
  void Draw();
  void DrawBoot();
  bool emptyImportBusy_=false;
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
  void HandleSummaryInput(Btn btn, BtnEvent ev);
  bool RequiredContentSeen() const;
  void MarkRequiredProgress();
  void HandleDenyConfirmInput(Btn btn, BtnEvent ev);
  void HandleEraseInput(Btn btn, BtnEvent ev);
  uint8_t SummaryScrollMax() const;
  // 当前请求是否允许"会话级"决定。私钥导出/迁移/恢复备份只给一次性的
  // 允许/拒绝（需求 §5），菜单因此根本不显示会话项，而不是显示了再降级。
  bool SessionDecisionOffered() const;

  void OnEnvelope(const proto::Envelope& env);
  void OnCancelRequest(uint32_t requestId);
  void SendStateEvent(proto::DeviceState ds);
  void ClearQueues();
  void RecordOutcome(uint32_t requestId, ops::ErrorCode code);
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
  std::unique_ptr<vlp::Controller> vaultlink_;
  proto::Link link_;
  ui::Reader reader_;
  ui::HoldConfirm hold_;
  ui::MenuView menu_;
  ops::ReviewDoc doc_;

  // PIN
  char pin_[ROCKEY_PIN_MAX_DIGITS + 1] = {0};
  uint8_t pinLen_ = 0;
  uint8_t pinDigit_ = 0;
  bool pinRowDrawn_ = false;
  uint8_t drawnPinLen_ = 0;
  uint8_t drawnPinDigit_ = 0;
  keystore::BsvNetwork newKeyNetwork_ = keystore::BsvNetwork::Main;
  char newPin_[ROCKEY_PIN_MAX_DIGITS + 1] = {0};
  uint8_t newPinLen_ = 0;
  bool changingPin_ = false;
  char oldPin_[ROCKEY_PIN_MAX_DIGITS + 1] = {0};
  uint8_t oldPinLen_ = 0;
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
  // 密码学自检未通过：拒绝一切业务请求（需求 §2/RK-09）
  bool selftestFailed_ = false;
  // 结果缓存已满：拒绝新请求，而不是遗忘旧 requestId 后放行
  bool outcomeCacheFull_ = false;
  // 擦除页的长按起点（0 = 未按住）；离开该页必须清零
  uint32_t eraseHoldMs_ = 0;
  // 必需内容门禁：已看过的必需条数，以及“刚被拦住”的提示标志
  uint16_t gateSeen_ = 0;
  bool gateBlocked_ = false;

  // 本次连接内已完成请求的结论缓存（防 requestId 重放二次执行）
  struct Outcome {
    uint32_t requestId = 0;
    uint8_t code = 0;
    bool used = false;
  };
  Outcome outcomes_[ROCKEY_MAX_RESULT_CACHE]{};

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
  // 设备事件序号（单调递增，主机忽略旧事件）
  uint32_t eventSeq_ = 0;
};

}  // namespace rockey

#endif  // ROCKEY_CORE_APP_H
