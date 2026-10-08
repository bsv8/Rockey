// 认证加密链路：握手、配对码、方向分离密钥、会话世代、活跃性与失活锁定。
//
// 冻结流程（docs/冻结/协议规范.md §握手）：
//   1. 主机 -> HELLO     {protocolVersion, nonce, ephPub, hostWallet/backend/runGeneration}
//   2. 设备 -> HELLO_ACK {protocolVersion, capabilities, deviceRunId, nonce, ephPub,
//                          publicKey, requiresPairing, firmwareBuildId}
//   3. shared   = X25519(deviceEphPriv, hostEphPub)
//      transcript = SHA256("rockey:handshake:v1" || 双方 nonce || 双方 ephPub ||
//                          deviceRunId || 主机三个世代 || publicKey)
//      c2s/s2c key 与 base nonce = HKDF(shared, salt=transcript, info=方向)
//      配对码 = SHA256("rockey:link:pairing:v1" || transcript) 前 3 字节 → 6 位十进制
//   4. 设备屏幕显示配对码；用户长按 B 实体确认
//   5. 主机 -> PAIR_CONFIRM {code}；设备 -> PAIR_OK
//   6. 主机 -> 请求（已加密，带主机三个世代）；设备用业务 Key 对 challenge 签名作为持有权证明
//
// 密钥/nonce 不跨 deviceRunId、connectionId 或会话复用（需求 §4）。
#ifndef ROCKEY_PROTO_LINK_H
#define ROCKEY_PROTO_LINK_H

#include <stdint.h>
#include <stddef.h>

#include "crypto/secure.h"
#include "core/rockey_config.h"
#include "proto/frame.h"

namespace rockey {
namespace proto {

enum class LinkState : uint8_t {
  kIdle,            // 未握手
  kAwaitHello,      // 已生成临时密钥，等待 HELLO
  kPaired,          // 密钥就绪，可加解密
  kEstablished,     // 已完成持有权证明与首个会话
  kFailed,          // 握手失败，已清理
};

enum class LinkError : uint8_t {
  kNone,
  kVersionMismatch,
  kBadHello,
  kDecryptFailed,
  kReplay,
  kUnauthorized,
  kTimeout,
};

struct HostGenerations {
  uint32_t hostRunGeneration = 0;
  uint32_t walletGeneration = 0;
  uint32_t backendGeneration = 0;
};

struct PairingState {
  bool required = false;      // 本连接尚未配对
  bool userConfirmed = false; // 用户已在设备上实体确认
  char code[7] = {0};         // 6 位十进制
  bool shown = false;
};

// 一个被完整接收、已通过世代检查与重放检查的请求信封
struct Envelope {
  uint32_t seq = 0;
  uint32_t requestId = 0;
  uint32_t sessionId = 0;
  uint8_t sessionEpoch = 0;
  HostGenerations gens{};
  uint8_t commitment[32] = {0};
  const uint8_t* body = nullptr;
  size_t bodyLen = 0;
};

class Link {
 public:
  void Begin(uint32_t nowMs);   // 每次上电/复位调用一次
  void Reset();                 // 断线/锁定时清空全部会话材料

  // 从传输层取字节并推进状态机；每解析出一条已解密请求就调用 handler
  using RequestHandler = void (*)(const Envelope& env, void* user);
  using IdleHandler = void (*)(void* user);
  void Poll(uint32_t nowMs, RequestHandler handler, void* user);
  void SetIdleHandler(IdleHandler h, void* user) {
    idleHandler_ = h;
    idleUser_ = user;
  }

  bool Tick(uint32_t nowMs);   // 心跳 / 超时检查；返回 false 表示已因失活而锁定

  LinkState state() const { return state_; }
  LinkError error() const { return error_; }
  const PairingState& pairing() const { return pairing_; }
  bool MarkPairingUserConfirmed();
  uint32_t deviceRunId() const { return deviceRunId_; }

  bool SendRaw(FrameType type, uint8_t flags, const uint8_t* payload, size_t len);
  bool SendHelloAck();
  bool SendPairOk();
  bool SendError(uint32_t requestId, uint16_t errorCode);
  bool SendResponse(uint32_t requestId, const uint8_t* payload, size_t len);
  bool SendEvent(uint32_t eventSeq, const uint8_t* payload, size_t len);
  bool SendPing();
  bool SendAbort(LinkError reason);

  // 会话
  bool OpenSession(uint32_t sessionId, uint8_t epoch, const HostGenerations& gens);
  bool CloseSession(uint32_t sessionId);
  bool SessionOpen(uint32_t sessionId) const;
  void ClearSessions();
  uint8_t SessionCount() const;

  // 主机持有权证明：设备用业务 Key 对 challenge 签名
  bool ProvePossession(const uint8_t challenge[32], uint8_t sigDer[72], size_t* sigLen);

  uint32_t statsEncryptedFrames() const { return encFrames_; }
  uint32_t statsDecryptFailures() const { return decFails_; }

 private:
  enum class Dir : uint8_t { kS2C = 0, kC2S = 1 };

  bool HandshakeWithHello(const uint8_t* payload, size_t len, uint32_t nowMs);
  bool DeriveKeys(const uint8_t hostEphPub[32], const uint8_t hostNonce[32],
                  const HostGenerations& gens);
  bool DecryptFrame(const Frame& f, uint8_t* out, size_t outCap, size_t* outLen, uint32_t* outSeq);
  bool EncryptFrame(FrameType type, uint8_t flags, const uint8_t* pt, size_t ptLen);
  void BuildNonce(Dir d, uint64_t counter, uint8_t nonce[12]);
  bool HandleEncrypted(FrameType type, uint8_t flags, uint32_t seq, const uint8_t* pt, size_t len,
                       RequestHandler handler, void* user, uint32_t nowMs);

  // 状态
  LinkState state_ = LinkState::kIdle;
  LinkError error_ = LinkError::kNone;
  PairingState pairing_;

  uint32_t deviceRunId_ = 0;
  uint8_t deviceNonce_[32] = {0};
  uint8_t deviceEphPub_[32] = {0};   // X25519 临时公钥
  uint8_t hostEphPub_[32] = {0};
  secure::SecretBytes<32> deviceEphPriv_{};
  secure::SecretBytes<32> key_[2];
  uint8_t baseNonce_[2][12] = {{0}};
  uint64_t counter_[2] = {0, 0};
  uint32_t lastRxSeq_[2] = {0, 0};
  bool rxSeen_[2] = {false, false};

  FrameReader reader_;
  uint8_t out_[ROCKEY_MAX_FRAME_PAYLOAD + 64]{};
  uint8_t scratch_[ROCKEY_MAX_PLAINTEXT + 64]{};
  uint32_t txSeq_ = 0;
  uint32_t eventSeq_ = 0;
  uint32_t lastHostRxMs_ = 0;
  uint32_t lastTxMs_ = 0;
  bool gotPing_ = false;
  uint32_t encFrames_ = 0;
  uint32_t decFails_ = 0;

  struct SessionSlot {
    uint32_t id = 0;
    uint8_t epoch = 0;
    HostGenerations gens{};
    bool open = false;
    uint32_t openedMs = 0;
  };
  SessionSlot sessions_[ROCKEY_MAX_SESSIONS]{};

  IdleHandler idleHandler_ = nullptr;
  void* idleUser_ = nullptr;
};

}  // namespace proto
}  // namespace rockey

#endif  // ROCKEY_PROTO_LINK_H