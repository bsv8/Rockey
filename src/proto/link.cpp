#include "proto/link.h"

#include <Arduino.h>
#include <string.h>

#include "crypto/aead.h"
#include "crypto/digest.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/x25519.h"
#include "core/log.h"
#include "i18n/i18n.h"
#include "proto/cbor.h"
#include "store/keystore.h"

namespace rockey {
namespace proto {
namespace {

constexpr const char* kTranscriptLabel = "rockey:handshake:v1";
constexpr const char* kPairingLabel = "rockey:link:pairing:v1";
constexpr const char* kC2SKeyInfo = "rockey:link:c2s:key:v1";
constexpr const char* kC2SNonceInfo = "rockey:link:c2s:nonce:v1";
constexpr const char* kS2CKeyInfo = "rockey:link:s2c:key:v1";
constexpr const char* kS2CNonceInfo = "rockey:link:s2c:nonce:v1";

void AppendU32(uint8_t* buf, size_t* n, uint32_t v) {
  buf[(*n)++] = static_cast<uint8_t>(v >> 24);
  buf[(*n)++] = static_cast<uint8_t>(v >> 16);
  buf[(*n)++] = static_cast<uint8_t>(v >> 8);
  buf[(*n)++] = static_cast<uint8_t>(v);
}

constexpr size_t kCapabilities[] = {
    0x0001,  // SYSTEM/INFO
    0x0011,  // IDENTITY/prove
    0x0012,  // IDENTITY/authorize
    0x0021,  // TRANSACTION/p2pkh-sign
    0x0031,  // CHANNEL/public-message
    0x0032,  // CHANNEL/hash-request
    0x0033,  // CHANNEL/private-message
    0x0034,  // CHANNEL/seal
    0x0035,  // CHANNEL/open
    0x0041,  // LOCAL_SECRET/seal
    0x0042,  // LOCAL_SECRET/open
    0x0051,  // CONTENT/attest-digest
    0x0061,  // EVIDENCE/receive
    0x0071,  // MIGRATION/import
    0x0072,  // MIGRATION/export
    0x0073,  // MIGRATION/status
    0x0081,  // RECOVERY/backup
};

}  // namespace

void Link::Begin(uint32_t nowMs) {
  state_ = LinkState::kAwaitHello;
  error_ = LinkError::kNone;
  memset(&pairing_, 0, sizeof(pairing_));
  reader_.Reset();
  txSeq_ = 0;
  eventSeq_ = 0;
  encFrames_ = 0;
  decFails_ = 0;
  counter_[0] = counter_[1] = 0;
  rxSeen_[0] = rxSeen_[1] = false;
  lastHostRxMs_ = nowMs;
  lastTxMs_ = nowMs;
  ClearSessions();

  deviceRunId_ = rand::U32();
  if (deviceRunId_ == 0) deviceRunId_ = 1;
  rand::Fill(deviceNonce_, sizeof(deviceNonce_));

  // X25519 临时密钥（自实现，RFC 7748，见 crypto/x25519.cpp）
  rand::Fill(deviceEphPriv_.data(), 32);
  x25519::PublicFromPrivate(deviceEphPriv_.data(), deviceEphPub_);
}

void Link::Reset() {
  state_ = LinkState::kIdle;
  error_ = LinkError::kNone;
  memset(&pairing_, 0, sizeof(pairing_));
  key_[0].Clear();
  key_[1].Clear();
  deviceEphPriv_.Clear();
  memset(baseNonce_, 0, sizeof(baseNonce_));
  counter_[0] = counter_[1] = 0;
  rxSeen_[0] = rxSeen_[1] = false;
  reader_.Reset();
  ClearSessions();
}

void Link::ClearSessions() {
  for (auto& s : sessions_) s = SessionSlot{};
}

uint8_t Link::SessionCount() const {
  uint8_t n = 0;
  for (const auto& s : sessions_) {
    if (s.open) n++;
  }
  return n;
}

bool Link::SessionOpen(uint32_t sessionId) const {
  for (const auto& s : sessions_) {
    if (s.open && s.id == sessionId) return true;
  }
  return false;
}

bool Link::OpenSession(uint32_t sessionId, uint8_t epoch, const HostGenerations& gens) {
  for (auto& s : sessions_) {
    if (s.open && s.id == sessionId) {
      // 同一 sessionId 重新打开：更新世代与开启时间
      s.epoch = epoch;
      s.gens = gens;
      s.openedMs = millis();
      return true;
    }
  }
  for (auto& s : sessions_) {
    if (!s.open) {
      s.id = sessionId;
      s.epoch = epoch;
      s.gens = gens;
      s.open = true;
      s.openedMs = millis();
      return true;
    }
  }
  return false;  // 槽位已满
}

bool Link::CloseSession(uint32_t sessionId) {
  for (auto& s : sessions_) {
    if (s.open && s.id == sessionId) {
      s = SessionSlot{};
      return true;
    }
  }
  return false;
}

bool Link::MarkPairingUserConfirmed() {
  if (!pairing_.required) return true;
  pairing_.userConfirmed = true;
  return true;
}

void Link::BuildNonce(Dir d, uint64_t counter, uint8_t nonce[12]) {
  uint8_t base[12];
  memcpy(base, baseNonce_[static_cast<int>(d)], 12);
  uint8_t ctr[12];
  memset(ctr, 0, 12);
  for (int i = 0; i < 8; ++i) ctr[11 - i] = static_cast<uint8_t>(counter >> (8 * i));
  // 96 位加法进位
  int carry = 0;
  for (int i = 11; i >= 0; --i) {
    int sum = base[i] + ctr[i] + carry;
    carry = sum >> 8;
    nonce[i] = static_cast<uint8_t>(sum & 0xFF);
  }
}

bool Link::DeriveKeys(const uint8_t hostEphPub[32], const uint8_t hostNonce[32],
                     const HostGenerations& gens) {
  uint8_t shared[32];
  if (!x25519::Shared(deviceEphPriv_.data(), hostEphPub, shared)) {
    RK_LOGE("link", "x25519 shared failed");
    return false;
  }
  memcpy(hostEphPub_, hostEphPub, 32);

  // transcript（两端必须逐字节一致）
  uint8_t t[512];
  size_t n = strlen(kTranscriptLabel);
  memcpy(t, kTranscriptLabel, n);
  t[n++] = ROCKEY_PROTOCOL_VERSION;
  memcpy(t + n, hostNonce, 32);
  n += 32;
  memcpy(t + n, deviceNonce_, 32);
  n += 32;
  memcpy(t + n, hostEphPub_, 32);
  n += 32;
  memcpy(t + n, deviceEphPub_, 32);
  n += 32;
  AppendU32(t, &n, deviceRunId_);
  AppendU32(t, &n, gens.hostRunGeneration);
  AppendU32(t, &n, gens.walletGeneration);
  AppendU32(t, &n, gens.backendGeneration);
  memcpy(t + n, keystore::KeyStore::PublicKey(), 33);
  n += 33;

  uint8_t transcript[32];
  digest::Sha256(t, n, transcript);

  digest::HkdfSha256(shared, 32, transcript, 32, reinterpret_cast<const uint8_t*>(kC2SKeyInfo),
                     strlen(kC2SKeyInfo), key_[static_cast<int>(Dir::kS2C)].data(), 32);
  digest::HkdfSha256(shared, 32, transcript, 32, reinterpret_cast<const uint8_t*>(kC2SNonceInfo),
                     strlen(kC2SNonceInfo), baseNonce_[static_cast<int>(Dir::kS2C)], 12);
  digest::HkdfSha256(shared, 32, transcript, 32, reinterpret_cast<const uint8_t*>(kS2CKeyInfo),
                     strlen(kS2CKeyInfo), key_[static_cast<int>(Dir::kC2S)].data(), 32);
  digest::HkdfSha256(shared, 32, transcript, 32, reinterpret_cast<const uint8_t*>(kS2CNonceInfo),
                     strlen(kS2CNonceInfo), baseNonce_[static_cast<int>(Dir::kC2S)], 12);

  // 配对码：SHA256("rockey:link:pairing:v1" || transcript) 的 6 位十进制
  uint8_t pbuf[64];
  size_t pl = strlen(kPairingLabel);
  memcpy(pbuf, kPairingLabel, pl);
  memcpy(pbuf + pl, transcript, 32);
  uint8_t ph[32];
  digest::Sha256(pbuf, pl + 32, ph);
  uint32_t v = (static_cast<uint32_t>(ph[0]) << 16) | (static_cast<uint32_t>(ph[1]) << 8) | ph[2];
  for (int i = 0; i < 6; ++i) {
    pairing_.code[i] = static_cast<char>('0' + (v % 10));
    v /= 10;
  }
  pairing_.code[6] = '\0';

  secure::Wipe(shared, sizeof(shared));
  secure::Wipe(t, sizeof(t));
  secure::Wipe(ph, sizeof(ph));
  return true;
}

bool Link::SendRaw(FrameType type, uint8_t flags, const uint8_t* payload, size_t len) {
  size_t framed = 0;
  if (!EncodeFrame(out_, sizeof(out_), type, flags, txSeq_++, payload, len, &framed)) return false;
  return Serial.write(out_, framed) == framed;
}

bool Link::EncryptFrame(FrameType type, uint8_t flags, const uint8_t* pt, size_t ptLen) {
  if (state_ == LinkState::kIdle || state_ == LinkState::kAwaitHello) return false;
  if (ptLen + aead::kTagLen > ROCKEY_MAX_FRAME_PAYLOAD) return false;
  uint8_t nonce[12];
  BuildNonce(Dir::kS2C, counter_[static_cast<int>(Dir::kS2C)]++, nonce);
  // AAD 覆盖帧头字段，使 type/flags/seq 也在认证范围内
  uint8_t aad[8];
  aad[0] = static_cast<uint8_t>(type);
  aad[1] = flags;
  uint32_t seq = txSeq_;
  memcpy(aad + 2, &seq, 4);
  memcpy(aad + 6, &deviceRunId_, 4);
  static uint8_t wire[ROCKEY_MAX_FRAME_PAYLOAD];
  uint8_t tag[aead::kTagLen];
  if (!aead::Seal(key_[static_cast<int>(Dir::kS2C)].data(), nonce, aad, sizeof(aad), pt, ptLen,
                        wire, tag)) {
    return false;
  }
  memcpy(wire + ptLen, tag, aead::kTagLen);
  encFrames_++;
  return SendRaw(type, flags, wire, ptLen + aead::kTagLen);
}

bool Link::DecryptFrame(const Frame& f, uint8_t* out, size_t outCap, size_t* outLen,
                        uint32_t* outSeq) {
  if (f.len < aead::kTagLen) return false;
  // 序号必须严格递增：拒绝重放与乱序
  int d = static_cast<int>(Dir::kS2C);
  if (rxSeen_[d] && f.seq <= lastRxSeq_[d]) {
    error_ = LinkError::kReplay;
    decFails_++;
    return false;
  }
  size_t ctLen = f.len - aead::kTagLen;
  if (ctLen > outCap) return false;
  uint8_t nonce[12];
  BuildNonce(Dir::kS2C, counter_[static_cast<int>(Dir::kS2C)]++, nonce);
  uint8_t aad[8];
  aad[0] = static_cast<uint8_t>(f.type);
  aad[1] = f.flags;
  memcpy(aad + 2, &f.seq, 4);
  memcpy(aad + 6, &deviceRunId_, 4);
  if (!aead::Open(key_[static_cast<int>(Dir::kS2C)].data(), nonce, aad, sizeof(aad), f.payload,
                        ctLen, f.payload + ctLen, out)) {
    error_ = LinkError::kDecryptFailed;
    decFails_++;
    return false;
  }
  lastRxSeq_[d] = f.seq;
  rxSeen_[d] = true;
  *outLen = ctLen;
  *outSeq = f.seq;
  return true;
}

bool Link::HandshakeWithHello(const uint8_t* payload, size_t len, uint32_t nowMs) {
  Reader r(payload, len);
  size_t pairs = r.MapBegin();
  if (pairs == 0 || pairs > 12 || !r.ok()) return false;

  uint64_t version = 0;
  uint8_t hostNonce[32];
  bool haveVersion = false, haveNonce = false, haveEph = false;
  uint8_t hostEphPub[32];
  HostGenerations gens{};

  // 键顺序按确定性编码递增校验（Reader 已强制），此处只关心内容
  for (size_t i = 0; i < pairs; ++i) {
    size_t klen = 0;
    const char* key = r.MapKey(&klen);
    if (!key) return false;
    if (klen == 7 && memcmp(key, "hostEph", 7) == 0) {
      size_t n = 0;
      const uint8_t* p = r.Bytes(&n);
      if (!p || n != 32) return false;
      memcpy(hostEphPub, p, 32);
      haveEph = true;
    } else if (klen == 9 && memcmp(key, "hostNonce", 9) == 0) {
      size_t n = 0;
      const uint8_t* p = r.Bytes(&n);
      if (!p || n != 32) return false;
      memcpy(hostNonce, p, 32);
      haveNonce = true;
    } else if (klen == 12 && memcmp(key, "capabilities", 12) == 0) {
      r.SkipItem();
    } else if (klen == 13 && memcmp(key, "runGeneration", 13) == 0) {
      gens.hostRunGeneration = static_cast<uint32_t>(r.Uint());
    } else if (klen == 15 && memcmp(key, "protocolVersion", 15) == 0) {
      version = r.Uint();
      haveVersion = true;
    } else if (klen == 16 && memcmp(key, "backendGeneration", 16) == 0) {
      gens.backendGeneration = static_cast<uint32_t>(r.Uint());
    } else if (klen == 16 && memcmp(key, "walletGeneration", 16) == 0) {
      gens.walletGeneration = static_cast<uint32_t>(r.Uint());
    } else {
      return false;  // 未知键拒绝：不允许静默忽略
    }
  }
  r.EndMap();
  if (!r.ok()) return false;
  if (!haveVersion) return false;
  if (version != ROCKEY_PROTOCOL_VERSION) {
    error_ = LinkError::kVersionMismatch;
    RK_LOGW("link", "protocol version mismatch");
    return false;
  }
  if (!haveNonce || !haveEph) {
    error_ = LinkError::kBadHello;
    return false;
  }
  if (!DeriveKeys(hostEphPub, hostNonce, gens)) {
    error_ = LinkError::kBadHello;
    return false;
  }
  state_ = LinkState::kPaired;
  pairing_.required = true;
  pairing_.userConfirmed = false;
  lastHostRxMs_ = nowMs;
  counter_[0] = counter_[1] = 0;
  rxSeen_[0] = rxSeen_[1] = false;
  return true;
}

bool Link::SendHelloAck() {
  Writer w(out_, sizeof(out_));
  w.BeginMap(11);
  w.Key("capabilities");
  w.BeginArray(sizeof(kCapabilities) / sizeof(kCapabilities[0]));
  for (size_t i = 0; i < sizeof(kCapabilities) / sizeof(kCapabilities[0]); ++i) w.Uint(kCapabilities[i]);
  w.EndArray();
  w.Key("deviceNonce");
  w.Bytes(deviceNonce_, 32);
  w.Key("deviceRunId");
  w.Uint(deviceRunId_);
  w.Key("deviceEph");
  w.Bytes(deviceEphPub_, 32);
  w.Key("firmwareBuildId");
  w.Text(ROCKEY_FIRMWARE_BUILD_ID);
  w.Key("language");
  w.Text(i18n::LangTag());
  w.Key("pairingRequired");
  w.Bool(true);
  w.Key("protocolVersion");
  w.Uint(ROCKEY_PROTOCOL_VERSION);
  w.Key("publicKey");
  w.Bytes(keystore::KeyStore::PublicKey(), 33);
  w.Key("state");
  w.Uint(keystore::KeyStore::HasKey() ? 2u : 0u);
  w.Key("supportsLockedInfo");
  w.Bool(true);
  w.EndMap();
  if (!w.ok()) return false;
  return SendRaw(FrameType::kHelloAck, 0, out_, w.size());
}

bool Link::SendPairOk() {
  Writer w(out_, sizeof(out_));
  w.BeginMap(2);
  w.Key("paired");
  w.Bool(true);
  w.Key("protocolVersion");
  w.Uint(ROCKEY_PROTOCOL_VERSION);
  w.EndMap();
  if (!w.ok()) return false;
  return EncryptFrame(FrameType::kPairOk, 0, out_, w.size());
}

bool Link::SendError(uint32_t requestId, uint16_t errorCode) {
  Writer w(out_, sizeof(out_));
  w.BeginMap(2);
  w.Key("error");
  w.Uint(errorCode);
  w.Key("requestId");
  w.Uint(requestId);
  w.EndMap();
  if (!w.ok()) return false;
  return EncryptFrame(FrameType::kResponse, 0, out_, w.size());
}

bool Link::SendResponse(uint32_t requestId, const uint8_t* payload, size_t len) {
  uint8_t tmp[ROCKEY_MAX_FRAME_PAYLOAD];
  Writer w(tmp, sizeof(tmp));
  w.BeginMap(2);
  w.Key("payload");
  if (payload && len) {
    w.Bytes(payload, len);
  } else {
    w.BytesNull();
  }
  w.Key("requestId");
  w.Uint(requestId);
  w.EndMap();
  if (!w.ok()) return false;
  return EncryptFrame(FrameType::kResponse, 0, tmp, w.size());
}

bool Link::SendEvent(uint32_t eventSeq, const uint8_t* payload, size_t len) {
  uint8_t tmp[ROCKEY_MAX_FRAME_PAYLOAD];
  Writer w(tmp, sizeof(tmp));
  w.BeginMap(3);
  w.Key("eventSeq");
  w.Uint(eventSeq);
  w.Key("payload");
  if (payload && len) w.Bytes(payload, len);
  else w.BytesNull();
  w.Key("deviceRunId");
  w.Uint(deviceRunId_);
  w.EndMap();
  if (!w.ok()) return false;
  eventSeq_ = eventSeq;
  return EncryptFrame(FrameType::kEvent, 0, tmp, w.size());
}

bool Link::SendPing() {
  uint8_t tmp[64];
  Writer w(tmp, sizeof(tmp));
  w.BeginMap(2);
  w.Key("deviceRunId");
  w.Uint(deviceRunId_);
  w.Key("nonce");
  w.Uint(rand::U32());
  w.EndMap();
  if (!w.ok()) return false;
  return EncryptFrame(FrameType::kPing, 0, tmp, w.size());
}

bool Link::SendAbort(LinkError reason) {
  uint8_t tmp[64];
  Writer w(tmp, sizeof(tmp));
  w.BeginMap(1);
  w.Key("reason");
  w.Uint(static_cast<uint64_t>(reason));
  w.EndMap();
  if (!w.ok()) return false;
  bool ok = EncryptFrame(FrameType::kAbort, 0, tmp, w.size());
  Reset();
  return ok;
}

bool Link::ProvePossession(const uint8_t challenge[32], uint8_t sigDer[72], size_t* sigLen) {
  if (!keystore::KeyStore::IsUnlocked()) return false;
  const uint8_t* priv = keystore::KeyStore::PrivateKey();
  if (!priv) return false;
  size_t cap = *sigLen;
  if (!secp::SignDer(priv, challenge, sigDer, &cap)) return false;
  *sigLen = cap;
  return true;
}

bool Link::HandleEncrypted(FrameType type, uint8_t flags, uint32_t seq, const uint8_t* pt,
                           size_t len, RequestHandler handler, void* user, uint32_t nowMs) {
  lastHostRxMs_ = nowMs;
  switch (type) {
    case FrameType::kPing: {
      uint8_t tmp[64];
      Writer w(tmp, sizeof(tmp));
      w.BeginMap(1);
      w.Key("nonce");
      w.Uint(0);
      w.EndMap();
      if (w.ok()) EncryptFrame(FrameType::kPong, 0, tmp, w.size());
      return true;
    }
    case FrameType::kPong:
      return true;
    case FrameType::kPairConfirm: {
      Reader r(pt, len);
      size_t pairs = r.MapBegin();
      if (pairs != 1 || !r.ExpectKey("code") || !r.ok()) return false;
      size_t n = 0;
      const char* code = r.Text(&n);
      r.EndMap();
      if (!code || n != 6) return false;
      if (!pairing_.userConfirmed) return false;
      if (memcmp(code, pairing_.code, 6) != 0) {
        error_ = LinkError::kUnauthorized;
        return false;
      }
      pairing_.required = false;
      state_ = LinkState::kEstablished;
      return SendPairOk();
    }
    case FrameType::kAbort: {
      Reset();
      return true;
    }
    case FrameType::kRequest: {
      if (!pairing_.required) {
        Envelope env;
        Reader r(pt, len);
        size_t pairs = r.MapBegin();
        if (pairs == 0 || pairs > 24 || !r.ok()) return false;
        uint32_t requestId = 0, sessionId = 0;
        uint8_t epoch = 0;
        HostGenerations gens{};
        uint8_t commitment[32] = {0};
        const uint8_t* body = nullptr;
        size_t bodyLen = 0;
        bool haveBody = false;
        for (size_t i = 0; i < pairs; ++i) {
          size_t klen = 0;
          const char* k = r.MapKey(&klen);
          if (!k) return false;
          if (klen == 9 && memcmp(k, "requestId", 9) == 0) {
            requestId = static_cast<uint32_t>(r.Uint());
          } else if (klen == 9 && memcmp(k, "sessionId", 9) == 0) {
            sessionId = static_cast<uint32_t>(r.Uint());
          } else if (klen == 11 && memcmp(k, "sessionEpoch", 11) == 0) {
            epoch = static_cast<uint8_t>(r.Uint());
          } else if (klen == 13 && memcmp(k, "runGeneration", 13) == 0) {
            gens.hostRunGeneration = static_cast<uint32_t>(r.Uint());
          } else if (klen == 9 && memcmp(k, "walletGen", 9) == 0) {
            gens.walletGeneration = static_cast<uint32_t>(r.Uint());
          } else if (klen == 10 && memcmp(k, "backendGen", 10) == 0) {
            gens.backendGeneration = static_cast<uint32_t>(r.Uint());
          } else if (klen == 10 && memcmp(k, "commitment", 10) == 0) {
            size_t n = 0;
            const uint8_t* p = r.Bytes(&n);
            if (!p || n != 32) return false;
            memcpy(commitment, p, 32);
          } else if (klen == 4 && memcmp(k, "body", 4) == 0) {
            body = r.Bytes(&bodyLen);
            haveBody = true;
          } else {
            return false;  // 未知键拒绝
          }
        }
        r.EndMap();
        if (!r.ok() || !haveBody || body == nullptr) return false;
        if (!SessionOpen(sessionId)) return false;
        env.seq = seq;
        env.requestId = requestId;
        env.sessionId = sessionId;
        env.sessionEpoch = epoch;
        env.gens = gens;
        memcpy(env.commitment, commitment, 32);
        env.body = body;
        env.bodyLen = bodyLen;
        if (handler) handler(env, user);
      }
      return true;
    }
    default:
      return false;
  }
}

void Link::Poll(uint32_t nowMs, RequestHandler handler, void* user) {
  uint8_t chunk[192];
  while (Serial.available() > 0) {
    int n = Serial.readBytes(chunk, sizeof(chunk));
    if (n <= 0) break;
    Frame f;
    while (reader_.Feed(chunk, static_cast<size_t>(n), &f)) {
      if (state_ == LinkState::kAwaitHello) {
        if (f.type != FrameType::kHello) {
          error_ = LinkError::kBadHello;
          continue;
        }
        if (HandshakeWithHello(f.payload, f.len, nowMs)) {
          SendHelloAck();
        }
        continue;
      }
      if (state_ == LinkState::kPaired || state_ == LinkState::kEstablished) {
        size_t ptLen = 0;
        uint32_t seq = 0;
        if (f.type == FrameType::kHello) continue;
        if (f.type == FrameType::kAbort) {
          Reset();
          continue;
        }
        if (!DecryptFrame(f, scratch_, sizeof(scratch_), &ptLen, &seq)) {
          continue;
        }
        HandleEncrypted(f.type, f.flags, seq, scratch_, ptLen, handler, user, nowMs);
      }
    }
    if (n < static_cast<int>(sizeof(chunk))) break;
  }
}

bool Link::Tick(uint32_t nowMs) {
  if (state_ == LinkState::kIdle || state_ == LinkState::kFailed) return true;
  if (state_ == LinkState::kAwaitHello) {
    if (nowMs - lastHostRxMs_ > ROCKEY_HANDSHAKE_TIMEOUT_MS) {
      error_ = LinkError::kTimeout;
      Reset();
      return false;
    }
    return true;
  }
  // 活跃性：主机必须按节奏发 PING 或请求，否则失活并撤权
  if (nowMs - lastHostRxMs_ > ROCKEY_LIVENESS_TIMEOUT_MS) {
    error_ = LinkError::kTimeout;
    if (idleHandler_) idleHandler_(idleUser_);
    Reset();
    return false;
  }
  static uint32_t lastPing = 0;
  if (nowMs - lastPing >= ROCKEY_LIVENESS_INTERVAL_MS) {
    lastPing = nowMs;
    SendPing();
  }
  return true;
}

}  // namespace proto
}  // namespace rockey