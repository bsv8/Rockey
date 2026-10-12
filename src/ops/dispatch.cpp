#include "ops/dispatch.h"

#include <stdio.h>
#include <string.h>

#include "crypto/aead.h"
#include "crypto/digest.h"
#include "crypto/rand.h"
#include "crypto/secp256k1.h"
#include "crypto/secure.h"
#include "crypto/x25519.h"
#include "i18n/strings.h"
#include "store/keystore.h"
#include "proto/cbor.h"
#include "store/vault_fs.h"
#include "ui/text.h"

namespace rockey {
namespace ops {
using proto::Reader;
using proto::Writer;

namespace {

constexpr uint32_t kSupportedOpVersion = 1;

void SafeCopy(char* dst, size_t cap, const char* src) {
  if (!src) {
    dst[0] = '\0';
    return;
  }
  strncpy(dst, src, cap - 1);
  dst[cap - 1] = '\0';
}

const char* OpString(OpId op) {
  switch (op) {
    case OpId::kIdentityProve: return "kOpIdentityProve";
    case OpId::kIdentityAuthorize: return "kOpIdentityAuthorize";
    case OpId::kTxSign: return "kOpTxSign";
    case OpId::kTxFeepoolSign: return "kOpTxFeepoolSign";
    case OpId::kChannelPublic: return "kOpChannelPublic";
    case OpId::kChannelHash: return "kOpChannelHash";
    case OpId::kChannelPrivate: return "kOpChannelPrivate";
    case OpId::kChannelSeal: return "kOpChannelSeal";
    case OpId::kChannelOpen: return "kOpChannelOpen";
    case OpId::kSecretSeal: return "kOpSecretSeal";
    case OpId::kSecretOpen: return "kOpSecretOpen";
    case OpId::kContentAttest: return "kOpContentAttest";
    case OpId::kMigrationImport: return "kOpMigrationImport";
    case OpId::kMigrationExport: return "kOpMigrationExport";
    default: return "kUnknown";
  }
}

i18n::Str OpStr(OpId op) {
  const char* id = OpString(op);
  i18n::Str s = i18n::StrFromId(id);
  return s == i18n::Str::kCount ? i18n::Str::kUnknown : s;
}

bool LookupOp(const char* name, size_t len, OpId* out) {
  struct Entry {
    const char* n;
    OpId id;
  };
  static const Entry kTable[] = {
      {"identity.prove", OpId::kIdentityProve},
      {"identity.authorize", OpId::kIdentityAuthorize},
      {"tx.p2pkh-sign", OpId::kTxSign},
      // 费用池签名：只在脚本/阶段/签名规则冻结后才会支持。登记 op 名是为了
      // 让主机得到"已知但当前不可用"的明确答复，而不是撞上一个未知操作的
      // 模糊错误；Prepare 对它直接拒绝，不解析任何字段（见 Prepare 内门禁）。
      {"tx.feepool-sign", OpId::kTxFeepoolSign},
      {"channel.public-message", OpId::kChannelPublic},
      {"channel.hash-request", OpId::kChannelHash},
      {"channel.private-message", OpId::kChannelPrivate},
      {"channel.seal", OpId::kChannelSeal},
      {"channel.open", OpId::kChannelOpen},
      {"secret.seal", OpId::kSecretSeal},
      {"secret.open", OpId::kSecretOpen},
      {"content.attest-digest", OpId::kContentAttest},
      {"migration.import", OpId::kMigrationImport},
      {"migration.export", OpId::kMigrationExport},
      {"migration.status", OpId::kMigrationStatus},
  };
  for (const auto& e : kTable) {
    if (strlen(e.n) == len && memcmp(e.n, name, len) == 0) {
      *out = e.id;
      return true;
    }
  }
  return false;
}

// 协议名 -> 稳定的一字节 id。持续授权按这个 id 绑定到具体协议，
// 这样"允许 protocol-a 的消息签名"不会命中 protocol-b 的请求。
// 新协议必须在这里显式登记；未登记的协议 Prepare 会拒绝。
bool ProtocolId(const char* name, uint8_t* id) {
  struct Entry { const char* n; uint8_t id; };
  static const Entry kTable[] = {
      {"messaging", 1},
      {"payment-request", 2},
      {"auth", 3},
      {"storage", 4},
  };
  for (const auto& e : kTable) {
    if (strcmp(e.n, name) == 0) {
      *id = e.id;
      return true;
    }
  }
  return false;
}

policy::Category CategoryOf(OpId op) {
  switch (op) {
    case OpId::kIdentityProve:
    case OpId::kIdentityAuthorize:
      return policy::Category::kIdentity;
    case OpId::kTxSign:
      return policy::Category::kTransaction;
    case OpId::kChannelPublic:
    case OpId::kChannelHash:
    case OpId::kChannelPrivate:
    case OpId::kChannelSeal:
    case OpId::kChannelOpen:
      return policy::Category::kChannel;
    case OpId::kSecretSeal:
    case OpId::kSecretOpen:
      return policy::Category::kLocalSecret;
    case OpId::kContentAttest:
      return policy::Category::kContent;
    case OpId::kMigrationImport:
    case OpId::kMigrationExport:
    case OpId::kMigrationStatus:
      return policy::Category::kMigration;
    default:
      return policy::Category::kSystem;
  }
}

// 匹配键缓冲：标签、文本一律带 NUL 追加，长度由 strlen 给出。
// 不用硬编码长度 —— "rockey:xxx:v1\0" 这种手数很容易数错，
// 数错就是越界读或把分隔符算进摘要里。
bool KeyBufText(uint8_t* buf, size_t cap, size_t* n, const char* text) {
  size_t t = strlen(text);
  if (*n + t + 1 > cap) return false;
  memcpy(buf + *n, text, t);
  *n += t;
  buf[(*n)++] = 0;
  return true;
}

bool KeyBufBytes(uint8_t* buf, size_t cap, size_t* n, const uint8_t* data, size_t len) {
  if (*n + len > cap) return false;
  memcpy(buf + *n, data, len);
  *n += len;
  return true;
}

void AddOperationChapter(ReviewDoc* doc, OpId op) {
  doc->AddChapter(i18n::T(i18n::Str::kSumOperation), kChapterRequired);
  doc->AddSummary(i18n::T(i18n::Str::kSumOperation), i18n::T(OpStr(op)));
}

// ── 内容摘要声明的规范摘要构造（冻结） ──────────────────────────
// digestToSign = SHA256d( UTF8("rockey:content:v1") || 0x00 || UTF8(purpose)
//                        || 0x00 || ASCII(digestHex lowercase) )
bool ContentDigest(const char* purpose, const char* digestHexLower, uint8_t out[32]) {
  static const char* kLabel = "rockey:content:v1";
  uint8_t buf[512];
  size_t n = 0;
  size_t l = strlen(kLabel);
  memcpy(buf, kLabel, l);
  n = l;
  buf[n++] = 0;
  size_t pl = strlen(purpose);
  memcpy(buf + n, purpose, pl);
  n += pl;
  buf[n++] = 0;
  size_t dl = strlen(digestHexLower);
  memcpy(buf + n, digestHexLower, dl);
  n += dl;
  digest::Sha256d(buf, n, out);
  return true;
}

// ── 身份/意图证明摘要（冻结） ──────────────────────────────────
// statementDigest = SHA256d( UTF8("rockey:identity:<kind>:v1") || 0x00
//                         || pubkey(33) || sessionId(u32be) || sessionEpoch(u8)
//                         || challenge(32) || 0x00 || UTF8(purpose) )
// kind 取 "prove" 或 "authorize"。域标签与交易/通道/内容摘要不同，
// 所以这里产生的签名不能被当成任何其它操作的签名来用。
bool IdentityProofDigest(const ExecContext& e, uint8_t out[32]) {
  uint8_t buf[256];
  size_t n = 0;
  static const char* kProveLabel = "rockey:identity:prove:v1";
  static const char* kAuthLabel = "rockey:identity:authorize:v1";
  const char* label =
      (e.op == OpId::kIdentityAuthorize) ? kAuthLabel : kProveLabel;
  if (!KeyBufText(buf, sizeof(buf), &n, label)) return false;
  if (!KeyBufBytes(buf, sizeof(buf), &n, keystore::KeyStore::PublicKey(), 33)) return false;
  uint8_t sid[4] = {static_cast<uint8_t>(e.match.sessionId >> 24),
                    static_cast<uint8_t>(e.match.sessionId >> 16),
                    static_cast<uint8_t>(e.match.sessionId >> 8),
                    static_cast<uint8_t>(e.match.sessionId)};
  if (!KeyBufBytes(buf, sizeof(buf), &n, sid, 4)) return false;
  uint8_t ep = e.match.sessionEpoch;
  if (!KeyBufBytes(buf, sizeof(buf), &n, &ep, 1)) return false;
  if (!KeyBufBytes(buf, sizeof(buf), &n, e.challenge, 32)) return false;
  if (!KeyBufText(buf, sizeof(buf), &n, e.purpose)) return false;
  digest::Sha256d(buf, n, out);
  return true;
}

// ── Channel v1 规范摘要构造（冻结，待与 Keymaster 共同固定向量） ──
bool ChannelPublicDigest(const char* protocolType, const uint8_t* msg, size_t msgLen,
                         uint8_t out[32]) {
  uint8_t buf[640];
  size_t n = 0;
  static const char* kLabel = "rockey:channel:public:v1";
  size_t l = strlen(kLabel);
  memcpy(buf, kLabel, l);
  n = l;
  buf[n++] = 0;
  size_t pl = strlen(protocolType);
  memcpy(buf + n, protocolType, pl);
  n += pl;
  buf[n++] = 0;
  if (n + msgLen > sizeof(buf)) return false;
  memcpy(buf + n, msg, msgLen);
  n += msgLen;
  digest::Sha256d(buf, n, out);
  return true;
}

bool ChannelHashDigest(const char* protocolType, const uint8_t reqDigest[32], uint8_t out[32]) {
  uint8_t buf[96];
  size_t n = 0;
  static const char* kLabel = "rockey:channel:hash:v1";
  size_t l = strlen(kLabel);
  memcpy(buf, kLabel, l);
  n = l;
  buf[n++] = 0;
  size_t pl = strlen(protocolType);
  memcpy(buf + n, protocolType, pl);
  n += pl;
  buf[n++] = 0;
  memcpy(buf + n, reqDigest, 32);
  n += 32;
  digest::Sha256d(buf, n, out);
  return true;
}

bool ChannelPrivateDigest(const char* protocolType, const uint8_t* msg, size_t msgLen,
                          uint8_t out[32]) {
  uint8_t buf[640];
  size_t n = 0;
  static const char* kLabel = "rockey:channel:private:v1";
  size_t l = strlen(kLabel);
  memcpy(buf, kLabel, l);
  n = l;
  buf[n++] = 0;
  size_t pl = strlen(protocolType);
  memcpy(buf + n, protocolType, pl);
  n += pl;
  buf[n++] = 0;
  if (n + msgLen > sizeof(buf)) return false;
  memcpy(buf + n, msg, msgLen);
  n += msgLen;
  digest::Sha256d(buf, n, out);
  return true;
}

// ── Channel seal/open 的密钥协商（域隔离，暂定，待与 Keymaster 固定向量） ──
//
// 这里必须是**确定性**的对称派生，不能每次生成随机临时密钥：
//  - seal 侧随机派生出来的公钥没有回给对端，对端无法解密；
//  - open 侧再随机一次就永远解不开上一次的密文。
//
// 现行做法：X25519 静态-静态 ECDH。
//   设备侧私钥 = HKDF-SHA256(业务私钥, salt="rockey:channel:x25519:key:v1",
//                            info = UTF8(protocolType), 32B)，并清高位
//   设备侧公钥 = X25519(base, devicePriv)
//   对端公钥   = SHA256(peer33) 清高位后当作 X25519 公钥点
//   共享秘密   = X25519(devicePriv, peerPubPoint)
//   会话密钥   = HKDF-SHA256(shared, salt=对端公钥, info="rockey:channel:seal:v1"
//                                   || 0x00 || protocolType, 32B)
//
// 这套映射是本仓库的暂定定义，**尚未与 Keymaster 的 Channel 协议对齐**；
// 对齐前不得据此声称软件↔设备互通（协议草案 §5 要求以固定向量为准）。
bool ChannelX25519Priv(const char* protocolType, uint8_t priv[32]) {
  uint8_t info[64];
  size_t n = 0;
  static const char* kLabel = "rockey:channel:x25519:key:v1";
  size_t l = strlen(kLabel);
  memcpy(info, kLabel, l);
  n = l;
  info[n++] = 0;
  size_t pl = strlen(protocolType);
  if (n + pl >= sizeof(info)) return false;
  memcpy(info + n, protocolType, pl);
  n += pl;
  digest::HkdfSha256(keystore::KeyStore::PrivateKey(), 32, nullptr, 0, info, n, priv, 32);
  priv[31] &= 127;
  priv[0] &= 248;
  secure::Wipe(info, sizeof(info));
  return true;
}

// 对方公钥 -> X25519 点。X25519 私钥夹紧后不能推出任何公钥形式，
// 所以这里用 SHA256(压缩公钥) 映射，与 Keymaster 侧必须用同一条规则。
void ChannelPeerPoint(const uint8_t peer33[33], uint8_t out[32]) {
  digest::Sha256(peer33, 33, out);
  out[31] &= 127;
}

bool ChannelSealKey(const uint8_t peer33[33], const char* protocolType, uint8_t out[32]) {
  if (!peer33 || !protocolType) return false;
  uint8_t devicePriv[32];
  uint8_t peerPoint[32];
  uint8_t shared[32];
  if (!ChannelX25519Priv(protocolType, devicePriv)) return false;
  ChannelPeerPoint(peer33, peerPoint);
  bool ok = false;
  if (x25519::Shared(devicePriv, peerPoint, shared)) {
    uint8_t info[80];
    size_t n = 0;
    static const char* kLabel = "rockey:channel:seal:v1";
    size_t l = strlen(kLabel);
    memcpy(info, kLabel, l);
    n = l;
    info[n++] = 0;
    size_t pl = strlen(protocolType);
    if (n + pl < sizeof(info)) {
      memcpy(info + n, protocolType, pl);
      n += pl;
      // salt 绑定对端公钥：换对端就换密钥
      digest::HkdfSha256(shared, 32, peer33, 33, info, n, out, 32);
      ok = true;
    }
    secure::Wipe(shared, sizeof(shared));
  }
  secure::Wipe(devicePriv, sizeof(devicePriv));
  return ok;
}

// ── 迁移记录（公开进度，不含秘密） ────────────────────────────────
enum class MigStage : uint8_t {
  kNone = 0,
  kHostPrepared,
  kDeviceStaged,
  kDeviceCommitted,
  kHostCommitted,
  kCleaned,
};

const char* MigStageName(MigStage s) {
  switch (s) {
    case MigStage::kHostPrepared: return i18n::T(i18n::Str::kMigStageHostPrepared);
    case MigStage::kDeviceStaged: return i18n::T(i18n::Str::kMigStageDeviceStaged);
    case MigStage::kDeviceCommitted: return i18n::T(i18n::Str::kMigStageDeviceCommitted);
    case MigStage::kHostCommitted: return i18n::T(i18n::Str::kMigStageHostCommitted);
    case MigStage::kCleaned: return i18n::T(i18n::Str::kMigStageCleaned);
    default: return i18n::T(i18n::Str::kNone);
  }
}

struct MigRecord {
  uint32_t magic;
  uint8_t stage;
  uint8_t direction;  // 0 = 软件->硬件, 1 = 硬件->软件
  uint8_t pub[33];
  uint8_t hostPreparedAt;
  char migrationId[33];
};

constexpr uint32_t kMigMagic = 0x524B4D47u;  // "RKMG"

bool SaveMig(const MigRecord& r) {
  return store::WriteRecord(store::kPathMigration, 1, reinterpret_cast<const uint8_t*>(&r),
                           sizeof(r), nullptr);
}

bool LoadMig(MigRecord* r) {
  static uint8_t buf[sizeof(MigRecord)];
  size_t len = 0;
  if (!store::ReadRecord(store::kPathMigration, buf, sizeof(buf), &len, nullptr)) return false;
  if (len != sizeof(MigRecord)) return false;
  memcpy(r, buf, sizeof(MigRecord));
  return r->magic == kMigMagic;
}

}  // namespace

i18n::Str ErrorString(ErrorCode e) {
  switch (e) {
    case ErrorCode::kOk: return i18n::Str::kOk;
    case ErrorCode::kLocked: return i18n::Str::kErrLocked;
    case ErrorCode::kBusy: return i18n::Str::kErrBusy;
    case ErrorCode::kUnsupported: return i18n::Str::kErrUnsupported;
    case ErrorCode::kVersionMismatch: return i18n::Str::kErrVersionMismatch;
    case ErrorCode::kWrongKey: return i18n::Str::kErrWrongKey;
    case ErrorCode::kInvalidRequest: return i18n::Str::kErrInvalidRequest;
    case ErrorCode::kDeniedOnce: return i18n::Str::kStatusDenied;
    case ErrorCode::kDeniedSession: return i18n::Str::kStatusDenied;
    case ErrorCode::kRevoked: return i18n::Str::kErrRevoked;
    case ErrorCode::kDisconnected: return i18n::Str::kErrDisconnected;
    case ErrorCode::kTimeout: return i18n::Str::kErrTimeout;
    case ErrorCode::kResultUnknown: return i18n::Str::kErrResultUnknown;
    case ErrorCode::kMigrationConflict: return i18n::Str::kErrMigrationConflict;
    default: return i18n::Str::kUnknown;
  }
}

bool MigrationRecord(char* out, size_t cap, size_t* len) {
  MigRecord r;
  int n;
  if (!LoadMig(&r)) {
    n = snprintf(out, cap, "%s|%u", i18n::T(i18n::Str::kNone), 0u);
  } else {
    char pubHex[67];
    digest::ToHex(r.pub, 33, pubHex, sizeof(pubHex));
    n = snprintf(out, cap, "%s|%u|%s|%s", MigStageName(static_cast<MigStage>(r.stage)),
                 static_cast<unsigned>(r.direction), pubHex, r.migrationId);
  }
  if (n < 0 || static_cast<size_t>(n) >= cap) return false;
  *len = static_cast<size_t>(n);
  return true;
}

bool MigrationImport(const uint8_t priv[32], const uint8_t expectedPub[33], char* errOut,
                     size_t errCap) {
  MigRecord existing;
  if (LoadMig(&existing)) {
    MigStage st = static_cast<MigStage>(existing.stage);
    if (st != MigStage::kCleaned && st != MigStage::kNone) {
      if (memcmp(existing.pub, expectedPub, 33) != 0) {
        SafeCopy(errOut, errCap, i18n::T(i18n::Str::kErrMigrationConflict));
        return false;
      }
    }
  }
  // 已有 Key 且公钥不同：拒绝覆盖，必须显式擦除
  keystore::Info info = keystore::KeyStore::Info_();
  if (info.initialized) {
    uint8_t derived[33];
    if (!secp::PubkeyFromPriv(priv, derived)) {
      SafeCopy(errOut, errCap, i18n::T(i18n::Str::kErrWrongKey));
      return false;
    }
    if (memcmp(derived, info.pubkey, 33) != 0) {
      SafeCopy(errOut, errCap, i18n::T(i18n::Str::kErrWrongKey));
      return false;
    }
    SafeCopy(errOut, errCap, i18n::T(i18n::Str::kMigSameKey));
    return false;  // 同一密钥不需要重导入
  }
  // 迁移流程：先用一次性 PIN 封装（由 UI 提供），此处只做密钥一致性核对
  uint8_t derived[33];
  if (!secp::PubkeyFromPriv(priv, derived) || memcmp(derived, expectedPub, 33) != 0) {
    SafeCopy(errOut, errCap, i18n::T(i18n::Str::kErrWrongKey));
    return false;
  }
  MigRecord rec{};
  rec.magic = kMigMagic;
  rec.stage = static_cast<uint8_t>(MigStage::kDeviceStaged);
  rec.direction = 0;
  memcpy(rec.pub, derived, 33);
  rec.hostPreparedAt = 1;
  SafeCopy(rec.migrationId, sizeof(rec.migrationId), "");
  if (!SaveMig(rec)) {
    SafeCopy(errOut, errCap, i18n::T(i18n::Str::kErrInvalidRequest));
    return false;
  }
  SafeCopy(errOut, errCap, "");
  return true;
}


// ── 请求解析 ────────────────────────────────────────────────────────
namespace {

bool ValidateProtocol(const char* p);

struct FieldCtx {
  ExecContext* exec;
  ReviewDoc* doc;
  PrepareStatus st = PrepareStatus::kOk;
  bool bad = false;

  void Fail(PrepareStatus s) {
    st = s;
    bad = true;
  }
};

// 按 operation 解析一个键；未知键一律拒绝，防止降级夹带
//
// 所有**主机提供的文本**（purpose / protocolType / scope / fileName / digestHex）
// 都从这一个入口进设备，所以 UTF-8 清洗、长度上限与缺字检测也集中在同一处：
//外部正文整章接入已撤销（Markdown/信用长文归 Keymaster），但实际字段仍会
// 带上主机给的字节，非法 UTF-8、控制字符、双向覆盖和缺字必须在进评审文档前
// 处理掉，并且缺字要可见（RK-05），不能静默替换后当成已核验内容。
bool ReadField(FieldCtx& fc, OpId op, const char* k, size_t klen, Reader& r) {
  ExecContext& e = *fc.exec;
  auto txt = [&](char* dst, size_t cap) -> bool {
    size_t n = 0;
    const char* v = r.Text(&n);
    if (!v || n == 0 || n >= cap) return false;
    char clean[256];
    SanitizeStats st;
    SanitizeResult sr = SanitizeUtf8(v, n, clean, sizeof(clean), ROCKEY_MAX_DYNAMIC_TEXT, &st);
    if (sr == SanitizeResult::kInvalid) return false;  // 无法解释的字节不当字段收
    size_t cl = strlen(clean);
    if (cl == 0 || cl >= cap) return false;
    memcpy(dst, clean, cl + 1);
    // 缺字/被清洗的字符必须在阅读页可见（RK-05）
    if (fc.doc) fc.doc->NoteDynamicText(clean, cl, st);
    return true;
  };
  auto bytes = [&](uint8_t* dst, size_t cap, size_t* outLen) -> bool {
    size_t n = 0;
    const uint8_t* v = r.Bytes(&n);
    if (!v || n == 0 || n > cap) return false;
    memcpy(dst, v, n);
    if (outLen) *outLen = n;
    return true;
  };

  switch (op) {
    case OpId::kIdentityProve:
    case OpId::kIdentityAuthorize: {
      if (klen == 9 && memcmp(k, "challenge", 9) == 0) {
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 32) return false;
        memcpy(e.challenge, v, 32);
        return true;
      }
      if (klen == 7 && memcmp(k, "purpose", 7) == 0) return txt(e.purpose, sizeof(e.purpose));
      return false;
    }
    case OpId::kTxSign: {
      if (klen == 7 && memcmp(k, "network", 7) == 0) {
        uint64_t net = r.Uint();
        // 只支持 BSV 主网（版本字节 0x00）
        return net == 0x00;
      }
      if (klen == 5 && memcmp(k, "rawTx", 5) == 0) {
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n == 0 || n > kMaxTxBytes) return false;
        // 原文驻留在请求缓冲内，评审与签署期间有效
        e.tx.raw = v;
        e.tx.rawLen = n;
        return true;
      }
      if (klen == 10 && memcmp(k, "inputIndex", 10) == 0) {
        e.tx.inputIndex = static_cast<uint32_t>(r.Uint());
        return true;
      }
      if (klen == 8 && memcmp(k, "prevouts", 8) == 0) {
        size_t cnt = r.ArrayBegin();
        if (!r.ok() || cnt == 0 || cnt > kMaxInputs) return false;
        static PrevOut pool[kMaxInputs];
        memset(pool, 0, sizeof(pool));
        for (size_t i = 0; i < cnt; ++i) {
          size_t pairs = r.MapBegin();
          if (!r.ok() || pairs == 0 || pairs > 6) return false;
          for (size_t j = 0; j < pairs; ++j) {
            size_t fklen = 0;
            const char* fk = r.MapKey(&fklen);
            if (!fk) return false;
            if (fklen == 6 && memcmp(fk, "proven", 6) == 0) {
              pool[i].provenOnChain = r.Bool();
            } else if (fklen == 8 && memcmp(fk, "satoshis", 8) == 0) {
              pool[i].satoshis = static_cast<uint64_t>(r.Uint());
            } else if (fklen == 6 && memcmp(fk, "script", 6) == 0) {
              size_t n = 0;
              const uint8_t* v = r.Bytes(&n);
              if (!v || n == 0 || n > kMaxScriptLen) return false;
              memcpy(pool[i].script, v, n);
              pool[i].scriptLen = static_cast<uint16_t>(n);
            } else if (fklen == 4 && memcmp(fk, "txid", 4) == 0) {
              size_t n = 0;
              const uint8_t* v = r.Bytes(&n);
              if (!v || n != 32) return false;
              memcpy(pool[i].txid, v, 32);
            } else if (fklen == 4 && memcmp(fk, "vout", 4) == 0) {
              pool[i].vout = static_cast<uint32_t>(r.Uint());
            } else {
              return false;
            }
          }
          r.EndMap();
          if (!r.ok()) return false;
        }
        r.EndArray();
        if (!r.ok()) return false;
        e.tx.prevouts = pool;
        e.tx.prevoutCount = cnt;
        return true;
      }
      return false;
    }
    case OpId::kChannelPublic:
    case OpId::kChannelHash:
    case OpId::kChannelPrivate: {
      if (klen == 8 && memcmp(k, "protocol", 8) == 0) {
        if (!txt(e.protocolType, sizeof(e.protocolType))) return false;
        return ValidateProtocol(e.protocolType);
      }
      if (klen == 9 && memcmp(k, "challenge", 9) == 0) {
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 32) return false;
        memcpy(e.challenge, v, 32);
        return true;
      }
      if (klen == 7 && memcmp(k, "message", 7) == 0) {
        return bytes(e.message, sizeof(e.message), &e.messageLen);
      }
      return false;
    }
    case OpId::kChannelSeal:
    case OpId::kChannelOpen: {
      if (klen == 8 && memcmp(k, "protocol", 8) == 0) {
        if (!txt(e.protocolType, sizeof(e.protocolType))) return false;
        return ValidateProtocol(e.protocolType);
      }
      if (klen == 12 && memcmp(k, "recipientPub", 12) == 0) {
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 33 || !secp::ValidatePubkey(v)) return false;
        memcpy(e.peerPub, v, 33);
        return true;
      }
      if (klen == 9 && memcmp(k, "senderPub", 9) == 0) {
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 33 || !secp::ValidatePubkey(v)) return false;
        memcpy(e.senderPub, v, 33);
        return true;
      }
      if (klen == 6 && memcmp(k, "sealed", 6) == 0 && op == OpId::kChannelOpen) {
        // channel.open 的密文字段名与 channel.seal 的输出保持一致
        return bytes(e.ciphertext, sizeof(e.ciphertext), &e.ciphertextLen);
      }
      if (klen == 10 && memcmp(k, "ciphertext", 10) == 0) {
        return bytes(e.ciphertext, sizeof(e.ciphertext), &e.ciphertextLen);
      }
      if (klen == 5 && memcmp(k, "nonce", 5) == 0) {
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 12) return false;
        memcpy(e.channelNonce, v, 12);
        return true;
      }
      if (klen == 7 && memcmp(k, "message", 7) == 0) {
        return bytes(e.message, sizeof(e.message), &e.messageLen);
      }
      return false;
    }
    case OpId::kSecretSeal:
    case OpId::kSecretOpen: {
      if (klen == 5 && memcmp(k, "scope", 5) == 0) {
        if (!txt(e.scope, sizeof(e.scope))) return false;
        return ValidateScope(e.scope, strlen(e.scope));
      }
      if (op == OpId::kSecretSeal) {
        if (klen == 9 && memcmp(k, "plaintext", 9) == 0) {
          return bytes(e.plaintext, sizeof(e.plaintext), &e.plaintextLen);
        }
        return false;
      }
      if (klen == 6 && memcmp(k, "sealed", 6) == 0) {
        size_t pairs = r.MapBegin();
        // v3 信封固定 5 个字段：version / keySource / saltHex / nonceHex / ciphertextHex。
        // 写 4 会让设备自己 seal 出来的密文永远解不开（迁移后旧数据也就打不开）。
        if (!r.ok() || pairs != 5) return false;
        bool haveV = false, haveKs = false, haveSalt = false, haveNonce = false, haveCt = false;
        char keySource[32] = {0};
        uint64_t version = 0;
        for (size_t j = 0; j < pairs; ++j) {
          size_t fklen = 0;
          const char* fk = r.MapKey(&fklen);
          if (!fk) return false;
          if (fklen == 13 && memcmp(fk, "ciphertextHex", 13) == 0) {
            char hex[900];
            if (!txt(hex, sizeof(hex))) return false;
            size_t n = 0;
            if (!digest::FromHex(hex, strlen(hex), e.sealed.ciphertext, sizeof(e.sealed.ciphertext),
                                 &n)) {
              return false;
            }
            e.sealed.ciphertextLen = n;
            haveCt = true;
          } else if (fklen == 9 && memcmp(fk, "keySource", 9) == 0) {
            if (!txt(keySource, sizeof(keySource))) return false;
            haveKs = true;
          } else if (fklen == 8 && memcmp(fk, "nonceHex", 8) == 0) {
            char hex[64];
            if (!txt(hex, sizeof(hex))) return false;
            size_t n = 0;
            if (!digest::FromHex(hex, strlen(hex), e.sealed.nonce, sizeof(e.sealed.nonce), &n) ||
                n != kNonceLen) {
              return false;
            }
            haveNonce = true;
          } else if (fklen == 7 && memcmp(fk, "saltHex", 7) == 0) {
            char hex[64];
            if (!txt(hex, sizeof(hex))) return false;
            size_t n = 0;
            if (!digest::FromHex(hex, strlen(hex), e.sealed.salt, sizeof(e.sealed.salt), &n) ||
                n != kSaltLen) {
              return false;
            }
            haveSalt = true;
          } else if (fklen == 7 && memcmp(fk, "version", 7) == 0) {
            version = r.Uint();
            haveV = true;
          } else {
            return false;
          }
        }
        r.EndMap();
        if (!r.ok()) return false;
        if (!haveV || !haveKs || !haveSalt || !haveNonce || !haveCt) return false;
        if (version != kEnvelopeVersion) return false;
        if (strcmp(keySource, kKeySource) != 0) return false;
        return true;
      }
      return false;
    }
    case OpId::kContentAttest: {
      if (klen == 7 && memcmp(k, "purpose", 7) == 0) return txt(e.purpose, sizeof(e.purpose));
      if (klen == 9 && memcmp(k, "digestHex", 9) == 0) {
        if (!txt(e.digestHex, sizeof(e.digestHex))) return false;
        size_t n = 0;
        return digest::FromHex(e.digestHex, strlen(e.digestHex), e.digest, sizeof(e.digest), &n) &&
               n == 32;
      }
      if (klen == 8 && memcmp(k, "fileName", 8) == 0) return txt(e.filename, sizeof(e.filename));
      return false;
    }
    case OpId::kMigrationImport: {
      if (klen == 10 && memcmp(k, "commitment", 10) == 0) {
        // 迁移承诺：SHA256d("rockey:migration:import:v1" || priv) 主机可自证
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 32) return false;
        return true;
      }
      if (klen == 7 && memcmp(k, "privKey", 7) == 0) {
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 32 || !secp::ValidatePriv(v)) return false;
        memcpy(e.importPriv, v, 32);
        return true;
      }
      return false;
    }
    default:
      return false;
  }
}

bool ValidateProtocol(const char* p) {
  size_t n = strlen(p);
  if (n == 0 || n > 31) return false;
  for (size_t i = 0; i < n; ++i) {
    char c = p[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
             c == '_' || c == '.';
    if (!ok) return false;
  }
  return true;
}

}  // namespace

PrepareStatus Prepare(const uint8_t* body, size_t bodyLen, uint32_t requestId, ReviewDoc* doc,
                     ExecContext* exec, const uint8_t commitment[32]) {
  doc->Reset();
  *exec = ExecContext{};
  (void)requestId;

  if (!keystore::KeyStore::HasKey()) return PrepareStatus::kMalformed;
  if (!keystore::KeyStore::IsUnlocked()) return PrepareStatus::kLocked;

  Reader r(body, bodyLen);
  size_t pairs = r.MapBegin();
  if (pairs == 0 || pairs > 24 || !r.ok()) return PrepareStatus::kMalformed;

  FieldCtx fc;
  fc.exec = exec;
  fc.doc = doc;

  OpId opId = OpId::kUnknown;
  bool haveOp = false, haveVersion = false;
  for (size_t i = 0; i < pairs; ++i) {
    size_t klen = 0;
    const char* k = r.MapKey(&klen);
    if (!k) return PrepareStatus::kMalformed;
    if (klen == 2 && memcmp(k, "op", 2) == 0) {
      size_t n = 0;
      const char* v = r.Text(&n);
      if (!v || n == 0 || n > 47) return PrepareStatus::kMalformed;
      char name[48];
      memcpy(name, v, n);
      name[n] = '\0';
      if (!LookupOp(name, n, &opId)) return PrepareStatus::kUnsupported;
      // ── 费用池冻结门禁（最早识别点） ──────────────────────────────
      // 费用池的脚本、阶段、双方公钥顺序、锁定/退款条件与状态证据都没有冻结
      // （VLP §3 门禁），因此冻结前：
      //  - 一识别出 op 就拒绝，不再解析任何字段，也不发明 wire 字段；
      //  - 不套用 tx.p2pkh-sign 的 P2PKH 语义（池脚本不是 P2PKH）；
      //  - 明确返回 unsupported，主机与用户看到"不可用"而不是模糊失败。
      // 真正的解析器要等 B1 冻结的对象/金额/锁定/状态证据到位后再实现。
      if (opId == OpId::kTxFeepoolSign) return PrepareStatus::kUnsupported;
      haveOp = true;
      continue;
    }
    if (klen == 9 && memcmp(k, "opVersion", 9) == 0) {
      if (r.Uint() != kSupportedOpVersion) return PrepareStatus::kMalformed;
      haveVersion = true;
      continue;
    }
    if (!haveOp) return PrepareStatus::kUnsupported;  // 必须先给 op（确定性顺序保证）
    if (!ReadField(fc, opId, k, klen, r)) return PrepareStatus::kMalformed;
  }
  r.EndMap();
  if (!r.ok()) return PrepareStatus::kMalformed;
  if (!haveOp || !haveVersion) return PrepareStatus::kMalformed;

  exec->op = opId;
  exec->opVersion = kSupportedOpVersion;
  exec->category = CategoryOf(opId);
  exec->match.category = static_cast<uint8_t>(exec->category);
  exec->match.operation = static_cast<uint8_t>(opId);
  // 请求承诺（由 App 从信封复制进来）参与授权匹配：
  // 持续授权只覆盖它被承诺过的那个具体请求。
  memcpy(exec->match.commitment, commitment, 16);
  // 方向：seal 是设备发出去，open 是收进来；两者绝不能共用一条授权
  exec->match.direction = static_cast<uint8_t>(
      opId == OpId::kChannelSeal ? policy::Direction::kOutbound : policy::Direction::kInbound);
  // 协议：必须来自已登记的协议名，未登记直接拒绝而不是当成"无协议"
  if (exec->protocolType[0]) {
    uint8_t pid = 0;
    if (!ProtocolId(exec->protocolType, &pid)) return PrepareStatus::kMalformed;
    exec->match.protocol = pid;
  }
  // 交易解析要靠设备自己的公钥判定找零归属与前序是否属于自己；
  // 不填就是空指针解引用，且等于放弃这项核对。
  if (opId == OpId::kTxSign) exec->tx.pub33 = keystore::KeyStore::PublicKey();

  // ── 迁移专用状态与冲突检查 ──────────────────────────────────────
  MigRecord mig;
  MigStage migStage = LoadMig(&mig) ? static_cast<MigStage>(mig.stage) : MigStage::kNone;
  bool migActive = migStage == MigStage::kDeviceStaged || migStage == MigStage::kDeviceCommitted ||
                   migStage == MigStage::kHostCommitted;
  if (migActive && opId != OpId::kMigrationImport && opId != OpId::kMigrationStatus &&
      opId != OpId::kMigrationExport && CategoryOf(opId) != policy::Category::kMigration) {
    return PrepareStatus::kMigrationConflict;  // 未完成迁移期间不并行批准其它业务
  }

  // ── 生成设备自己的评审文档 ──────────────────────────────────────
  SafeCopy(doc->title, sizeof(doc->title), i18n::T(OpStr(opId)));
  digest::ToHex(keystore::KeyStore::PublicKey(), 33, doc->subject, sizeof(doc->subject));

  char line[160];
  AddOperationChapter(doc, opId);

  switch (opId) {
    case OpId::kIdentityProve:
    case OpId::kIdentityAuthorize: {
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      digest::ToHex(exec->challenge, 32, line, sizeof(line));
      doc->AddSummary(i18n::T(i18n::Str::kSumObject), line);
      doc->AddSummary(i18n::T(i18n::Str::kSumScope), exec->purpose[0] ? exec->purpose : "-");
      doc->AddChapter(i18n::T(i18n::Str::kSumScope), kChapterRequired);
      snprintf(line, sizeof(line), "%s\n%s", i18n::T(i18n::Str::kScopeSignMessage), exec->purpose);
      doc->AppendLine(line);
      // 匹配键绑定 challenge 与用途，换一个用途就是另一个授权
      {
        uint8_t buf[128];
        size_t n = 0;
        if (!KeyBufText(buf, sizeof(buf), &n, "rockey:identity:v1") ||
            !KeyBufBytes(buf, sizeof(buf), &n, exec->challenge, 32) ||
            !KeyBufText(buf, sizeof(buf), &n, exec->purpose)) {
          return PrepareStatus::kMalformed;
        }
        uint8_t h[32];
        digest::Sha256(buf, n, h);
        memcpy(exec->match.objectHash, h, 16);
      }
      break;
    }
    case OpId::kTxSign: {
      TxReview rv = ReviewTx(exec->tx);
      if (!rv.ok) return PrepareStatus::kMalformed;
      char buf[128];
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      snprintf(buf, sizeof(buf), "%s %llu", i18n::T(i18n::Str::kAmountSats),
               static_cast<unsigned long long>(rv.totalOut - rv.changeSats));
      doc->AddSummary(i18n::T(i18n::Str::kSumAmount), buf);
      snprintf(buf, sizeof(buf), "%s %llu", i18n::T(i18n::Str::kAmountSats),
               static_cast<unsigned long long>(rv.fee));
      doc->AddSummary(i18n::T(i18n::Str::kSumLimits), buf);
      snprintf(buf, sizeof(buf), "%s", rv.changeAddress);
      doc->AddSummary(i18n::T(i18n::Str::kSumScope), buf);

      // 逐项付款明细：地址与金额都由设备从待签交易的输出脚本解出。
      // 只显示"支付总额"是不够的 —— 用户看不到钱付给谁。
      doc->AddChapter(i18n::T(i18n::Str::kTxPayees), kChapterRequired);
      for (uint32_t i = 0; i < rv.payRecorded; ++i) {
        // 由 hash160 反推 P2PKH 地址（版本字节固定为主网）
        char addr[40];
        if (P2pkhAddressFromHash160(rv.pays[i].hash160, addr, sizeof(addr))) {
          snprintf(buf, sizeof(buf), "%s\n%s %llu", addr, i18n::T(i18n::Str::kAmountSats),
                   static_cast<unsigned long long>(rv.pays[i].satoshis));
        } else {
          snprintf(buf, sizeof(buf), "-");
        }
        doc->AppendLine(buf);
      }
      if (rv.truncatedPays) doc->AppendLine(i18n::T(i18n::Str::kTxMorePayees));

      // 前序证据：主机的 proven 布尔值只决定要不要显示"未验证"，
      // 绝不会因为主机说 true 就把风险提示去掉（需求 §5 / §6.3）。
      doc->AddRisk(Risk::kPaysOther);
      doc->AddChapter(i18n::T(i18n::Str::kSumRisks), kChapterRequired | kChapterWarning);
      // 无论主机把 proven 标成什么，都固定显示这一行：
      // 设备只核对了字节与声明自洽，没有验证链上未花费状态。
      doc->AppendLine(i18n::T(i18n::Str::kRiskHostEvidence));
      if (rv.anyUnproven) {
        doc->AddRisk(Risk::kUnverifiedInputs);
        doc->AppendLine(i18n::T(i18n::Str::kRiskUnverifiedInputs));
      }
      doc->AppendLine(i18n::T(i18n::Str::kRiskPaysOther));
      doc->AddChapter(i18n::T(i18n::Str::kSumExcludes), kChapterRequired);
      doc->AppendLine(i18n::T(i18n::Str::kScopePrivateRead));
      doc->AppendLine(i18n::T(i18n::Str::kScopePrivateWrite));
      memcpy(exec->match.objectHash, rv.sighash, 16);
      // 本次涉及的金额（付给别人的输出总额，不含找零），供会话授权预算判定
      exec->valueSats = rv.totalOut - rv.changeSats;
      break;
    }
    case OpId::kChannelPublic:
    case OpId::kChannelHash:
    case OpId::kChannelPrivate:
    case OpId::kChannelSeal:
    case OpId::kChannelOpen: {
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      doc->AddSummary(i18n::T(i18n::Str::kSumScope), exec->protocolType);
      // 对端公钥必须齐备：seal 用 recipientPub，open 用 senderPub。
      // 交叉填写会让授权落到错误的对手方上。
      if (opId == OpId::kChannelSeal) {
        if (!exec->peerPub[0]) return PrepareStatus::kMalformed;
        if (exec->senderPub[0]) return PrepareStatus::kMalformed;
      } else if (opId == OpId::kChannelOpen) {
        if (!exec->senderPub[0]) return PrepareStatus::kMalformed;
        if (exec->peerPub[0]) return PrepareStatus::kMalformed;
      }
      if (exec->peerPub[0] || exec->senderPub[0]) {
        digest::ToHex(exec->peerPub[0] ? exec->peerPub : exec->senderPub, 33, line, sizeof(line));
        doc->AddSummary(i18n::T(i18n::Str::kChannelPeerKey), line);
      }
      doc->AddChapter(i18n::T(i18n::Str::kSumRisks), kChapterRequired | kChapterWarning);
      if (CategoryOf(opId) == policy::Category::kChannel) {
        if (opId == OpId::kChannelPrivate || opId == OpId::kChannelOpen) {
          doc->AddRisk(Risk::kPrivateChannel);
          doc->AppendLine(i18n::T(i18n::Str::kRiskPrivateChannel));
        }
      }
      doc->AddChapter(i18n::T(i18n::Str::kSumExcludes), kChapterRequired);
      doc->AppendLine(i18n::T(i18n::Str::kScopePay));
      doc->AppendLine(i18n::T(i18n::Str::kScopePrivateWrite));
      // 匹配键绑定协议、对端公钥与设备自算的消息摘要。
      // 用消息原文前 16 字节有两个问题：open 没有 message 时会全零，
      // 而且"允许对 A 说这句话"会顺带允许对 A 说任何别的话。
      {
        uint8_t buf[160];
        size_t n = 0;
        if (!KeyBufText(buf, sizeof(buf), &n, "rockey:channel:v1") ||
            !KeyBufText(buf, sizeof(buf), &n, exec->protocolType) ||
            !KeyBufBytes(buf, sizeof(buf), &n, exec->peerPub[0] ? exec->peerPub : exec->senderPub,
                          33)) {
          return PrepareStatus::kMalformed;
        }
        uint8_t dg[32];
        switch (opId) {
          case OpId::kChannelPublic:
            ChannelPublicDigest(exec->protocolType, exec->message, exec->messageLen, dg);
            break;
          case OpId::kChannelHash:
            ChannelHashDigest(exec->protocolType, exec->challenge, dg);
            break;
          case OpId::kChannelPrivate:
            ChannelPrivateDigest(exec->protocolType, exec->message, exec->messageLen, dg);
            break;
          case OpId::kChannelSeal:
            // seal 的对象是**明文**：正常请求根本没有 ciphertext，
            // 早先按密文处理会让每个合法的 seal 请求都变成 malformed。
            if (!exec->messageLen) return PrepareStatus::kMalformed;
            digest::Sha256(exec->message, exec->messageLen, dg);
            break;
          default:
            // open 的对象是密文
            if (!exec->ciphertextLen) return PrepareStatus::kMalformed;
            digest::Sha256(exec->ciphertext, exec->ciphertextLen, dg);
            break;
        }
        if (!KeyBufBytes(buf, sizeof(buf), &n, dg, 32)) return PrepareStatus::kMalformed;
        uint8_t h[32];
        digest::Sha256(buf, n, h);
        memcpy(exec->match.objectHash, h, 16);
      }
      break;
    }
    case OpId::kSecretSeal:
    case OpId::kSecretOpen: {
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      doc->AddSummary(i18n::T(i18n::Str::kSumScope), exec->scope);
      char lenBuf[32];
      snprintf(lenBuf, sizeof(lenBuf), "%llu",
               static_cast<unsigned long long>(opId == OpId::kSecretSeal
                                                   ? exec->plaintextLen
                                                   : exec->sealed.ciphertextLen));
      doc->AddSummary(i18n::T(i18n::Str::kSumLimits), lenBuf);
      doc->AddChapter(i18n::T(i18n::Str::kSumRisks), kChapterRequired | kChapterWarning);
      doc->AppendLine(i18n::T(i18n::Str::kScopePrivateWrite));
      doc->AddChapter(i18n::T(i18n::Str::kSumExcludes), kChapterRequired);
      doc->AppendLine(i18n::T(i18n::Str::kScopePay));
      // 封装的对象就是那段密文：授权必须绑定密文，而不是只绑定 scope。
      // 只绑定 scope 的话，一次"允许解封该 scope"会变成该 scope 的无限开锁许可。
      uint8_t buf[128];
      size_t n = 0;
      uint8_t sh[32];
      if (opId == OpId::kSecretOpen) {
        if (exec->sealed.ciphertextLen == 0) return PrepareStatus::kMalformed;
        digest::Sha256(exec->sealed.ciphertext, exec->sealed.ciphertextLen, sh);
      } else {
        digest::Sha256(exec->plaintext, exec->plaintextLen, sh);
      }
      if (!KeyBufText(buf, sizeof(buf), &n, "rockey:localsecret:v1") ||
          !KeyBufText(buf, sizeof(buf), &n, exec->scope) ||
          !KeyBufBytes(buf, sizeof(buf), &n, sh, 32)) {
        return PrepareStatus::kMalformed;
      }
      uint8_t h[32];
      digest::Sha256(buf, n, h);
      memcpy(exec->match.objectHash, h, 16);
      break;
    }
    case OpId::kContentAttest: {
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      SafeCopy(line, sizeof(line), exec->filename);
      doc->AddSummary(i18n::T(i18n::Str::kSumObject), line);
      doc->AddSummary(i18n::T(i18n::Str::kSumLimits), exec->purpose);
      doc->AddChapter(i18n::T(i18n::Str::kSumRisks), kChapterRequired | kChapterWarning);
      doc->AddRisk(Risk::kContentDigestHostComputed);
      doc->AppendLine(i18n::T(i18n::Str::kContentNotTx));
      doc->AddChapter(i18n::T(i18n::Str::kSumExcludes), kChapterRequired);
      doc->AppendLine(i18n::T(i18n::Str::kScopePay));
      // 显示设备自己算出的声明摘要，而不是主机给的十六进制原文
      uint8_t statement[32];
      ContentDigest(exec->purpose, exec->digestHex, statement);
      char d[70];
      digest::ToHex(statement, 32, d, sizeof(d));
      doc->AddSummary(i18n::T(i18n::Str::kContentDigestLabel), d);
      size_t n = 0;
      digest::FromHex(exec->digestHex, strlen(exec->digestHex), exec->match.objectHash, 16, &n);
      break;
    }
    case OpId::kMigrationImport:
    case OpId::kMigrationExport:
    case OpId::kMigrationStatus: {
      doc->AddChapter(i18n::T(i18n::Str::kSumScope), kChapterRequired);
      doc->AddSummary(i18n::T(i18n::Str::kSumScope), i18n::T(i18n::Str::kScopeMigrate));
      if (opId == OpId::kMigrationExport) {
        doc->AddChapter(i18n::T(i18n::Str::kSumRisks), kChapterRequired | kChapterWarning);
        doc->AppendLine(i18n::T(i18n::Str::kExportWarning));
      }
      doc->AddChapter(i18n::T(i18n::Str::kSumExcludes), kChapterRequired);
      doc->AppendLine(i18n::T(i18n::Str::kScopePay));
      break;
    }
    default:
      return PrepareStatus::kUnsupported;
  }

  doc->Finish();
  return PrepareStatus::kOk;
}

ErrorCode Execute(ExecContext& e, uint8_t* out, size_t cap, size_t* outLen) {
  *outLen = 0;
  if (!keystore::KeyStore::IsUnlocked()) return ErrorCode::kLocked;
  Writer w(out, cap);
  uint8_t sigDer[80];
  size_t sigLen = sizeof(sigDer);
  const uint8_t* priv = keystore::KeyStore::PrivateKey();
  if (!priv) return ErrorCode::kLocked;

  switch (e.op) {
    case OpId::kIdentityProve:
    case OpId::kIdentityAuthorize: {
      // 绝不能直接签主机给的 32 字节：那等于一个任意摘要签名接口 ——
      // 浏览器可以把一笔交易的 sighash 当 challenge 塞进来，拿走一个
      // 与 tx.p2pkh-sign 同等有效的交易签名，而屏幕上从没显示过这笔交易。
      // 设备自己构造域隔离的证明摘要，把用途、身份、会话和 challenge
      // 一起绑进去；交易/通道/内容摘要的域标签不同，跨域不可复用。
      uint8_t stmt[32];
      if (!IdentityProofDigest(e, stmt)) return ErrorCode::kInvalidRequest;
      if (!secp::SignDer(priv, stmt, sigDer, &sigLen)) return ErrorCode::kInvalidRequest;
      w.BeginMap(4);
      w.Key("challenge");
      w.Bytes(e.challenge, 32);
      w.Key("publicKey");
      w.Bytes(keystore::KeyStore::PublicKey(), 33);
      w.Key("signature");
      w.Bytes(sigDer, sigLen);
      w.Key("signatureFormat");
      w.Text("der-strict-lows-domain-separated");
      break;
    }
    case OpId::kTxSign: {
      TxReview rv = ReviewTx(e.tx);
      if (!rv.ok) return ErrorCode::kInvalidRequest;
      if (!SignInput(e.tx, sigDer, &sigLen)) return ErrorCode::kInvalidRequest;
      w.BeginMap(4);
      w.Key("sighash");
      w.Bytes(rv.sighash, 32);
      w.Key("publicKey");
      w.Bytes(keystore::KeyStore::PublicKey(), 33);
      w.Key("signature");
      w.Bytes(sigDer, sigLen);
      w.Key("sighashType");
      w.Uint(kSighashAllForkId);
      break;
    }
    case OpId::kContentAttest: {
      uint8_t digestToSign[32];
      if (!ContentDigest(e.purpose, e.digestHex, digestToSign)) return ErrorCode::kInvalidRequest;
      if (!secp::SignDer(priv, digestToSign, sigDer, &sigLen)) return ErrorCode::kInvalidRequest;
      w.BeginMap(3);
      w.Key("publicKey");
      w.Bytes(keystore::KeyStore::PublicKey(), 33);
      w.Key("signature");
      w.Bytes(sigDer, sigLen);
      w.Key("statementDigest");
      w.Bytes(digestToSign, 32);
      break;
    }
    case OpId::kChannelPublic: {
      uint8_t dg[32];
      if (!ChannelPublicDigest(e.protocolType, e.message, e.messageLen, dg)) {
        return ErrorCode::kInvalidRequest;
      }
      if (!secp::SignDer(priv, dg, sigDer, &sigLen)) return ErrorCode::kInvalidRequest;
      w.BeginMap(2);
      w.Key("publicKey");
      w.Bytes(keystore::KeyStore::PublicKey(), 33);
      w.Key("signature");
      w.Bytes(sigDer, sigLen);
      break;
    }
    case OpId::kChannelHash: {
      uint8_t dg[32];
      if (!ChannelHashDigest(e.protocolType, e.challenge, dg)) return ErrorCode::kInvalidRequest;
      if (!secp::SignDer(priv, dg, sigDer, &sigLen)) return ErrorCode::kInvalidRequest;
      w.BeginMap(2);
      w.Key("signature");
      w.Bytes(sigDer, sigLen);
      w.Key("requestDigest");
      w.Bytes(e.challenge, 32);
      break;
    }
    case OpId::kChannelPrivate: {
      uint8_t dg[32];
      if (!ChannelPrivateDigest(e.protocolType, e.message, e.messageLen, dg)) {
        return ErrorCode::kInvalidRequest;
      }
      if (!secp::SignDer(priv, dg, sigDer, &sigLen)) return ErrorCode::kInvalidRequest;
      w.BeginMap(3);
      w.Key("publicKey");
      w.Bytes(keystore::KeyStore::PublicKey(), 33);
      w.Key("signature");
      w.Bytes(sigDer, sigLen);
      w.Key("messageDigest");
      w.Bytes(dg, 32);
      break;
    }
    case OpId::kChannelSeal: {
      uint8_t key[32];
      if (!ChannelSealKey(e.peerPub, e.protocolType, key)) return ErrorCode::kInvalidRequest;
      uint8_t nonce[12];
      rand::Fill(nonce, 12);
      uint8_t aad[64];
      size_t aadLen = 0;
      if (!KeyBufText(aad, sizeof(aad), &aadLen, "rockey:channel:seal:v1") ||
          !KeyBufText(aad, sizeof(aad), &aadLen, e.protocolType)) {
        secure::Wipe(key, sizeof(key));
        return ErrorCode::kInvalidRequest;
      }
      uint8_t ct[520];
      uint8_t tag[16];
      if (!aead::Seal(key, nonce, aad, aadLen, e.message, e.messageLen, ct, tag)) {
        secure::Wipe(key, sizeof(key));
        return ErrorCode::kInvalidRequest;
      }
      // 密文与 tag 合并成一个字段：open 侧按同样约定读，
      // 不再是"seal 单独回 tag、open 却把 tag 算进 ciphertextLen"的两套规则。
      uint8_t sealed[sizeof(ct) + sizeof(tag)];
      memcpy(sealed, ct, e.messageLen);
      memcpy(sealed + e.messageLen, tag, sizeof(tag));
      w.BeginMap(2);
      w.Key("nonce");
      w.Bytes(nonce, 12);
      w.Key("sealed");
      w.Bytes(sealed, e.messageLen + sizeof(tag));
      secure::Wipe(key, sizeof(key));
      secure::Wipe(ct, sizeof(ct));
      secure::Wipe(sealed, sizeof(sealed));
      break;
    }
    case OpId::kChannelOpen: {
      // sealed = ciphertext || tag(16)，与 channel.seal 的输出同构
      if (e.ciphertextLen < aead::kTagLen) return ErrorCode::kInvalidRequest;
      uint8_t key[32];
      if (!ChannelSealKey(e.senderPub, e.protocolType, key)) return ErrorCode::kInvalidRequest;
      uint8_t aad[64];
      size_t aadLen = 0;
      if (!KeyBufText(aad, sizeof(aad), &aadLen, "rockey:channel:seal:v1") ||
          !KeyBufText(aad, sizeof(aad), &aadLen, e.protocolType)) {
        secure::Wipe(key, sizeof(key));
        return ErrorCode::kInvalidRequest;
      }
      size_t ctLen = e.ciphertextLen - aead::kTagLen;
      uint8_t plain[512];
      bool ok = aead::Open(key, e.channelNonce, aad, aadLen, e.ciphertext, ctLen,
                           e.ciphertext + ctLen, plain);
      if (!ok) {
        secure::Wipe(key, sizeof(key));
        return ErrorCode::kInvalidRequest;
      }
      w.BeginMap(1);
      w.Key("plaintext");
      w.Bytes(plain, ctLen);
      secure::Wipe(plain, sizeof(plain));
      secure::Wipe(key, sizeof(key));
      break;
    }
    case OpId::kSecretSeal: {
      SealedSecret sealed;
      if (!Seal(e.scope, strlen(e.scope), e.plaintext, e.plaintextLen, &sealed)) {
        return ErrorCode::kInvalidRequest;
      }
      char saltHex[40], nonceHex[32], ctHex[8192];
      digest::ToHex(sealed.salt, kSaltLen, saltHex, sizeof(saltHex));
      digest::ToHex(sealed.nonce, kNonceLen, nonceHex, sizeof(nonceHex));
      digest::ToHex(sealed.ciphertext, sealed.ciphertextLen, ctHex, sizeof(ctHex));
      w.BeginMap(5);
      w.Key("saltHex");
      w.Text(saltHex);
      w.Key("version");
      w.Uint(kEnvelopeVersion);
      w.Key("nonceHex");
      w.Text(nonceHex);
      w.Key("keySource");
      w.Text(kKeySource);
      w.Key("ciphertextHex");
      w.Text(ctHex);
      secure::Wipe(sealed.ciphertext, sizeof(sealed.ciphertext));
      break;
    }
    case OpId::kSecretOpen: {
      uint8_t plain[ops::kPlaintextMax];
      size_t plainLen = 0;
      if (!Open(e.scope, strlen(e.scope), e.sealed, plain, sizeof(plain), &plainLen)) {
        return ErrorCode::kInvalidRequest;
      }
      w.BeginMap(1);
      w.Key("plaintext");
      w.Bytes(plain, plainLen);
      secure::Wipe(plain, sizeof(plain));
      break;
    }
    case OpId::kMigrationStatus: {
      char rec[400];
      size_t recLen = 0;
      if (!MigrationRecord(rec, sizeof(rec), &recLen)) return ErrorCode::kInvalidRequest;
      w.BeginMap(1);
      w.Key("record");
      w.TextN(rec, recLen);
      break;
    }
    default:
      return ErrorCode::kUnsupported;
  }

  if (!w.ok()) return ErrorCode::kInvalidRequest;
  *outLen = w.size();
  return ErrorCode::kOk;
}

bool ExportOnce(const uint8_t* recipientSessionKey, uint8_t* out, size_t cap, size_t* len) {
  const uint8_t* priv = keystore::KeyStore::PrivateKey();
  if (!priv) return false;
  uint8_t nonce[12];
  rand::Fill(nonce, 12);
  uint8_t aad[16];
  memcpy(aad, "rockey:export:v1", 16);
  uint8_t ct[64];
  uint8_t tag[16];
  if (!aead::Seal(recipientSessionKey, nonce, aad, sizeof(aad), priv, 32, ct, tag)) {
    return false;
  }
  size_t n = 0;
  if (n + 12 + 32 + 16 > cap) return false;
  memcpy(out + n, nonce, 12);
  n += 12;
  memcpy(out + n, ct, 32);
  n += 32;
  memcpy(out + n, tag, 16);
  n += 16;
  *len = n;
  secure::Wipe(ct, sizeof(ct));
  return true;
}

}  // namespace ops
}  // namespace rockey