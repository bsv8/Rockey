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

namespace rockey {
namespace ops {
using proto::Reader;
using proto::Writer;

namespace {

constexpr uint32_t kSupportedOpVersion = 1;
constexpr uint8_t kProtocolChannelV1 = 1;

void SafeCopy(char* dst, size_t cap, const char* src) {
  if (!src) {
    dst[0] = '\0';
    return;
  }
  strncpy(dst, src, cap - 1);
  dst[cap - 1] = '\0';
}

void HashPrefix(uint16_t opId, uint8_t out[16]) {
  uint8_t buf[3] = {static_cast<uint8_t>(opId >> 8), static_cast<uint8_t>(opId), 0x00};
  uint8_t h[32];
  digest::Sha256(buf, sizeof(buf), h);
  memcpy(out, h, 16);
}

const char* OpString(OpId op) {
  switch (op) {
    case OpId::kIdentityProve: return "kOpIdentityProve";
    case OpId::kIdentityAuthorize: return "kOpIdentityAuthorize";
    case OpId::kTxSign: return "kOpTxSign";
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
      {"channel.public-message", OpId::kChannelPublic},
      {"channel.hash-request", OpId::kChannelHash},
      {"channel.private-message", OpId::kChannelPrivate},
      {"channel.seal", OpId::kChannelSeal},
      {"channel.open", OpId::kChannelOpen},
      {"secret.seal", OpId::kSecretSeal},
      {"secret.open", OpId::kSecretOpen},
      {"content.attest-digest", OpId::kContentAttest},
      {"evidence.receive", OpId::kEvidenceReceive},
      {"migration.import", OpId::kMigrationImport},
      {"migration.export", OpId::kMigrationExport},
      {"migration.status", OpId::kMigrationStatus},
      {"recovery.backup", OpId::kRecoveryBackup},
  };
  for (const auto& e : kTable) {
    if (strlen(e.n) == len && memcmp(e.n, name, len) == 0) {
      *out = e.id;
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
    case OpId::kEvidenceReceive:
      return policy::Category::kEvidence;
    case OpId::kMigrationImport:
    case OpId::kMigrationExport:
    case OpId::kMigrationStatus:
    case OpId::kRecoveryBackup:
      return policy::Category::kMigration;
    default:
      return policy::Category::kSystem;
  }
}

// 设备生成的摘要标签（不用主机给的说明文字）
void DigestLabel(uint8_t digest[32], char* out, size_t cap) {
  digest::ToHex(digest, 32, out, cap);
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

bool ChannelSealKey(const uint8_t peer33[33], const char* protocolType, uint8_t out[32]) {
  uint8_t xpriv[32], xpub[32], shared[32];
  rand::Fill(xpriv, 32);
  x25519::PublicFromPrivate(xpriv, xpub);
  bool ok = false;
  // 用对方公钥的 SHA-256 前 32 字节映射到 Curve25519（双方必须一致，见协议规范）
  uint8_t h[32];
  digest::Sha256(peer33, 33, h);
  h[31] &= 127;
  if (x25519::Shared(xpriv, h, shared)) {
    uint8_t info[64];
    size_t n = 0;
    static const char* kLabel = "rockey:channel:seal:v1";
    size_t l = strlen(kLabel);
    memcpy(info, kLabel, l);
    n = l;
    info[n++] = 0;
    size_t pl = strlen(protocolType);
    memcpy(info + n, protocolType, pl);
    n += pl;
    digest::HkdfSha256(shared, 32, nullptr, 0, info, n, out, 32);
    ok = true;
  }
  secure::Wipe(shared, sizeof(shared));
  secure::Wipe(xpriv, sizeof(xpriv));
  return ok;
}

// ── 迁移记录（公开进度，不含秘密） ────────────────────────────────
constexpr size_t kMigRecMax = 320;

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
    case ErrorCode::kInvalidEvidence: return i18n::Str::kErrInvalidEvidence;
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
bool ReadField(FieldCtx& fc, OpId op, const char* k, size_t klen, Reader& r) {
  ExecContext& e = *fc.exec;
  auto txt = [&](char* dst, size_t cap) -> bool {
    size_t n = 0;
    const char* v = r.Text(&n);
    if (!v || n == 0 || n >= cap) return false;
    memcpy(dst, v, n);
    dst[n] = '\0';
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
      if (klen == 6 && memcmp(k, "rawTx", 6) == 0) {
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
            if (fklen == 7 && memcmp(fk, "proven", 6) == 0) {
              pool[i].provenOnChain = r.Bool();
            } else if (fklen == 8 && memcmp(fk, "satoshis", 8) == 0) {
              pool[i].satoshis = static_cast<uint64_t>(r.Uint());
            } else if (fklen == 5 && memcmp(fk, "script", 6) == 0) {
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
        if (!r.ok() || pairs != 4) return false;
        bool haveV = false, haveKs = false, haveSalt = false, haveNonce = false, haveCt = false;
        char keySource[32] = {0};
        uint64_t version = 0;
        for (size_t j = 0; j < pairs; ++j) {
          size_t fklen = 0;
          const char* fk = r.MapKey(&fklen);
          if (!fk) return false;
          if (fklen == 14 && memcmp(fk, "ciphertextHex", 13) == 0) {
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
          } else if (fklen == 8 && memcmp(fk, "saltHex", 7) == 0) {
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
    case OpId::kEvidenceReceive: {
      if (klen == 8 && memcmp(k, "subjectPub", 10) == 0) {
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 33 || !secp::ValidatePubkey(v)) return false;
        memcpy(e.subjectPub, v, 33);
        return true;
      }
      if (klen == 5 && memcmp(k, "nonce", 5) == 0) {
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 32) return false;
        memcpy(e.evidenceNonce, v, 32);
        return true;
      }
      if (klen == 12 && memcmp(k, "ciphertext", 10) == 0) {
        return bytes(e.ciphertext, sizeof(e.ciphertext), &e.ciphertextLen);
      }
      return false;
    }
    case OpId::kMigrationImport: {
      if (klen == 9 && memcmp(k, "commitment", 10) == 0) {
        // 迁移承诺：SHA256d("rockey:migration:import:v1" || priv) 主机可自证
        size_t n = 0;
        const uint8_t* v = r.Bytes(&n);
        if (!v || n != 32) return false;
        return true;
      }
      if (klen == 6 && memcmp(k, "privKey", 7) == 0) {
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
                     ExecContext* exec) {
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
      exec->match.objectHash[0] = 0;
      memcpy(exec->match.objectHash, exec->challenge, 16);
      break;
    }
    case OpId::kTxSign: {
      TxReview rv = ReviewTx(exec->tx);
      if (!rv.ok) return PrepareStatus::kMalformed;
      char buf[96];
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      snprintf(buf, sizeof(buf), "%s %lu", i18n::T(i18n::Str::kAmountSats),
               static_cast<unsigned long>(rv.totalOut - rv.changeSats));
      doc->AddSummary(i18n::T(i18n::Str::kSumAmount), buf);
      snprintf(buf, sizeof(buf), "%s %lu", i18n::T(i18n::Str::kAmountSats),
               static_cast<unsigned long>(rv.fee));
      doc->AddSummary(i18n::T(i18n::Str::kSumLimits), buf);
      snprintf(buf, sizeof(buf), "%s", rv.changeAddress);
      doc->AddSummary(i18n::T(i18n::Str::kSumScope), buf);
      if (rv.anyUnproven) doc->AddRisk(Risk::kUnverifiedInputs);
      doc->AddRisk(Risk::kPaysOther);
      doc->AddChapter(i18n::T(i18n::Str::kSumRisks), kChapterRequired | kChapterWarning);
      if (rv.anyUnproven) doc->AppendLine(i18n::T(i18n::Str::kRiskUnverifiedInputs));
      doc->AppendLine(i18n::T(i18n::Str::kRiskPaysOther));
      doc->AddChapter(i18n::T(i18n::Str::kSumExcludes), kChapterRequired);
      doc->AppendLine(i18n::T(i18n::Str::kScopePrivateRead));
      doc->AppendLine(i18n::T(i18n::Str::kScopePrivateWrite));
      memcpy(exec->match.objectHash, rv.sighash, 16);
      break;
    }
    case OpId::kChannelPublic:
    case OpId::kChannelHash:
    case OpId::kChannelPrivate:
    case OpId::kChannelSeal:
    case OpId::kChannelOpen: {
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      doc->AddSummary(i18n::T(i18n::Str::kSumScope), exec->protocolType);
      if (exec->peerPub[0] || exec->senderPub[0]) {
        digest::ToHex(exec->peerPub[0] ? exec->peerPub : exec->senderPub, 33, line, sizeof(line));
        doc->AddSummary(i18n::T(i18n::Str::kEvidSubject), line);
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
      if (exec->messageLen) memcpy(exec->match.objectHash, exec->message, 16);
      break;
    }
    case OpId::kSecretSeal:
    case OpId::kSecretOpen: {
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      doc->AddSummary(i18n::T(i18n::Str::kSumScope), exec->scope);
      char lenBuf[32];
      snprintf(lenBuf, sizeof(lenBuf), "%lu",
               static_cast<unsigned long>(opId == OpId::kSecretSeal ? exec->plaintextLen
                                                                    : exec->sealed.ciphertextLen));
      doc->AddSummary(i18n::T(i18n::Str::kSumLimits), lenBuf);
      doc->AddChapter(i18n::T(i18n::Str::kSumRisks), kChapterRequired | kChapterWarning);
      doc->AppendLine(i18n::T(i18n::Str::kScopePrivateWrite));
      doc->AddChapter(i18n::T(i18n::Str::kSumExcludes), kChapterRequired);
      doc->AppendLine(i18n::T(i18n::Str::kScopePay));
      uint8_t sh[32];
      digest::Sha256(reinterpret_cast<const uint8_t*>(exec->scope), strlen(exec->scope), sh);
      memcpy(exec->match.objectHash, sh, 16);
      break;
    }
    case OpId::kContentAttest: {
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      SafeCopy(line, sizeof(line), exec->filename);
      doc->AddSummary(i18n::T(i18n::Str::kSumObject), line);
      doc->AddSummary(i18n::T(i18n::Str::kSumLimits), exec->purpose);
      doc->AddChapter(i18n::T(i18n::Str::kSumRisks), kChapterRequired | kChapterWarning);
      doc->AppendLine(i18n::T(i18n::Str::kErrInvalidRequest));
      doc->AddChapter(i18n::T(i18n::Str::kSumExcludes), kChapterRequired);
      doc->AppendLine(i18n::T(i18n::Str::kScopePay));
      char d[70];
      doc->AddSummary(i18n::T(i18n::Str::kSumRisks), d);
      size_t n = 0;
      digest::FromHex(exec->digestHex, strlen(exec->digestHex), exec->match.objectHash, 16, &n);
      break;
    }
    case OpId::kEvidenceReceive: {
      doc->AddChapter(i18n::T(i18n::Str::kSumObject), kChapterRequired);
      digest::ToHex(exec->subjectPub, 33, line, sizeof(line));
      doc->AddSummary(i18n::T(i18n::Str::kEvidSubject), line);
      doc->AddChapter(i18n::T(i18n::Str::kEvidTitle), kChapterRequired | kChapterWarning);
      doc->AddRisk(Risk::kNoEvidence);
      doc->AppendLine(i18n::T(i18n::Str::kEvidNoEvidence));
      doc->AppendLine(i18n::T(i18n::Str::kEvidNote));
      doc->AppendLine(i18n::T(i18n::Str::kEvidTimeUnknown));
      doc->AddRisk(Risk::kTimeUnverified);
      doc->AddChapter(i18n::T(i18n::Str::kSumExcludes), kChapterRequired);
      doc->AppendLine(i18n::T(i18n::Str::kScopeSignTx));
      memcpy(exec->match.objectHash, exec->subjectPub, 16);
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
    case OpId::kRecoveryBackup: {
      doc->AddChapter(i18n::T(i18n::Str::kSumRisks), kChapterRequired | kChapterWarning);
      doc->AppendLine(i18n::T(i18n::Str::kBackupExplain));
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
      if (!secp::SignDer(priv, e.challenge, sigDer, &sigLen)) return ErrorCode::kInvalidRequest;
      w.BeginMap(3);
      w.Key("publicKey");
      w.Bytes(keystore::KeyStore::PublicKey(), 33);
      w.Key("signature");
      w.Bytes(sigDer, sigLen);
      w.Key("signatureFormat");
      w.Text("der-strict-lows");
      break;
    }
    case OpId::kTxSign: {
      TxReview rv = ReviewTx(e.tx);
      if (!rv.ok) return ErrorCode::kInvalidRequest;
      if (!SignInput(e.tx, sigDer, &sigLen)) return ErrorCode::kInvalidRequest;
      w.BeginMap(4);
      w.Key("publicKey");
      w.Bytes(keystore::KeyStore::PublicKey(), 33);
      w.Key("sighash");
      w.Bytes(rv.sighash, 32);
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
      w.Key("messageDigest");
      w.Bytes(dg, 32);
      w.Key("publicKey");
      w.Bytes(keystore::KeyStore::PublicKey(), 33);
      w.Key("signature");
      w.Bytes(sigDer, sigLen);
      break;
    }
    case OpId::kChannelSeal: {
      uint8_t key[32];
      if (!ChannelSealKey(e.peerPub, e.protocolType, key)) return ErrorCode::kInvalidRequest;
      uint8_t nonce[12];
      rand::Fill(nonce, 12);
      uint8_t aad[64];
      size_t aadLen = 0;
      memcpy(aad, "rockey:channel:seal:v1", 22);
      aadLen = 22;
      size_t pl = strlen(e.protocolType);
      memcpy(aad + aadLen, e.protocolType, pl);
      aadLen += pl;
      uint8_t ct[520];
      uint8_t tag[16];
      if (!aead::Seal(key, nonce, aad, aadLen, e.message, e.messageLen, ct, tag)) {
        return ErrorCode::kInvalidRequest;
      }
      w.BeginMap(3);
      w.Key("ciphertext");
      w.Bytes(ct, e.messageLen);
      w.Key("nonce");
      w.Bytes(nonce, 12);
      w.Key("tag");
      w.Bytes(tag, 16);
      secure::Wipe(key, sizeof(key));
      secure::Wipe(ct, sizeof(ct));
      break;
    }
    case OpId::kChannelOpen: {
      uint8_t key[32];
      if (!ChannelSealKey(e.senderPub, e.protocolType, key)) return ErrorCode::kInvalidRequest;
      uint8_t aad[64];
      size_t aadLen = 0;
      memcpy(aad, "rockey:channel:seal:v1", 22);
      aadLen = 22;
      size_t pl = strlen(e.protocolType);
      memcpy(aad + aadLen, e.protocolType, pl);
      aadLen += pl;
      if (e.ciphertextLen < 16) return ErrorCode::kInvalidRequest;
      uint8_t plain[512];
      if (!aead::Open(key, e.channelNonce, aad, aadLen, e.ciphertext,
                            e.ciphertextLen - 16, e.ciphertext + e.ciphertextLen - 16, plain)) {
        secure::Wipe(key, sizeof(key));
        return ErrorCode::kInvalidRequest;
      }
      w.BeginMap(1);
      w.Key("plaintext");
      w.Bytes(plain, e.ciphertextLen - 16);
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
      w.Key("ciphertextHex");
      w.Text(ctHex);
      w.Key("keySource");
      w.Text(kKeySource);
      w.Key("nonceHex");
      w.Text(nonceHex);
      w.Key("saltHex");
      w.Text(saltHex);
      w.Key("version");
      w.Uint(kEnvelopeVersion);
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