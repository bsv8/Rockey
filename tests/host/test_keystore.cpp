// 主机侧测试（需要 mbedtls）：编译 src/ 里的**真实** keystore / vault_fs /
// digest / aead 实现，跑密钥封装与恢复备份的端到端行为。
//
// 覆盖的都是"静默替换身份"或"解锁语义出错"这类只能靠执行才能发现的缺陷：
//  - 首次设置 PIN 后能解锁，错误 PIN 记失败并进入递增等待（跨重启留时长）；
//  - **已有 Key 时拒绝不同 Key 覆盖**（需求 §2 / R2）：换 Key 必须显式擦除；
//  - 同一 Key 允许重新封装（换 PIN / 恢复），旧密文立即作废；
//  - ChangePin 失败不破坏旧封装；
//  - 恢复备份往返：恢复码+备份在新 PIN 下解回同一把 Key；篡改即拒绝；
//  - 擦除后才能写入另一把 Key。
//
// 注意：这里的曲线运算用 mbedTLS 3.6 + 确定性 RNG（见 shim_env.cpp 注释），
// 验证的是 keystore 的**状态机与提交逻辑**；真机上的密码学仍由固件 SelfTest
// 与 tools/test-vectors/main.py 覆盖，两者不能互相替代。
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <LittleFS.h>
#include "store/vault_fs.h"
#include "store/crc32.h"
#include "../../Coding/Rockey/vaultlink-sdk/device/sdk/migration.hpp"
#include "../../Coding/Rockey/vaultlink-integration/pin_reauthentication.hpp"
#include "../../Coding/Rockey/vaultlink-integration/migration_keystore.hpp"
#include "../../Coding/Rockey/vaultlink-integration/migration_store.hpp"
#include "../../Coding/Rockey/vaultlink-integration/provision_keys.hpp"
#include <fstream>

#include "core/log.h"
#include "crypto/secp256k1.h"
#include "store/keystore.h"
#include "ops/local_secret.h"

// 主机替身时钟（shim_env.cpp）
void delay(unsigned long ms);
unsigned long millis();

using rockey::keystore::KeyStore;
using rockey::keystore::Status;

namespace {

int g_pass = 0;
int g_fail = 0;
const char* g_case = "";

void Begin(const char* name) { g_case = name; }

void Check(bool cond, const char* what) {
  if (cond) {
    g_pass++;
  } else {
    g_fail++;
    printf("  FAIL [%s] %s\n", g_case, what);
  }
}

// 两把不同的合法私钥（都不等于设备测试密钥）
const uint8_t kPrivA[32] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                            0xcc, 0xdd, 0xee, 0xff, 0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
                            0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0x01};
const uint8_t kPrivB[32] = {0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb,
                            0xdc, 0xed, 0xfe, 0x0f, 0x10, 0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a,
                            0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x02};
const char* kPin = "12345678";
const char* kPin2 = "87654321";

void KeyHex(const uint8_t priv[32], char out[67]) {
  uint8_t pub[33];
  if (!rockey::secp::PubkeyFromPriv(priv, pub)) {
    out[0] = '\0';
    return;
  }
  static const char* hex = "0123456789abcdef";
  for (int i = 0; i < 33; ++i) {
    out[i * 2] = hex[pub[i] >> 4];
    out[i * 2 + 1] = hex[pub[i] & 0xF];
  }
  out[66] = '\0';
}

// 主机替身时钟推进到 PIN 等待结束。
// 设备侧语义：失败后必须等满（时长落盘，重启不清零），所以每次成功解锁前
// 都要先把等待耗尽，否则会按 kNeedsWait 拒绝 —— 那是正确行为，不是缺陷。
void DrainPinWait() {
  for (int i = 0; i < 1200; ++i) {
    if (KeyStore::WaitMsRemaining(millis()) == 0) return;
    delay(1000);
  }
}

}  // namespace

int main() {
  printf("rockey host tests: keystore (needs mbedtls)\n");

  Begin("keystore/init");
  Check(KeyStore::Init(), "KeyStore::Init");
  Check(!KeyStore::HasKey(), "no key on a fresh device");

  Begin("keystore/set-pin");
  Check(KeyStore::SetPinAndWrap(kPin, strlen(kPin), kPrivA, rockey::keystore::BsvNetwork::Main) == Status::kOk, "first set PIN + wrap");
  Check(KeyStore::HasKey(), "key present after setup");

  char hexA[67];
  char hexB[67];
  KeyHex(kPrivA, hexA);
  KeyHex(kPrivB, hexB);
  Check(strlen(hexA) == 66 && strlen(hexB) == 66, "both fixtures derive to real pubkeys");
  Check(strcmp(hexA, hexB) != 0, "fixtures are different keys");

  Check(KeyStore::Info_().bsvNetwork == rockey::keystore::BsvNetwork::Main, "created identity has main network");
  Check(KeyStore::SetPinAndWrap(kPin, strlen(kPin), kPrivA, rockey::keystore::BsvNetwork::Test) == Status::kWrongKey,
        "same private key cannot replace its identity network");
  Check(KeyStore::Info_().bsvNetwork == rockey::keystore::BsvNetwork::Main, "rejected network change preserves original identity");
  Begin("keystore/refuse-different-key");
  // R2：已有 Key 时拒绝不同 Key 覆盖 —— 换 Key 必须显式擦除设备。
  // 少了这道检查，任何调用方（含 UI 与迁移流程）都能静默替换设备身份。
  Check(KeyStore::SetPinAndWrap(kPin, strlen(kPin), kPrivB, rockey::keystore::BsvNetwork::Main) == Status::kWrongKey,
        "different key is refused while a key exists");
  {
    rockey::keystore::Info info = KeyStore::Info_();
    Check(info.initialized, "record still present after refusal");
  }
  // 拒绝之后旧 Key 仍然可以正常解锁：拒绝不能把设备搞坏
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "original key still unlocks");
  Check(KeyStore::IsUnlocked(), "unlocked");
  {
    const uint8_t* p = KeyStore::PrivateKey();
    Check(p && memcmp(p, kPrivA, 32) == 0, "unlocked private key is the original one");
  }
  KeyStore::Lock();
  Check(!KeyStore::IsUnlocked(), "lock clears the key");

  Begin("keystore/wrong-pin");
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "unlock before re-authentication");
  uint32_t failsBefore = KeyStore::FailCount();
  Check(KeyStore::Unlock("00000000", 8) == Status::kWrongPin, "wrong PIN refused");
  Check(KeyStore::FailCount() == failsBefore + 1, "failure count persisted");
  Check(KeyStore::WaitMsRemaining(millis()) > 0,
        "failure wait is in effect (stored as duration, not a timestamp)");
  Check(!KeyStore::IsUnlocked(), "not unlocked after wrong PIN");
  Check(KeyStore::PrivateKey() == nullptr, "failed re-authentication removes access to the old RAM key");

  Begin("keystore/re-unlock");
  // 等待期过后（主机替身时钟可以推进）用正确 PIN 解锁，失败计数归零
  DrainPinWait();
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "correct PIN unlocks after the wait");
  Check(KeyStore::FailCount() == 0, "success resets the failure count");

  Begin("keystore/invalid-reauthentication");
  Check(KeyStore::Unlock(nullptr, 8) == Status::kInvalidArg, "null PIN is rejected");
  Check(!KeyStore::IsUnlocked() && KeyStore::PrivateKey() == nullptr, "invalid re-authentication also clears the old RAM key");
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "valid PIN can unlock again");

  Begin("keystore/change-pin-reauthentication");
  const auto oldFailures = KeyStore::FailCount();
  Check(KeyStore::ChangePin("00000000", 8, kPin2, strlen(kPin2)) == Status::kWrongPin,
        "change PIN rejects wrong old PIN");
  Check(!KeyStore::IsUnlocked(), "failed PIN change clears unlocked RAM Key");
  Check(KeyStore::FailCount() == oldFailures + 1, "PIN change failure uses persistent counter");
  Check(KeyStore::WaitMsRemaining(millis()) > 0, "PIN change failure enters persistent wait");
  Check(KeyStore::ChangePin(kPin, strlen(kPin), kPin2, strlen(kPin2)) == Status::kLocked,
        "PIN change cannot bypass lock after a failure");
  DrainPinWait();
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "failed PIN change preserves old encrypted Key");

  Begin("keystore/change-pin");
  Check(KeyStore::ChangePin(kPin, strlen(kPin), kPin2, strlen(kPin2)) == Status::kOk,
        "change PIN while unlocked");
  KeyStore::Lock();
  Check(KeyStore::Unlock(kPin, strlen(kPin)) != Status::kOk, "old PIN no longer works");
  // 上一次失败又进入等待：先耗尽再用新 PIN（设备行为，非缺陷）
  DrainPinWait();
  Check(KeyStore::Unlock(kPin2, strlen(kPin2)) == Status::kOk, "new PIN works");
  KeyStore::Lock();

  Begin("keystore/recovery-backup");
  // 需要解锁状态才能生成备份（上一次失败又进入了等待，先耗尽）
  DrainPinWait();
  Check(KeyStore::Unlock(kPin2, strlen(kPin2)) == Status::kOk, "unlock for backup");
  char code[64] = {0};
  uint8_t blob[256] = {0};
  size_t blobLen = sizeof(blob);
  Check(KeyStore::CreateRecoveryBackup(code, sizeof(code), blob, &blobLen) == Status::kOk,
        "recovery backup created");
  Check(strlen(code) == KeyStore::kRecoveryCodeChars, "recovery code is 26 base32 chars");
  Check(KeyStore::HasRecoveryBackup(), "backup record written");

  // 擦除后用"恢复码 + 备份 + 新 PIN"在新设备上恢复同一把 Key
  Check(KeyStore::Erase(), "erase completes all persistent removals");
  Check(!KeyStore::HasKey(), "erase removed the key");
  Check(KeyStore::RestoreFromBackup(code, blob, blobLen, kPin, strlen(kPin)) == Status::kOk,
        "restore the same key from the backup");
  DrainPinWait();
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "restored key unlocks with new PIN");
  {
    const uint8_t* p = KeyStore::PrivateKey();
    Check(p && memcmp(p, kPrivA, 32) == 0, "restored key is the original private key");
  }
  KeyStore::Lock();

  Begin("keystore/restore-tamper");
  {
    uint8_t bad[256] = {0};
    memcpy(bad, blob, blobLen);
    bad[blobLen - 1] ^= 0x01;  // 改 tag 一个比特
    Check(KeyStore::RestoreFromBackup(code, bad, blobLen, kPin, strlen(kPin)) != Status::kOk,
          "tampered backup is refused");
  }
  {
    uint8_t bad[256] = {0};
    memcpy(bad, blob, blobLen);
    Check(KeyStore::RestoreFromBackup("aaaaaaaaaaaaaaaaaaaaaaaaaa", bad, blobLen, kPin,
                                      strlen(kPin)) != Status::kOk,
          "wrong recovery code is refused");
  }

  Begin("keystore/erase-then-other-key");
  Check(KeyStore::Erase(), "erase completes before another key may be created");
  Check(KeyStore::Erase(), "already-erased device removal is idempotent");
  Check(!KeyStore::HasKey(), "erased again");
  // 显式擦除之后才允许写入另一把 Key
  Check(KeyStore::SetPinAndWrap(kPin, strlen(kPin), kPrivB, rockey::keystore::BsvNetwork::Main) == Status::kOk,
        "a different key is allowed only after an explicit erase");
  DrainPinWait();
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "the new key unlocks");
  {
    const uint8_t* p = KeyStore::PrivateKey();
    Check(p && memcmp(p, kPrivB, 32) == 0, "the device now holds the new key");
  }
  KeyStore::Lock();

  Begin("store/large-ledger-generation");
  // Real vault_fs.cpp executes over the documented host LittleFS adapter; this
  // checks record logic, not physical Flash power-failure behavior.
  std::vector<uint8_t> large(65536, 0x5a), restored(large.size());
  uint32_t generation = 0; size_t size = 0;
  const char* path = "/vault/vlp-policy.bin";
  Check(rockey::store::WriteRecord(path, 1, large.data(), large.size(), &generation) && generation == 1,
        "full-size ledger initial generation");
  large.back() ^= 1;
  Check(rockey::store::WriteRecord(path, 1, large.data(), large.size(), &generation) && generation == 2,
        "64KB ledger increments generation instead of resetting after 1KB");
  Check(rockey::store::ReadRecord(path, restored.data(), restored.size(), &size, &generation)
        && size == large.size() && generation == 2 && restored == large, "large ledger readback");
  uint32_t crc = rockey::store::Crc32Extend(UINT32_MAX, large.data(), 1023);
  crc = rockey::store::Crc32Extend(crc, large.data() + 1023, large.size() - 1023);
  Check((crc ^ UINT32_MAX) == rockey::store::Crc32(large.data(), large.size()), "streaming CRC matches whole-record CRC");
  File valid = LittleFS.open(path, "r");
  std::vector<uint8_t> raw(valid.size()); valid.read(raw.data(), raw.size()); valid.close();
  auto rewrite = [](const char* record, const std::vector<uint8_t>& bytes) {
    File file = LittleFS.open(record, "w"); file.write(bytes.data(), bytes.size()); file.close();
  };
  auto bad = raw; bad.back() ^= 1; rewrite(path, bad);
  Check(!rockey::store::WriteRecord(path, 1, large.data(), large.size(), &generation), "corrupt existing ledger is not overwritten");
  File unchanged = LittleFS.open(path, "r"); std::vector<uint8_t> actual(unchanged.size());
  unchanged.read(actual.data(), actual.size()); unchanged.close();
  Check(actual == bad, "corrupt evidence remains available for recovery");
  raw[6] = raw[7] = raw[8] = raw[9] = 0xff; rewrite(path, raw);
  Check(!rockey::store::WriteRecord(path, 1, large.data(), large.size(), &generation), "generation exhaustion cannot wrap to zero");
  Check(rockey::store::Remove(path), "explicit removal of exhausted test bank");
  Check(!rockey::store::WriteRecord(path, 1, large.data(), large.size() + 1, nullptr), "over-limit payload rejected before reading buffer");
  const std::string tooLong = "/vault/" + std::string(128, 'a');
  Check(!rockey::store::WriteRecord(tooLong.c_str(), 1, nullptr, 0, nullptr)
        && !rockey::store::Remove(tooLong.c_str()), "temporary paths cannot truncate onto another record");

  Begin("keystore/corrupt-records-refuse-reset");
  File key = LittleFS.open(rockey::store::kPathKey, "r");
  std::vector<uint8_t> envelope(key.size()); key.read(envelope.data(), envelope.size()); key.close();
  auto brokenKey = envelope; brokenKey.back() ^= 1; rewrite(rockey::store::kPathKey, brokenKey);
  Check(KeyStore::HasKey(), "corrupt envelope remains an existing key");
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kCorrupt && !KeyStore::IsUnlocked(), "corrupt envelope never appears as uninitialized");
  Check(KeyStore::SetPinAndWrap(kPin, strlen(kPin), kPrivA, rockey::keystore::BsvNetwork::Main) == Status::kCorrupt, "corrupt key cannot be overwritten by a new identity");
  rewrite(rockey::store::kPathKey, envelope);
  File state = LittleFS.open(rockey::store::kPathState, "r");
  std::vector<uint8_t> attempts(state.size()); state.read(attempts.data(), attempts.size()); state.close();
  attempts.back() ^= 1; rewrite(rockey::store::kPathState, attempts);
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kIoError && KeyStore::PrivateKey() == nullptr,
        "corrupt PIN state blocks unlock instead of resetting attempts");
  Check(KeyStore::Erase(), "only explicit device erase removes corrupt persistent state");
  Check(KeyStore::SetPinAndWrap(kPin, strlen(kPin), kPrivB, rockey::keystore::BsvNetwork::Main) == Status::kOk
        && KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "explicit erase restores a valid fresh setup");
  KeyStore::Lock();

  Begin("keystore/migration-erase-preserves-recovery");
  using namespace vaultlink;
  uint8_t migrationPub[33]; rockey::secp::PubkeyFromPriv(kPrivB,migrationPub);
  auto progress=obj({{"version",Value(uint64_t(1))},{"id","aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
    {"walletGeneration","bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},{"publicKey",Bytes(migrationPub,migrationPub+33)},
    {"sourceHash",Bytes(32,1)},{"policyHash",Bytes(32,2)},{"direction","to-software"},
    {"phase","erasing"},{"targetHash",Bytes(32,3)}});
  auto publicRecord=encode(inspect_device_migration(progress),1024);
  Check(rockey::store::WriteRecord("/vault/vlp-migration.bin",1,publicRecord.data(),publicRecord.size(),nullptr),"write canonical public erasing progress");
  Check(KeyStore::Erase(true),"migration erase removes secrets while preserving its public marker");
  Check(!KeyStore::HasKey()&&KeyStore::PrivateKey()==nullptr,"no old private-key access after migration erase");
  std::vector<uint8_t> recovered(1024);size_t progressSize=0;
  Check(rockey::store::ReadRecord("/vault/vlp-migration.bin",recovered.data(),recovered.size(),&progressSize,nullptr)
    && progressSize==publicRecord.size()&&std::equal(publicRecord.begin(),publicRecord.end(),recovered.begin()),"recovery progress survives key erase exactly");
  Check(KeyStore::SetPinAndWrap(kPin,strlen(kPin),kPrivA, rockey::keystore::BsvNetwork::Main)==Status::kCorrupt,"pending erased migration cannot become a fresh wallet");
  Check(KeyStore::Erase()&&!rockey::store::Exists("/vault/vlp-migration.bin"),"independent explicit reset removes recovery state before a different identity");
  Begin("keystore/three-button-private-operation-reauthentication");
  Check(KeyStore::SetPinAndWrap(kPin,strlen(kPin),kPrivB, rockey::keystore::BsvNetwork::Main)==Status::kOk
    && KeyStore::Unlock(kPin,strlen(kPin))==Status::kOk,"set up actual KeyStore for reauthentication");
  rockey::vlp::PinReauthentication physicalPin;
  Check(physicalPin.begin()&&!physicalPin.verified()&&physicalPin.required()==strlen(kPin),"new physical PIN entry never inherits a prior approval");
  physicalPin.previous();Check(physicalPin.digit()==9,"A decrements selected digit with wrap");
  physicalPin.next();Check(physicalPin.digit()==0,"C increments selected digit with wrap");
  physicalPin.select();physicalPin.back();Check(physicalPin.entered()==0,"B long-press deletes the last entered digit");
  for(size_t i=0;i<strlen(kPin);++i) {
    for(char digit='0';digit<kPin[i];++digit)physicalPin.next();
    auto result=physicalPin.select();
    Check(result==(i+1==strlen(kPin)?rockey::vlp::PinReauthentication::Verified:rockey::vlp::PinReauthentication::Pending),"only the complete correct PIN verifies");
  }
  Check(physicalPin.verified()&&physicalPin.entered()==0&&KeyStore::IsUnlocked(),"successful reauthentication clears entered PIN and preserves actual unlocked key");
  Check(physicalPin.begin()&&!physicalPin.verified(),"a new private request resets PIN verification");
  const auto attemptsBefore=KeyStore::FailCount();
  for(size_t i=0;i<strlen(kPin);++i)physicalPin.select();
  Check(!physicalPin.verified()&&!KeyStore::IsUnlocked()&&KeyStore::PrivateKey()==nullptr,"incorrect physical PIN cannot retain the previous RAM key");
  Check(KeyStore::FailCount()==attemptsBefore+1&&KeyStore::WaitMsRemaining(millis())>0,"private-operation PIN uses persistent attempts and waiting");
  Check(!physicalPin.begin(),"a failed private operation cannot turn into a second unlock flow");
  DrainPinWait();Check(KeyStore::Unlock(kPin,strlen(kPin))==Status::kOk,"normal device unlock recovers only after the PIN wait");
  physicalPin.clear();KeyStore::Lock();
  Begin("keystore/private-export-host-commit-physical-erase");
  Check(KeyStore::Unlock(kPin,strlen(kPin))==Status::kOk,"unlock actual hardware key before browser-triggered export");
  auto osRandom=[](void*,unsigned char* bytes,size_t count)->int {
    std::ifstream entropy("/dev/urandom",std::ios::binary);entropy.read(reinterpret_cast<char*>(bytes),count);return entropy?0:-1;
  };
  Bytes rawKey(kPrivB,kPrivB+32);IdentityKey runtimeCopy(rawKey,osRandom);wipe_bytes(rawKey);
  auto own=runtimeCopy.public_key();auto keyHex=[](const Bytes& bytes){return to_hex(bytes);};
  auto bank=encode(obj({{"version",uint64_t(2)},{"key",keyHex(own)},
    {"channels",Value::list({})},{"sessions",Value::list({})},
    {"pending",Value::list({})},{"pools",Value::list({})}}),65536);
  Check(rockey::store::WriteRecord("/vault/vlp-policy.bin",1,bank.data(),bank.size(),nullptr),"persist actual canonical source ledger before export");
  rockey::vlp::KeyStoreMigrationKeys deviceKeys(own,[&]{runtimeCopy.lock();});
  rockey::vlp::MigrationStore migrationDisk;MigrationJournal deviceJournal(migrationDisk);
  // Explicit HOST event adapter: verified=true only after the real three-button
  // input model authenticates against the real KeyStore. Not a physical-button test.
  class HostPrivateUI final:public rockey::vlp::ApprovalUI {
   public:rockey::vlp::Review review;rockey::vlp::Approval answer;
    void begin(const rockey::vlp::Review& r)override{review=r;}
    rockey::vlp::Approval decision()override{return answer;}
    void clear()override{}
  } privateUI;
  rockey::vlp::MigrationPrivateRequests privateRequests(deviceJournal,deviceKeys,privateUI,[&]{return bank;},
    [](bool erase){return std::string(erase?"Erase old key after browser commit":"Private key leaves device once");});
  const std::string transferId="dddddddd-dddd-dddd-dddd-dddddddddddd";
  auto exportBody=obj({{"id",transferId},{"walletGeneration","eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"},
    {"sourceHash",Bytes(32,1)},{"policyHash",sha256(bank)}});
  privateUI.answer={rockey::vlp::Approval::Denied,0,false};
  {
    auto rejected=privateRequests.prepare("migration.export",exportBody,commitment("key-migration-export",exportBody));
    Check(!rejected.cache_result&&rejected.operation->ready()&&!rejected.operation->allowed(),"browser export still requires a fresh physical once decision");
    bool directDenied=false;try{rejected.operation->execute();}catch(const Failure&){directDenied=true;}
    Check(directDenied&&deviceJournal.status().kind==Value::Null,"denial cannot export the private key");
  }
  privateUI.answer={rockey::vlp::Approval::Once,0,false};
  {
    auto exportRequest=privateRequests.prepare("migration.export",exportBody,commitment("key-migration-export",exportBody));
    Check(exportRequest.operation->ready()&&exportRequest.operation->allowed()&&!privateUI.review.requires_pin
      &&!privateUI.review.can_remember&&!privateUI.review.can_raise,"export requires physical once-only approval without repeated PIN");
    auto result=exportRequest.operation->execute();
    Check(result.at("privateKey").binary(32)==Bytes(kPrivB,kPrivB+32),"export returns the actual KeyStore private key once");
    Check(result.at("migration").at("phase").string()=="device-committed","public journal commits before delivering key");
  }
  auto commitBody=obj({{"id",transferId},{"targetHash",Bytes(32,3)}});
  bool prematureErase=false;try{privateRequests.prepare("migration.erase",commitBody,commitment("key-migration-erase",commitBody));}
  catch(const Failure&){prematureErase=true;}
  Check(prematureErase&&KeyStore::HasKey(),"device erase is impossible before the browser commit acknowledgement");
  auto acknowledge=privateRequests.prepare("migration.host-commit",commitBody,commitment("key-migration-host-commit",commitBody));
  Check(acknowledge.operation->ready()&&acknowledge.operation->execute().at("migration").at("phase").string()=="complete",
    "public browser commit binds its target KeyHold hash");
  auto changedCommit=obj({{"id",transferId},{"targetHash",Bytes(32,4)}});bool changedTarget=false;
  try{privateRequests.prepare("migration.erase",changedCommit,commitment("key-migration-erase",changedCommit));}
  catch(const Failure&){changedTarget=true;}
  Check(changedTarget&&KeyStore::HasKey(),"another target hash cannot erase the source key");
  privateUI.answer={rockey::vlp::Approval::Denied,0,false};
  {
    auto deniedErase=privateRequests.prepare("migration.erase",commitBody,commitment("key-migration-erase",commitBody));
    Check(deniedErase.operation->ready()&&!deniedErase.operation->allowed()&&KeyStore::HasKey(),"optional erase denial retains the key");
  }
  Check(!deviceJournal.pending()&&deviceJournal.status().at("phase").string()=="complete","retained backup does not leave transfer unfinished");
  privateUI.answer={rockey::vlp::Approval::Once,0,false};
  auto eraseRequest=privateRequests.prepare("migration.erase",commitBody,commitment("key-migration-erase",commitBody));
  Check(eraseRequest.operation->ready()&&eraseRequest.operation->allowed(),"new independent physical erase is permitted without repeated PIN");
  auto erased=eraseRequest.operation->execute();
  Check(erased.at("migration").at("phase").string()=="erased"&&!KeyStore::HasKey()&&KeyStore::PrivateKey()==nullptr,
    "hardware source key is erased after host commit and separate physical approval");
  Check(!rockey::store::Exists("/vault/vlp-policy.bin")&&deviceJournal.status().at("targetHash").binary(32)==Bytes(32,3),
    "old hardware ledger is removed while public recovery target remains");
  bool copyWiped=false;try{runtimeCopy.sign(Bytes(32,1));}catch(const Failure&){copyWiped=true;}
  Check(copyWiped,"erase clears the runtime signing copy as well as KeyStore RAM");
  MigrationJournal restartedJournal(migrationDisk);
  Check(restartedJournal.status().at("phase").string()=="erased","actual public erase receipt reloads from atomic device storage");
  physicalPin.clear();
  Begin("keystore/device-local-import-pin");
  Check(KeyStore::Erase(),"start import PIN test only after explicit reset");
  rockey::vlp::ProvisionKeys provisional;
  provisional.arm(kPin,strlen(kPin),rockey::keystore::BsvNetwork::Main);
  Check(provisional.ready()&&!KeyStore::HasKey(),"new import PIN is device-local and does not create a key");
  rockey::vlp::PinReauthentication repeated;
  Check(repeated.begin_local(provisional.digits(),[&](const char* p,size_t n){return provisional.authenticate(p,n,millis());}),"import re-entry uses the real PIN model");
  for(const char* c=kPin2;*c;++c){for(char d='0';d<*c;++d)repeated.next();repeated.select();}
  Check(!repeated.verified()&&!provisional.ready()&&KeyStore::FailCount()==1&&!KeyStore::HasKey(),"wrong import PIN is durably counted, clears setup PIN and cannot create key");
  auto wait=KeyStore::WaitMsRemaining(millis());
  Check(wait>0,"wrong import PIN starts actual persistent wait gate");
  provisional.arm(kPin,strlen(kPin),rockey::keystore::BsvNetwork::Main);
  Check(!provisional.authenticate(kPin,strlen(kPin),millis())&&KeyStore::FailCount()==1,"correct PIN cannot bypass the wait gate by re-arming import");
  delay(wait+1);
  Check(provisional.authenticate(kPin,strlen(kPin),millis())&&KeyStore::FailCount()==0,"only correct local PIN after waiting clears the persistent counter");
  provisional.clear();
  Check(!provisional.ready(),"local cancellation clears provisional PIN readiness");
  KeyStore::Lock();
  Check(KeyStore::PrivateKey()==nullptr,"boot KAT begins with actual KeyStore locked");
  Check(rockey::ops::SelfTest(),"local-secret KAT uses public vector while wallet is locked");
  Check(!KeyStore::IsUnlocked()&&KeyStore::PrivateKey()==nullptr,"boot KAT never unlocks the user wallet");
  Begin("keystore/test-network-identity");
  Check(KeyStore::Erase(), "explicit reset before creating a test identity");
  Check(KeyStore::SetPinAndWrap(kPin, strlen(kPin), kPrivA, rockey::keystore::BsvNetwork::Test) == Status::kOk, "create test identity with the same private key");
  Check(KeyStore::Init() && KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk, "test identity survives reboot and unlock");
  Check(KeyStore::Info_().bsvNetwork == rockey::keystore::BsvNetwork::Test, "reboot retains test network");
  Check(KeyStore::ChangePin(kPin, strlen(kPin), kPin2, strlen(kPin2)) == Status::kOk, "change test identity PIN");
  Check(KeyStore::Info_().bsvNetwork == rockey::keystore::BsvNetwork::Test, "PIN change retains test network");
  char testCode[64] = {0}; uint8_t testBackup[256] = {0}; size_t testBackupLen = sizeof(testBackup);
  Check(KeyStore::CreateRecoveryBackup(testCode, sizeof(testCode), testBackup, &testBackupLen) == Status::kOk, "create authenticated test identity backup");
  Check(KeyStore::Erase(), "erase before restoring test identity");
  Check(KeyStore::RestoreFromBackup(testCode, testBackup, testBackupLen, kPin, strlen(kPin)) == Status::kOk, "restore authenticated test identity backup");
  Check(KeyStore::Unlock(kPin, strlen(kPin)) == Status::kOk && KeyStore::Info_().bsvNetwork == rockey::keystore::BsvNetwork::Test, "restored identity retains network plus private key");
  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
