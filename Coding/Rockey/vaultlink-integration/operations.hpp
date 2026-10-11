#pragma once
#include "../vaultlink-sdk/device/sdk/endpoint.hpp"
#include "../vaultlink-sdk/device/sdk/policy.hpp"
#include "../vaultlink-sdk/device/sdk/feepool.hpp"
#include "../vaultlink-sdk/device/sdk/standard.hpp"
#include "../vaultlink-sdk/device/sdk/local_secret.hpp"
#include "../vaultlink-sdk/device/sdk/connect_envelope.hpp"
#include "../vaultlink-sdk/device/sdk/channel.hpp"
#include "../vaultlink-sdk/device/sdk/bitfs_wire.hpp"
#include "../vaultlink-sdk/device/sdk/network_identity.hpp"
#include <memory>
#include "scope_grants.hpp"
#include "approval_ui.hpp"
namespace rockey::vlp {
class PaymentService {
  vaultlink::IdentityKey &key;
  const std::string network;
  vaultlink::Policy policy;
  ApprovalUI &ui;
  ScopeGrants grants;
  class IdentityQuery final:public vaultlink::Operation {
    PaymentService& service;
   public:
    explicit IdentityQuery(PaymentService& s):service(s){}
    bool ready() override{return true;}
    bool allowed() override{return true;}
    vaultlink::Value execute() override{return vaultlink::obj({{"bsvNetwork",service.network},{"publicKey",service.key.public_key()}});}
  };
  class Action final : public vaultlink::Operation {
    ApprovalUI &ui;
    bool prompt, finished = false, started = false;
    Review review;
    Approval answer;
    std::function<vaultlink::Value(const Approval &)> run;
    std::function<void(const Approval &)> record;
    bool recorded=false;
   public:
    Action(ApprovalUI &u, Review review, bool ask,
           std::function<vaultlink::Value(const Approval &)> execute,
           std::function<void(const Approval &)> decided = {}, bool deny = false)
        : ui(u), prompt(ask), review(std::move(review)), run(std::move(execute)),record(std::move(decided)) {
      vaultlink::require(prompt||!this->review.requires_pin,"physical-confirmation-required");
      if (!prompt) answer.state = deny ? Approval::Denied : Approval::Once;
    }
    bool ready() override {
      if (prompt) {
        if (!started) { ui.begin(review); started = true; }
        answer = ui.decision();
      }
      return answer.state != Approval::Pending;
    }
    bool allowed() override {
      if(review.requires_pin&&(!answer.pin_verified||answer.state!=Approval::Once))return false;
      if(!recorded){if(record)record(answer);recorded=true;}
      return answer.state==Approval::Once||answer.state==Approval::Raise||answer.state==Approval::AllowSession;
    }
    vaultlink::Value execute() override {
      vaultlink::require(!review.requires_pin||(answer.pin_verified&&answer.state==Approval::Once),"physical-confirmation-required");
      auto result = run(answer);
      // 查询/会话记账不属于授权；仅成功执行的自动授权产生提示，重放缓存
      // 与失败请求不会再次响。人工提示由实际 UI begin 负责。
      if(!prompt&&!review.operation.empty())ui.automatically_approved(review);
      cancel();
      return result;
    }
    void cancel() override { if (!finished && started) ui.clear(); finished = true; }
    ~Action() override { cancel(); }
  };
  vaultlink::Value channel(const std::string &id) {
    return policy.channel_view(id);
  }
 public:
  PaymentService(vaultlink::IdentityKey &k, vaultlink::Store &store, ApprovalUI &u, std::string bsvNetwork)
      : key(k), network(std::move(bsvNetwork)), policy(store, vaultlink::to_hex(k.public_key()),vaultlink::sha256,network), ui(u) {vaultlink::require(network=="main"||network=="test","network-identity-required");}
  size_t grant_count() const{return grants.count();}
  ScopeGrants::Entry grant(size_t i) const{return grants.get(i);}
  void cancel_grant(size_t i){grants.cancel(i);}
  void cancel_grants(){grants.clear();}
  vaultlink::Bytes policy_bank(){return policy.encoded_bank();}
  // USB 断开撤销链路与易失 scope 决定；App 连接预算独立持久，不因串口重连重开。
  void disconnected() { grants.clear(); ui.clear(); }
  vaultlink::Prepared prepare(const std::string &op, const vaultlink::Value &body,
                             const vaultlink::Bytes &hash) {
    using namespace vaultlink;
    if(op=="identity.network"){body.fields({});require(commitment("identity-network",body)==hash,"invalid-commitment");return {"identity-network",body,std::make_unique<IdentityQuery>(*this)};}
    if(op=="bitfs.wire-sign") {
      require(commitment("bitfs-wire-document",body)==hash,"invalid-commitment");auto checked=inspect_bitfs_wire(body,key.public_key());
      require(checked.kind!=5,"payment-context-required");
      Review r{op,"","",{{"operation",op},{"wireKind",std::to_string(checked.kind)},{"objectHash",to_hex(checked.digest)}}};
      r.facts.insert(r.facts.end(),checked.facts.begin(),checked.facts.end());
      return {"bitfs-wire-document",body,std::make_unique<Action>(ui,r,true,[this,body](const Approval &){
        auto current=inspect_bitfs_wire(body,key.public_key());return obj({{"publicKey",key.public_key()},{"signature",key.sign(current.digest)}});
      })};
    }
    if(op=="channel.public-message"||op=="channel.hash-request"||op=="channel.private-message"||op=="channel.seal"||op=="channel.open") {
      body.fields({"message"});const auto &raw=body.at("message").binary();
      const std::string kind=op=="channel.public-message"?"public":op=="channel.hash-request"?"hash":op=="channel.private-message"?"private":op=="channel.seal"?"seal":"open";
      const auto profile="bsv8-channel-"+kind;
      require(commitment(profile,body)==hash,"invalid-commitment");
      ChannelReview checked;
      if(kind=="seal")checked=inspect_signed_channel(raw,key.public_key());
      else if(kind=="open") {
        // Authenticate and verify the sender before displaying authorization scope.
        // No plaintext leaves the device until the user has granted that scope.
        auto opened=key.open_channel(raw);WipeBytes wipe{opened};auto full=parse_jcs(opened);
        auto sender=full.at("from_public_key").string();checked=inspect_signed_channel(opened,channel_pub(sender));checked.peer=sender;
      }else checked=inspect_channel(kind,raw,key.public_key());
      const auto grant_op=kind=="private"||kind=="seal"?std::string("channel.outbound"):kind=="open"?std::string("channel.inbound"):op;
      const auto scope=checked.peer.empty()?checked.channel:checked.peer+"/"+checked.protocol;
      Review r{op,"","",{{"operation",op},{"scope",checked.channel},{"requestId",checked.message_id},
        {"issuedAt",std::to_string(checked.issued)},{"expiresAt",std::to_string(checked.expires)},{"objectHash",to_hex(checked.digest)}}};
      if(!checked.peer.empty())r.facts.push_back({"peer",checked.peer});
      if(!checked.protocol.empty())r.facts.push_back({"protocol",checked.protocol});
      r.can_remember=true;auto expected=std::make_shared<uint64_t>(grants.revision());auto decision=grants.decision(grant_op,scope);
      auto record=[this,expected,grant_op,scope](const Approval &answer){
        require(grants.revision()==*expected,"permission-revoked");
        if(answer.state==Approval::AllowSession||answer.state==Approval::DenySession){grants.set(grant_op,scope,answer.state==Approval::AllowSession?ScopeGrants::Allow:ScopeGrants::Deny);*expected=grants.revision();}
      };
      return {profile,body,std::make_unique<Action>(ui,r,decision==ScopeGrants::Ask,[this,body,kind,expected](const Approval &){
        require(grants.revision()==*expected,"permission-revoked");const auto &message=body.at("message").binary();
        if(kind=="seal")return obj({{"message",key.seal_channel(message)}});
        if(kind=="open")return obj({{"message",key.open_channel(message)}});
        auto verified=inspect_channel(kind,message,key.public_key());return obj({{"publicKey",key.public_key()},{"signature",key.sign(verified.digest)}});
      },record,decision==ScopeGrants::Deny)};
    }
    if(op=="identity.noise-proof"||op=="identity.peer-record") {
      const std::string kind=op=="identity.noise-proof"?"noise":"peer-record",profile="libp2p-identity-"+kind;
      auto checked=inspect_network_identity(kind,body,key.public_key());require(commitment(profile,body)==hash,"invalid-commitment");
      Review r{op,"","",{{"operation",op},{"protocol",kind},{"objectHash",to_hex(checked.digest)}}};
      if(kind=="peer-record")r.facts.push_back({"sequence",checked.sequence});
      // Noise proves ownership of a fixed, device-reconstructed handshake payload.
      // Default to automatic approval; explicit denial/revocation still applies.
      // Peer records remain an independent, manually reviewed permission.
      const bool noise=kind=="noise";
      r.can_remember=!noise;const std::string scope="libp2p-identity";auto expected=std::make_shared<uint64_t>(grants.revision());auto decision=grants.decision(op,scope);
      auto record=[this,expected,op,scope](const Approval &answer){
        require(grants.revision()==*expected,"permission-revoked");
        if(answer.state==Approval::AllowSession||answer.state==Approval::DenySession){grants.set(op,scope,answer.state==Approval::AllowSession?ScopeGrants::Allow:ScopeGrants::Deny);*expected=grants.revision();}
      };
      return {profile,body,std::make_unique<Action>(ui,r,!noise&&decision==ScopeGrants::Ask,[this,body,kind,expected](const Approval &){
        require(grants.revision()==*expected,"permission-revoked");auto current=inspect_network_identity(kind,body,key.public_key());
        return obj({{"publicKey",key.public_key()},{"signature",key.sign(current.digest)}});
      },record,decision==ScopeGrants::Deny)};
    }
    if(op=="connect.identity-sign"||op=="connect.intent-sign") {
      const bool identity=op=="connect.identity-sign";
      const std::string profile=identity?"connect-identity-envelope":"connect-intent-envelope";
      auto checked=inspect_connect(identity?"identity":"intent",body,key.public_key(),network);
      require(commitment(profile,body)==hash,"invalid-commitment");
      Review r{op,"","",{{"operation",op},{"audience",checked.audience},{"requestId",checked.request},
        {"issuedAt",std::to_string(checked.issued)},{"expiresAt",std::to_string(checked.expires)},
        {"objectHash",to_hex(checked.digest)}}};
      if(identity)for(const auto &name:checked.claims)r.facts.push_back({"claim",name});
      else {r.facts.push_back({"contentType",checked.content_type});r.facts.push_back({"contentLength",std::to_string(checked.content_length)});r.facts.push_back({"contentHash",to_hex(checked.content_digest)});}
      // One physical decision per envelope; no persistent or session-wide identity approval.
      return {profile,body,std::make_unique<Action>(ui,r,true,[this,body,identity](const Approval &){
        auto current=inspect_connect(identity?"identity":"intent",body,key.public_key(),network);
        return obj({{"publicKey",key.public_key()},{"signature",key.sign(current.digest)}});
      })};
    }
    if(op=="local-secret.seal"||op=="local-secret.open") {
      const bool seal=op=="local-secret.seal";
      if(seal)body.fields({"scope","plaintext"});else body.fields({"scope","sealed"});
      auto scope=body.at("scope").string();local_scope(scope);
      if(seal)require(!body.at("plaintext").binary().empty()&&body.at("plaintext").binary().size()<=512,"invalid-secret");
      else {const auto &v=body.at("sealed");v.fields({"version","keySource","saltHex","nonceHex","ciphertextHex"});
        require(v.at("version").integer()==3&&v.at("keySource").string()=="active-key-hkdf-v1"&&v.at("saltHex").string().size()==32&&v.at("nonceHex").string().size()==24&&v.at("ciphertextHex").string().size()>=34&&v.at("ciphertextHex").string().size()<=1056,"invalid-secret");}
      auto encoded=encode(body,32768);WipeBytes wipe_encoded{encoded};
      Review r{op,"","",{{"operation",op},{"scope",scope},{"objectHash",to_hex(sha256(encoded))}}};
      r.can_remember=true;
      auto expected=std::make_shared<uint64_t>(grants.revision());
      auto decision=grants.decision(op,scope);
      auto record=[this,expected,op,scope](const Approval &answer){
        require(grants.revision()==*expected,"permission-revoked");
        if(answer.state==Approval::AllowSession||answer.state==Approval::DenySession){
          grants.set(op,scope,answer.state==Approval::AllowSession?ScopeGrants::Allow:ScopeGrants::Deny);
          *expected=grants.revision();
        }
      };
      return {"local-secret-v3",body,std::make_unique<Action>(ui,r,decision==ScopeGrants::Ask,[this,body,seal,scope,expected](const Approval &){
        require(grants.revision()==*expected,"permission-revoked");
        if(seal)return key.seal_local(scope,body.at("plaintext").binary());
        return obj({{"plaintext",Value(key.open_local(scope,body.at("sealed")))}});
      },record,decision==ScopeGrants::Deny)};
    }
    if (op == "payment.configure") {
      body.fields({"id", "owner", "kind", "network", "paymentType", "enabled", "singleLimit", "defaultSessionLimit", "revision"});
      auto payment_type=body.at("paymentType").string();
      require(body.at("network").string() == (network) && (payment_type == "p2pkh" || payment_type == "feepool.connect" || payment_type == "feepool.bitfs" || payment_type == "bsv.standard" || payment_type == "feepool.bitfs.cosigner" || payment_type == "feepool.connect.cosigner"), "unsupported");
      Channel c{body.at("id").string(), body.at("owner").string(), body.at("singleLimit").integer(),
                body.at("defaultSessionLimit").integer(), body.at("revision").integer(),
                body.at("enabled").flag(), body.at("kind").string(), payment_type};
      require(c.kind == "app" || c.kind == "plugin", "invalid-owner");
      Review r{op, c.id, c.owner, {{"singleLimit", std::to_string(c.single)}, {"defaultSessionLimit", std::to_string(c.total)},
                                 {"enabled", c.enabled ? "true" : "false"}, {"kind", c.kind}}};
      return {"payment-config", body, std::make_unique<Action>(ui, r, true, [this, c](const Approval &) {
        policy.configure(c, true);
        return obj({{"configured", true}, {"revision", c.revision}});
      })};
    }
    if (op == "payment.session-open") {
      body.fields({"sessionId", "owner"});
      auto id = body.at("sessionId").string(), owner = body.at("owner").string();
      auto snapshot = policy.snapshot();
      for (const auto &s : snapshot.at("sessions").array) {
        if (s.at("id").string() != id) continue;
        require(s.at("owner").string() == owner && s.at("active").flag(), "invalid-session");
        return {"payment-session", body, std::make_unique<Action>(ui, Review{}, false,
          [s](const Approval &) { return obj({{"opened", true}, {"sessionLimit", s.at("limit")}}); })};
      }
      uint64_t limit = 0; bool found = false;
      for (const auto &c : snapshot.at("channels").array) {
        if (c.at("owner").string() != owner || c.at("kind").string() != "app" || !c.at("enabled").flag()) continue;
        auto value = c.at("defaultSessionLimit").integer();
        require(!found || limit == value, "session-limit-conflict"); limit = value; found = true;
      }
      require(found, "unknown-owner");
      Review r{op, "", owner, {{"sessionId", id}, {"sessionLimit", std::to_string(limit)}}};
      return {"payment-session", body, std::make_unique<Action>(ui, r, true, [this, id, owner, limit](const Approval &) {
        policy.start(id, owner, true);
        return obj({{"opened", true}, {"sessionLimit", limit}});
      })};
    }
    if (op == "payment.session-close") {
      body.fields({"sessionId"});
      auto id = body.at("sessionId").string();
      // 这是撤权，不新增授权，无需为了关闭会话再次要求设备确认。
      return {"payment-session-close", body, std::make_unique<Action>(ui, Review{}, false,
        [this, id](const Approval &) { policy.close_session(id); return obj({{"closed", true}}); })};
    }
    if (op == "payment.channel-list") {
      body.fields({});
      return {"payment-channel-list", body, std::make_unique<Action>(ui, Review{}, false,
        [this](const Approval &) { return policy.channels_view(); })};
    }
    if (op == "payment.channel-read") {
      body.fields({"channelId"});
      auto c = channel(body.at("channelId").string());
      return {"payment-channel-read", body, std::make_unique<Action>(ui, Review{}, false,
        [c](const Approval &) { return c; })};
    }
    if (op == "payment.session-read") {
      body.fields({"sessionId"});
      auto s = policy.session_view(body.at("sessionId").string());
      return {"payment-session-read", body, std::make_unique<Action>(ui, Review{}, false,
        [s](const Approval &) { return s; })};
    }
    if(op=="payment.policy-export") {
      body.fields({"offset","length"});auto offset=body.at("offset").integer(),length=body.at("length").integer();
      require(length>0&&length<=8192,"invalid-range");
      auto snapshot=policy.encoded_bank();require(offset<snapshot.size(),"invalid-range");
      auto count=std::min<uint64_t>(length,snapshot.size()-offset);
      Bytes chunk(snapshot.begin()+offset,snapshot.begin()+offset+count);
      auto result=obj({{"offset",offset},{"size",uint64_t(snapshot.size())},{"sha256",sha256(snapshot)},{"chunk",chunk}});
      return {"payment-policy-export",body,std::make_unique<Action>(ui,Review{},false,[result](const Approval &){return result;})};
    }
    if(op=="payment.pool-read") {
      body.fields({"poolId"});auto pool=policy.pool_state(body.at("poolId").string());
      auto result=obj({{"poolId",pool.id},{"paid",pool.paid},{"binding",pool.binding.empty()?Value():Value(pool.binding)}});
      return {"payment-pool-read",body,std::make_unique<Action>(ui,Review{},false,[result](const Approval &){return result;})};
    }
    bool is_standard=op=="tx.standard-payment";
    const bool is_opening=op=="tx.feepool-bitfs-opening";
    const bool is_authorization=op=="tx.feepool-bitfs-authorize";
    bool is_pool=op=="tx.feepool-connect"||op=="tx.feepool-bitfs"||is_authorization||is_opening;
    if (op != "tx.p2pkh-payment" && !is_pool && !is_standard) throw Failure("unsupported");
    std::string role="payer";bool has_role=false;
    if(is_opening){body.fields({"rawTx","prevTransactions","channelId","paymentId","sessionId","stage","role","openingRequest"});role=body.at("role").string();require(role=="cosigner"&&body.at("stage").string()=="state"&&body.at("prevTransactions").kind==Value::Array&&body.at("prevTransactions").array.empty(),"invalid-opening");}
    else if(is_pool){for(const auto &f:body.map)if(f.first=="role")has_role=true;
      if(has_role){if(is_authorization)body.fields({"rawTx", "prevTransactions", "channelId", "paymentId", "sessionId", "stage", "role", "authorization"});else body.fields({"rawTx", "prevTransactions", "channelId", "paymentId", "sessionId", "stage", "role"});role=body.at("role").string();}
      else {if(is_authorization)body.fields({"rawTx", "prevTransactions", "channelId", "paymentId", "sessionId", "stage", "authorization"});else body.fields({"rawTx", "prevTransactions", "channelId", "paymentId", "sessionId", "stage"});}
      if(is_authorization)require(role=="payer"&&body.at("stage").string()=="state","invalid-authorization");
    }
    else body.fields({"rawTx", "prevTransactions", "channelId", "paymentId", "sessionId"});
    auto raw = body.at("rawTx").binary();
    const auto &prev = body.at("prevTransactions");
    require(prev.kind == Value::Array && prev.array.size() <= (is_standard?10:4), "invalid-prevout");
    std::vector<Bytes> evidence;
    for (const auto &v : prev.array) evidence.push_back(v.binary());
    auto family=op=="tx.feepool-connect"?std::string("connect"):std::string("bitfs");
    PoolReview pool_review;PoolInspection pool;
    vaultlink::Review review;
    auto profile=is_opening?std::string("bsv-feepool-bitfs-opening"):is_authorization?std::string("bsv-feepool-bitfs-authorization"):is_pool?"bsv-feepool-"+family:std::string(is_standard?"bsv-standard-payment":"bsv-payment-context");
    if(is_pool) {
      pool_review=is_opening?inspect_bitfs_opening(raw,body.at("openingRequest").binary(),key.public_key()):is_authorization?inspect_bitfs_authorization(raw,evidence,key.public_key(),body.at("authorization")):inspect_pool(raw,evidence,key.public_key(),family,body.at("stage").string(),role);review=pool_review.review;
      if(!pool_review.pool.empty()) {
        pool=policy.inspect_pool_state(pool_review.pool,pool_review.binding,pool_review.paid);
        review.amount=pool.paid-pool.previous_paid;
        policy.check_pool(pool,review.amount);
      }
    }else review=is_standard?inspect_standard(raw,evidence,key.public_key()):inspect(raw,evidence,key.public_key());
    auto id = body.at("paymentId").string(), channel_id = body.at("channelId").string();
    auto configured = channel(channel_id);
    require(configured.at("paymentType").string()==(is_pool?"feepool."+family+(role=="cosigner"?".cosigner":""):std::string(is_standard?"bsv.standard":"p2pkh")),"invalid-channel");
    auto owner = configured.at("owner").string();
    auto session_id = body.at("sessionId").kind == Value::Null ? "" : body.at("sessionId").string();
    policy.fresh(id);
    auto budget = policy.quote(channel_id, session_id, owner, review.amount);
    Value core = body;
    core.map.push_back({"amount", review.amount});
    require(commitment(profile, core) == hash, "invalid-commitment");
    Review r{op, channel_id, owner, {{"amount", std::to_string(review.amount)}, {"change", std::to_string(review.change)},
      {"fee", std::to_string(review.fee)}, {"singleLimit", std::to_string(configured.at("singleLimit").integer())},
      {"used", std::to_string(budget.used)}, {"sessionLimit", std::to_string(budget.limit)},
      {"singleExceeded", budget.single ? "true" : "false"}, {"sessionExceeded", budget.total ? "true" : "false"}}};
    auto tx = parse_tx(raw);
    if(is_pool) {
      if(is_authorization){auto authorization=inspect_bitfs_wire(obj({{"kind",Value(uint64_t(5))},{"document",body.at("authorization").at("document")}}),key.public_key());r.facts.push_back({"wireKind","5"});r.facts.insert(r.facts.end(),authorization.facts.begin(),authorization.facts.end());}
      r.facts.push_back({"poolFamily",family});r.facts.push_back({"kind",role});r.facts.push_back({"poolStage",body.at("stage").string()});
      r.facts.push_back({"cumulativePaid",std::to_string(pool_review.paid)});
      r.facts.push_back({"lockedAmount",std::to_string(pool_review.locked)});
      if(body.at("stage").string()=="fund")for(const auto &participant:pool_roles(tx.outputs[0].script,family))
        r.facts.push_back({"recipientScript",p2pkh_output_address(own_script(participant))});
    }
    for (const auto &out : tx.outputs) {
      auto description=is_p2pkh(out.script)?p2pkh_output_address(out.script):
        (is_pool && body.at("stage").string()=="fund"?std::string("multisig ")+family:std::string("script ")+to_hex(out.script));
      r.facts.push_back({out.script == own_script(key.public_key()) ? "changeScript" : "recipientScript",
        std::to_string(out.amount) + " sat " + description});
    }
    r.can_raise = budget.total;
    r.minimum_limit = add(budget.used, review.amount);
    return {profile, core, std::make_unique<Action>(ui, r, budget.prompt(),
      [this, id, channel_id, session_id, owner, review, hash, pool,is_authorization](const Approval &a) {
        policy.reserve(id, channel_id, session_id, owner, review.amount, hash, true,
                       a.state == Approval::Raise ? a.limit : 0, pool);
        policy.executable(id);
        std::vector<Value> signatures;
        // 产生签名后的失败保留预占，重启时转成 unknown，不重新执行。
        for (const auto &digest : review.digests) {
          policy.executable(id);
          auto sig = key.sign(digest); if(!is_authorization)sig.push_back(0x41); signatures.push_back(Value(sig));
        }
        policy.signed_payment(id);
        return obj({{"signatures", Value::list(signatures)}, {"amount", review.amount}});
      })};
  }
};
} // namespace rockey::vlp
