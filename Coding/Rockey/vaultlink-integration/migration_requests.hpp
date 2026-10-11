#pragma once
#include "operations.hpp"
#include "../vaultlink-sdk/device/sdk/migration.hpp"
#include "migration_private.hpp"
namespace rockey::vlp {
/** Shared production request router, also run over native encrypted pipes.
 * There are no private-key import/export endpoints here yet. Pending migration
 * permits public recovery reads and Endpoint's cancellation/lock controls only. */
class MigrationRequests {
  PaymentService& payments;
  vaultlink::MigrationJournal& journal;
  MigrationPrivateRequests* private_requests;
  class Status final:public vaultlink::Operation {
    vaultlink::MigrationJournal& journal;
   public:
    explicit Status(vaultlink::MigrationJournal& j):journal(j){}
    bool ready()override{return true;}
    bool allowed()override{return true;}
    vaultlink::Value execute()override{return vaultlink::obj({{"migration",journal.status()}});}
  };
 public:
  MigrationRequests(PaymentService& p,vaultlink::MigrationJournal& j,const vaultlink::Bytes& publicKey,
      MigrationPrivateRequests* priv=nullptr)
      :payments(p),journal(j),private_requests(priv) {
    auto recovery=journal.status();
    if(recovery.kind!=vaultlink::Value::Null) {
      vaultlink::require(recovery.at("publicKey").binary(33)==publicKey,"migration-conflict");
      if(journal.pending()&&recovery.at("phase").string()!="erasing")vaultlink::require(recovery.at("policyHash").binary(32)
        ==vaultlink::sha256(payments.policy_bank()),"migration-policy-changed");
    }
  }
  vaultlink::Prepared prepare(const std::string& op,const vaultlink::Value& body,const vaultlink::Bytes& hash) {
    if(op=="identity.network")return payments.prepare(op,body,hash);
    if(op=="migration.status") {
      body.fields({});vaultlink::require(vaultlink::commitment("key-migration-status",body)==hash,"invalid-commitment");
      return {"key-migration-status",body,std::make_unique<Status>(journal)};
    }
    if(op=="migration.export"||op=="migration.host-commit"||op=="migration.erase") {
      vaultlink::require(private_requests!=nullptr,"unsupported");return private_requests->prepare(op,body,hash);
    }
    if(journal.pending()&&journal.status().at("phase").string()=="erasing")throw vaultlink::Failure("migration-erasing");
    vaultlink::require((!journal.pending()&&(!private_requests||!private_requests->armed()))||op=="payment.policy-export","migration-pending");
    return payments.prepare(op,body,hash);
  }
};
} // namespace rockey::vlp
