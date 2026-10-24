#pragma once
#include "i18n/i18n.h"
#include <string>
namespace rockey::vlp {
// Fixed labels are device-owned; host/App strings are values, never titles.
inline const char* payment_fact_label(const std::string& key) {
  using i18n::Str;
  if(key=="app")return i18n::T(Str::kVlpApp);
  if(key=="origin")return i18n::T(Str::kVlpOrigin);
  if(key=="publisher")return i18n::T(Str::kVlpPublisher);
  if(key=="paymentType")return i18n::T(Str::kVlpPaymentType);
  if(key=="purpose")return i18n::T(Str::kVlpPurpose);
  if(key=="ownership")return i18n::T(Str::kVlpOwnership);
  if(key=="recipient")return i18n::T(Str::kVlpRecipient);
  if(key=="businessAmount")return i18n::T(Str::kVlpBusinessAmount);
  return nullptr;
}
inline std::string payment_fact_value(const std::string& key,const std::string& value) {
  if(key=="ownership"){
    if(value=="third-party")return i18n::T(i18n::Str::kVlpThirdPartyRisk);
    if(value=="app-publisher")return i18n::T(i18n::Str::kVlpPublisherRisk);
  }
  return value;
}
}
