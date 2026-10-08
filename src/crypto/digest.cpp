#include "crypto/digest.h"

#include <string.h>

extern "C" {
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
}

#include "crypto/secure.h"

namespace rockey {
namespace digest {

void Sha256(const uint8_t* data, size_t len, uint8_t out[kSha256Len]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  if (len) mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

void Sha256d(const uint8_t* data, size_t len, uint8_t out[kSha256Len]) {
  uint8_t tmp[kSha256Len];
  Sha256(data, len, tmp);
  Sha256(tmp, kSha256Len, out);
  secure::Wipe(tmp, sizeof(tmp));
}

void HmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen,
                uint8_t out[kSha256Len]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(info, key, keyLen, msg, msgLen, out);
}

void HkdfSha256(const uint8_t* ikm, size_t ikmLen, const uint8_t* salt, size_t saltLen,
                const uint8_t* info, size_t infoLen, uint8_t* out, size_t outLen) {
  // RFC5869：extract
  uint8_t prk[kSha256Len];
  uint8_t zeroSalt[kSha256Len];
  if (!salt || saltLen == 0) {
    secure::Wipe(zeroSalt, sizeof(zeroSalt));
    HmacSha256(zeroSalt, sizeof(zeroSalt), ikm, ikmLen, prk);
  } else {
    HmacSha256(salt, saltLen, ikm, ikmLen, prk);
  }
  // expand
  uint8_t t[kSha256Len];
  size_t tLen = 0;
  uint8_t counter = 1;
  size_t done = 0;
  while (done < outLen) {
    const mbedtls_md_info_t* infoMd = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, infoMd, 1);
    if (tLen) mbedtls_md_update(&ctx, t, tLen);
    if (infoLen) mbedtls_md_update(&ctx, info, infoLen);
    mbedtls_md_update(&ctx, &counter, 1);
    mbedtls_md_finish(&ctx, t);
    mbedtls_md_free(&ctx);
    tLen = kSha256Len;
    size_t n = outLen - done;
    if (n > kSha256Len) n = kSha256Len;
    memcpy(out + done, t, n);
    done += n;
    counter++;
  }
  secure::Wipe(prk, sizeof(prk));
  secure::Wipe(t, sizeof(t));
}

void Pbkdf2Sha256(const uint8_t* pw, size_t pwLen, const uint8_t* salt, size_t saltLen,
                  uint32_t iterations, uint8_t* out, size_t outLen) {
  uint32_t block = 1;
  size_t done = 0;
  uint8_t u[kSha256Len];
  uint8_t acc[kSha256Len];
  while (done < outLen) {
    uint8_t idx[4] = {static_cast<uint8_t>(block >> 24), static_cast<uint8_t>(block >> 16),
                      static_cast<uint8_t>(block >> 8), static_cast<uint8_t>(block)};
    // U1 = HMAC(pw, salt || INT_BE(block))
    uint8_t buf[64 + 4];
    size_t bufLen = 0;
    if (saltLen > 64) saltLen = 64;
    if (saltLen) {
      memcpy(buf, salt, saltLen);
      bufLen = saltLen;
    }
    memcpy(buf + bufLen, idx, 4);
    bufLen += 4;
    HmacSha256(pw, pwLen, buf, bufLen, u);
    secure::Wipe(buf, sizeof(buf));
    memcpy(acc, u, kSha256Len);
    for (uint32_t i = 1; i < iterations; ++i) {
      HmacSha256(pw, pwLen, u, kSha256Len, u);
      for (size_t j = 0; j < kSha256Len; ++j) acc[j] = static_cast<uint8_t>(acc[j] ^ u[j]);
    }
    size_t n = outLen - done;
    if (n > kSha256Len) n = kSha256Len;
    memcpy(out + done, acc, n);
    done += n;
    block++;
  }
  secure::Wipe(u, sizeof(u));
  secure::Wipe(acc, sizeof(acc));
}

size_t ToHex(const uint8_t* data, size_t len, char* out, size_t outCap) {
  static const char kHex[] = "0123456789abcdef";
  if (outCap < len * 2 + 1) return 0;
  for (size_t i = 0; i < len; ++i) {
    out[i * 2] = kHex[data[i] >> 4];
    out[i * 2 + 1] = kHex[data[i] & 0xF];
  }
  out[len * 2] = '\0';
  return len * 2;
}

bool FromHex(const char* hex, size_t hexLen, uint8_t* out, size_t outCap, size_t* outLen) {
  if (hexLen % 2 != 0) return false;
  size_t n = hexLen / 2;
  if (n > outCap) return false;
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < n; ++i) {
    int hi = nib(hex[i * 2]);
    int lo = nib(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  if (outLen) *outLen = n;
  return true;
}

}  // namespace digest
}  // namespace rockey