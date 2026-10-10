// 主机侧的 ESP-IDF 替身：AES-ECB 单块与随机数。
// 单独成文件，既能配合 tests/host/host_shims.cpp 使用，也能被
// scripts/check_test_vectors.py 的自检驱动单独链接（那个驱动不需要
// keystore / secp 的替身）。
#include <stdint.h>
#include <stddef.h>

#include <mbedtls/aes.h>

#include "aes/esp_aes.h"

extern "C" {

int esp_aes_init(esp_aes_context* ctx) {
  ctx->ctx = new mbedtls_aes_context();
  mbedtls_aes_init(static_cast<mbedtls_aes_context*>(ctx->ctx));
  return 0;
}

int esp_aes_setkey(esp_aes_context* ctx, const uint8_t* key, int key_bits) {
  // mbedtls 的第三个参数单位是**比特**，与 ESP-IDF 的 key_bits 同单位。
  // aead.cpp 只用正向密码（CTR 模式的密钥流），所以统一走 setkey_enc。
  return mbedtls_aes_setkey_enc(static_cast<mbedtls_aes_context*>(ctx->ctx), key,
                                static_cast<unsigned int>(key_bits));
}

int esp_aes_crypt_ecb(esp_aes_context* ctx, esp_aes_direction_t dir, const uint8_t in[16],
                     uint8_t out[16]) {
  (void)dir;
  return mbedtls_aes_crypt_ecb(static_cast<mbedtls_aes_context*>(ctx->ctx), MBEDTLS_AES_ENCRYPT, in,
                               out);
}

void esp_aes_free(esp_aes_context* ctx) {
  mbedtls_aes_free(static_cast<mbedtls_aes_context*>(ctx->ctx));
  delete static_cast<mbedtls_aes_context*>(ctx->ctx);
  ctx->ctx = nullptr;
}

uint32_t esp_random(void) {
  static uint32_t s = 0x12345678u;
  s = s * 1103515245u + 12345u;
  return (s >> 8) ^ 0x5bf03635u;
}

void esp_fill_random(void* buf, size_t len) {
  uint8_t* p = static_cast<uint8_t*>(buf);
  for (size_t i = 0; i < len; ++i) p[i] = static_cast<uint8_t>(esp_random() >> 24);
}

}  // extern "C"
