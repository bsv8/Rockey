// ESP-IDF AES-ECB 单块接口的最小替身，只为在主机上编译真实 aead.cpp。
// 语义与硬件无关：单块 AES-128/256 ECB，与 mbedtls AES 等价。
#ifndef ROCKEY_STUB_ESP_AES_H
#define ROCKEY_STUB_ESP_AES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { ESP_AES_128 = 0, ESP_AES_256 = 1 } esp_aes_type_t;
typedef enum { ESP_AES_ENCRYPT = 0, ESP_AES_DECRYPT = 1 } esp_aes_direction_t;

typedef struct {
  void* ctx;  // 主机侧指向 mbedtls_aes_context
} esp_aes_context;

int esp_aes_init(esp_aes_context* ctx);
int esp_aes_setkey(esp_aes_context* ctx, const uint8_t* key, int key_bits);
int esp_aes_crypt_ecb(esp_aes_context* ctx, esp_aes_direction_t dir, const uint8_t in[16],
                     uint8_t out[16]);
void esp_aes_free(esp_aes_context* ctx);

#ifdef __cplusplus
}
#endif

#endif
