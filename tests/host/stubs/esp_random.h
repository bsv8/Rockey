#ifndef ROCKEY_STUB_ESP_RANDOM_H
#define ROCKEY_STUB_ESP_RANDOM_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
uint32_t esp_random(void);
void esp_fill_random(void* buf, size_t len);
#ifdef __cplusplus
}
#endif
#endif
