#include "core/log.h"

#include <Arduino.h>
#include <stdarg.h>
#include <string.h>

namespace rockey {

uint32_t Log::dropped_ = 0;

bool Log::Enabled(LogLevel level) {
  return static_cast<int>(level) <= LOG_LEVEL;
}

void Log::Init() {
  dropped_ = 0;
}

Fingerprint Fingerprint::Of(const uint8_t* data, size_t len) {
  Fingerprint f;
  // FNV-1a 32bit，截取 16bit；只用于同一性比较，不是密码学用途。
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < len; ++i) {
    h ^= data[i];
    h *= 16777619u;
  }
  f.fp_ = static_cast<uint16_t>(h ^ (h >> 16));
  f.len_ = static_cast<uint8_t>(len > 255 ? 255 : len);
  return f;
}

void Fingerprint::Format(char* out, size_t outLen) const {
  if (outLen < 12) {
    if (outLen) out[0] = '\0';
    return;
  }
  static const char kHex[] = "0123456789abcdef";
  out[0] = 'f'; out[1] = 'p'; out[2] = '=';
  for (int i = 0; i < 4; ++i) {
    out[3 + i] = kHex[(fp_ >> (12 - 4 * i)) & 0xF];
  }
  out[7] = '/';
  out[8] = kHex[(len_ >> 4) & 0xF];
  out[9] = kHex[len_ & 0xF];
  out[10] = ' ';
  out[11] = '\0';
}

void Log::Write(LogLevel level, const char* tag, const char* fmt, ...) {
  if (!Enabled(level)) {
    dropped_++;
    return;
  }
  char line[200];
  int n = snprintf(line, sizeof(line), "[R] %s ", tag ? tag : "?");
  if (n < 0) return;
  if (static_cast<size_t>(n) < sizeof(line)) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line + n, sizeof(line) - static_cast<size_t>(n), fmt, ap);
    va_end(ap);
  }
  line[sizeof(line) - 1] = '\0';
  Serial.println(line);
}

}  // namespace rockey