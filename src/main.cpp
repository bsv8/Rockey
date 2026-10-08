#include <Arduino.h>

#include "core/app.h"
#include "core/log.h"

// Rockey 硬件 Vault 固件入口。
//
// 安全要点：
//  - 钱包固件不初始化 WiFi/BT；无线功能在首版完全关闭。
//  - 任何按键、主机或调试通道都不能提供 PIN，也不能读取私钥。
//  - 锁定/断电/重启后，私钥与派生材料都不再驻留内存。
static rockey::App g_app;

void setup() {
  g_app.Begin();
}

void loop() {
  g_app.Loop();
}
