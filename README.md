# Rockey

Rockey 是面向 Keymaster 的 ESP32 / M5Stack 实验硬件 Vault：设备独立解锁、解析请求并通过三实体按钮授权，浏览器负责联网和数据搬运。

当前状态：只有设计文档，硬件型号与部分参数待冻结，尚无固件实现或验收结果。

## 文档

- [需求](./docs/需求.md)：单 Key、迁移、白名单、长文阅读与三按钮 UX、多语言字体。
- [施工单](./docs/施工单.md)：平台选型、协议、固件、交互与联合验收的实施顺序。
- [Keymaster 互操作协议草案](./docs/Keymaster互操作协议草案.md)：跨项目共同语义、安全边界和冻结清单；尚非完整 wire 规范。
- [Keymaster 需求](../keymaster.cc/docs/proposals/rockey/Vault软硬件统一需求.md)与 [施工单](../keymaster.cc/docs/proposals/rockey/Vault软硬件统一施工单.md)：浏览器侧统一 Vault 与单 Key 生命周期改造。

跨仓库链接假定 Rockey 与 keymaster.cc 同级检出。Rockey 继承此前 LabVault 设计名称下的实验定位，不宣称专用安全芯片等级的物理防护。
