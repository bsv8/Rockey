# Rockey

统一维护：`./rockey list`、`./rockey flash xxx.bin`、`./rockey clear-data`。工具集中在 [`tools/`](tools/README.md)，发布固件按时间归档到 [`releases/`](releases/README.md)。刷机只写固件区，清空只写钱包区，两者操作前均自动备份。

Rockey 是面向 Keymaster 的 ESP32 / M5Stack 实验硬件 Vault：设备独立解锁、解析请求并通过三实体按钮授权，浏览器负责联网和数据搬运。

当前状态：**已有可编译的固件实现，但全部未经真机验证**，也没有任何 RK-01…RK-09 的验收证据。硬件型号与部分参数尚未冻结。按施工单口径，R2/R3/R4 仍不通过、R5-R8 未完成，逐条结论见 [施工单](./docs/施工单.md) 第 12 节，接口细节见 [冻结/](./docs/冻结/)。

> 密码学曾经出现过三处"实现完全错误但自检显示通过"（HKDF 忽略 PRK、RIPEMD-160 移位表错、AES-GCM 解密取错 GHASH 输入），因此本仓库的验证一律以**执行真实实现并与成熟实现逐字节对照**为准，不以固件内 `SelfTest()` 为准。

> 2026-10-09 当前边界：BSV/费用池及登记签名的基础核验与物理授权、PIN/密钥导入导出；信用/Markdown/业务解释由 Keymaster 承担。见 [共同需求](../VaultLinkProtocol/docs/密钥后端最小职责需求.md)。

## 文档

- [需求](./docs/需求.md)：单 Key、迁移、签名白名单、基础审核与三按钮 UX、多语言字体。
- [施工单](./docs/施工单.md)：平台选型、协议、固件、交互与联合验收的实施顺序与真实进度。
- [Keymaster 互操作协议草案](./docs/Keymaster互操作协议草案.md)：跨项目共同语义、安全边界和冻结清单；尚非完整 wire 规范。
- [冻结/线缆格式](./docs/冻结/线缆格式.md)：帧、握手、请求/响应字段表与确定性编码规则。历史设备线缆记录；新对接以 VLP 联合冻结版本为准。
- [冻结/构建配置矩阵](./docs/冻结/构建配置矩阵.md)：LANG / FONT_PROFILE / GLYPH_SET 与环境矩阵。
- [冻结/硬件清单](./docs/冻结/硬件清单.md)：固件当前假定的硬件参数，**尚未真机确认**；并如实记录安全熔丝未启用。
- [冻结/密钥封装](./docs/冻结/密钥封装.md)：封装格式 v1、失败等待机制。
- [Keymaster 需求](../keymaster.cc/docs/proposals/rockey/Vault软硬件统一需求.md)与 [施工单](../keymaster.cc/docs/proposals/rockey/Vault软硬件统一施工单.md)：浏览器侧统一 Vault 与单 Key 生命周期改造。

跨仓库链接假定 Rockey 与 keymaster.cc 同级检出。Rockey 继承此前 LabVault 设计名称下的实验定位，不宣称专用安全芯片等级的物理防护。

## 验证

不需要 ESP32 工具链，在任何装了 C++17 编译器的机器上都能跑：

```sh
tools/build/main.sh --check-only
```

依次执行：

| 检查 | 内容 |
| --- | --- |
| `tools/syntax/main.sh` | 对 `src/` 做 `-fsyntax-only`；本机有 mbedTLS 时覆盖 27/28 个实现文件。 |
| `tests/host/` | 编译 `src/` 里的**真实实现**运行回归断言：CBOR/帧、AES-GCM 对照 mbedTLS、HKDF 对照 RFC 5869 与 mbedTLS、X25519 对照 RFC 7748、交易序列化与 sighash 预映像、地址向量、授权撤销与限额、本地秘密往返、64 位金额格式化、密钥封装/换 PIN/失败等待、已撤销与未冻结入口的拒绝行为。 |
| `tools/wire-encoding/main.py` | 字段名长度守卫、CBOR 键序、`BeginMap` 计数。 |
| `tools/i18n/main.py` | 文案完整性。 |
| `tools/test-vectors/main.py` | X25519 / AES-GCM / RIPEMD-160 / 本地秘密 v3。RIPEMD 与 AES-GCM 两节会**编译并执行**固件代码后比对；其余目前只比对常量，覆盖不足处已在输出中注明。 |

构建固件另需 PlatformIO：`tools/build/main.sh [环境...] [--all] [--upload <环境>]`。

## 2026-10-10：三按钮改 PIN 与主菜单滚动

设备主菜单增加“更改密码”。进入时关闭 VLP、撤销持续决定并锁定，依次输入当前 PIN、新 PIN、再次确认；等待设置期间 Key 保持锁定，不接受 USB 业务请求。完成、取消或不一致时清零输入缓冲，回到锁定页，需用当前有效 PIN 重新解锁。新 PIN 写入仍走原子封装记录，不改变公钥或支付账本。

底层 ChangePin 的旧 PIN 校验改用统一 Unlock 门禁，错误旧 PIN 现在记持久失败次数、进入等待并清除 RAM Key，不再绕开失败保护；非法新 PIN 提交前拒绝。主机 keystore 41 条断言通过，包括错误旧 PIN、失败等待、锁定后不能继续改 PIN、旧封装仍可解锁、改 PIN 后仅新 PIN 有效。它验证真实密码学/KeyStore 逻辑，宿主 LittleFS/时钟为明确的测试适配，不代表实体 Flash 掉电或按钮验收。

主菜单容量为 9 项，显示窗口随当前选中项滚动；原仅显示前 6 项导致擦除不可见的问题一并修复。构建支持 ROCKEY_BUILD_JOBS（默认 2），可降低并行度；此前系统临时空间不足的失败不算发布验证通过。

Keymaster 已增加首次硬件绑定、公开记录原子初始化和实际操作状态顶栏，不新增 RocKey 信用查询/Markdown 或 USB 握手消息。迁移、Channel 兼容、BitFS 卖方开池预签和真设备验收仍未完成。
