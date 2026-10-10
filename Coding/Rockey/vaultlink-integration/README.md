# RocKey VLP 产品适配

> 2026-10-10 最终施工记录：[三项目施工验收](../../../../BSV8_VaultLinkProtocol/reports/2026-10-10-三项目施工验收.md)。同 Key 双向迁移及恢复、三按钮导入 PIN、有限安全归档、普通未签名预览/显式预签已完成代码施工；旧“继续施工/不支持”条目保留为历史。实体 USB、按键和 Flash 掉电另行验收，不能用宿主测试代替。本期不做信用信息。


> 当前支持及验收边界见本文末尾“受限签名收口与迁移账本转换”；前面的增量条目保留历史状态。

2026-10-09，施工中。App 解锁后由 Controller 独占 USB Serial 接收，使用实际 VLP wire 2 Endpoint，不降级接收旧 wire。长期 Key 仍由现有三按钮 PIN/KeyStore 管理；解锁时才创建 IdentityKey，临时私钥副本擦除，锁定/断链清 Key 并关闭业务会话。

PaymentService 支持 `payment.configure`、`payment.session-open`、`payment.channel-read`、`payment.session-read`、`tx.p2pkh-payment`，声明 Draft 能力 0x223。配置支持 main/p2pkh、feepool.connect、feepool.bitfs；配置及新建 App 会话要求物理确认。设备从实际交易与完整前序证据核算支出、找零及费用，按实际脚本生成审核地址。额度内自动执行；超额批准/拒绝，当前会话增额不改未来默认。策略落盘使用真实 `/vault/vlp-policy.bin` 原子记录；擦除钱包同时移除该账本。

Controller 的 A/C 滚动，A 长按拒绝，读到末尾并释放旧按键后 B 长按批准。累计超额时 B 短按切换增额，A/C 调节额度，不得低于本次后累计；最终长按批准。配对也使用异步物理确认，USB 心跳不被屏幕等待阻塞。固定说明有 en/zh-Hans/zh-Hant/zh-Hk/ja 翻译，按选定语言生成字体。本轮只构建 en 和 zh-Hans。

## 真实构建

使用安装 PlatformIO 6.2.0、Pillow 12.3.0 的 Python，espressif32 6.12.0 / Arduino 2.0.17，TFT_eSPI 2.5.43：

```sh
ROCKEY_PYTHON=/path/to/venv/bin/python \
ROCKEY_NM=/path/to/xtensa-esp32-elf-nm \
scripts/build.sh m5stack-core-en m5stack-core-zh-hans
```

构建脚本按语言生成现有固定开源字体、运行主机门禁、编译真实固件并扫描发布 ELF。修复了旧入口未定义 Python PlatformIO 包装函数的问题；不再硬编码某台机器的工具目录。ESP32 框架缺失的 HKDF/RIPEMD160 模块来自 `Coding/Rockey/mbedtls-extra` 固定上游源码，含许可证和文件 hash。

上一轮两种固件构建及发布扫描均通过，构建 ID `20261009T152639Z-0156bb1`：

| 环境 | RAM | Flash | 产物 |
| --- | ---: | ---: | --- |
| m5stack-core-en | 95592 / 327680 | 573113 / 1703936 | `.pio/build/m5stack-core-en/firmware.bin` |
| m5stack-core-zh-hans | 95592 / 327680 | 658633 / 1703936 | `.pio/build/m5stack-core-zh-hans/firmware.bin` |

主机语法检查 27 项通过，原有密码/编码/交易/PIN 等真实实现测试合计 1489 项通过。与 Keymaster SDK 的 C++ 产品服务加密互通、实际签名验签及额度行为已通过 ASAN/UBSAN 宿主测试。`tests/native.cpp` 的公开测试 Key 和批准适配仅在主机测试使用，未编入固件；不能把它称为实体按钮验收。

尚未刷机或验收物理 USB/按钮。新 wire 两种费用池见下节；Channel、本地秘密和迁移未支持；旧菜单或旧实现存在不表示新协议可用。主机绑定/迁移及消息/持久容量限制见 Keymaster 同名目录记录。LittleFS 原子记录/CRC 是落盘及误码保护，不能宣称拥有硬件抗回滚证明。


## 2026-10-10 费用池施工

新增 tx.feepool-connect、tx.feepool-bitfs 与 payment.pool-read。当前硬件角色分别为 Connect client 和 BitFS buyer；fund/state 独立解释实际脚本、完整交易证据、参与方、锁定金额、累计/新增付款、找零和矿工费。固定字段在五种已有语言都有译文，仍按所选语言生成字库。

池基线与额度预占一起落盘；同池并发、过期基线、累计回滚、错误脚本/公钥/前序拒绝。已签/未知额度及池基线不释放；零增量关池不重复计额。旧 version 1 政策升级为 2，保留用户配置及账本记录。App 默认会话总额的更改同步 owner 下各 App 渠道，但不修改当前会话限额/used。

Keymaster 宿主互通使用正式 C++ PaymentService/Endpoint/mbedTLS、实际完整签名 FundingTx 和真实磁盘记录，验证两类交易新增量与结果验签，不是设备按钮证明。896 字节消息及有界持久容量仍会拒绝超限；没有偷偷扩帧或删除重放记录。卖方/仲裁角色与其他脚本尚未支持。


本轮验证：VLP 35/35（另执行扩展后的 C++ version 1 升级/池账本实测）、产品集成 6/6、相关回归 32 文件/398 用例；类型、107 个契约结构/73 用例、306 模块 Worker 边界通过。Keymaster 生产构建通过（仍有既有大 chunk 提示）。RocKey 英文/简体中文固件构建及发布 ELF 扫描通过，最新构建 ID `20261009T170639Z-0156bb1`。未刷机，未宣称物理 USB/按钮验收。


## 2026-10-10 标准交易、分片与会话取消增量

已实施：VLP 标准单钥脚本解析及 TS/C++ 固定 0x41 签名；Keymaster protocol spend 的手续费迭代不签名，稳定交易由唯一额度核心签署，输入在等待批准前领取 claim；BitFS 通用 FundingTx 支持单池输出。加入 32 KiB 有界认证分片（原帧/密码不变）、消息串行发送和帧类型绑定。产品能力为 Draft 0x224。

软件 App 关闭请求页立即撤销未执行申请与待批准，恢复同一连接保留累计额度。Window/Worker MessagePort USB 字节桥已实现并在实际 C++ Endpoint 互通中使用；它尚未装配到 Keymaster 钱包生命周期和设置界面，不等同于产品硬件绑定已完成。

BitFS 卖方 Kind 2 先预签、Kind 4 才收完整资金原文。已撤回错误复用付款方前序路径的生产接线，现有软件卖方流程保留。后续必须补可核验的开池预签 Profile 和实际阶段联测，不能开放硬件任意摘要作为替代。迁移、Channel/本地秘密、其它资金入口、安全归档及真机验收继续保留未完成状态。

验证：VLP 38/38；产品 SDK/C++ 与软件核心集成 6/6；Keymaster 53 文件/504 业务用例通过；类型、107 契约结构、73 契约用例、310 模块 Worker 边界及自检通过。以上是主机验证，不是浏览器 USB、实体按键或掉电验收。

追加验证：支付核心在预占后、签名开始前同步检查取消，确定未签的失败释放预占并保留不可复用墓碑；已经进入私钥运算的失败仍保留未知额度。实际交易、真实签名和磁盘账本测试通过，产品集成更新为 7/7。软件超额 UI 真 Worker 检查 1/1 通过。RocKey 英文/简体中文发布固件与 ELF 扫描通过，构建 ID `20261009T175300Z-0156bb1`；没有刷机或真实资金广播。SDK 两份 vendor 文件与 manifest 哈希逐一一致。


## 2026-10-10 本地秘密兼容施工

硬件绑定检查确认：钱包恢复数据需要 v3 LocalSecret。已按冻结配方增加正式 C++ 封装/解封、SDK 严格范围/信封校验、Keymaster 硬件代理以及 RocKey 实体审核，产品 Draft 能力 0x225。HKDF 和长期派生密钥保留在设备内；秘密正文不进入设备审核页。支持明文 1..512 字节、scope 1..95 UTF-8 字节。大信封仍走既有有界加密分片。

秘密缓冲处理包括：原私钥/HKDF 临时材料清理；C++ 协议值替换、销毁和连接关闭清理；完整请求编码、分片编码、解密记录清理；取消连接世代后，硬件代理不交付迟到解封明文。JavaScript 清理是应用层缓冲处理，不宣称消除运行时/系统内存副本。

验证直接使用 Keymaster 现有 WorkerKeySession 与 VaultOperationExecutor 产生旧 v3 密文，实际 C++ 实现可解封；C++ 封装结果也可由现有软件解封，覆盖 1/32/512 字节。换 Key、换 scope、锁定、篡改、超长和非法范围均拒绝。正式 C++ Endpoint 与硬件代理通过加密字节桥执行 512 字节往返及错误后再次正常解封。确认来源为宿主测试 ApprovalUI，不是实体按键验收。

当前仅本次实体确认。持续许可/否决及撤销、硬件公开钱包记录、解锁与唯一桥的生命周期装配、同 Key 双向迁移仍未完成；本次不是完整硬件钱包交付，也没有刷机、熔丝或资金广播。

本增量验证记录：VLP 39/39；正式产品 SDK/C++ Endpoint 集成 7/7；旧软件与 C++ 密文双向兼容及原有 Worker 核心回归 3 文件/6 用例通过；类型、107 契约结构、73 契约用例、311 模块 Worker 边界与自检通过。RocKey 英文/简体中文发布固件和 ELF 扫描通过，构建 ID `20261009T181326Z-0156bb1`。两端 SDK vendor manifest 哈希逐项一致。没有真实 USB/按键或掉电验收。


## 2026-10-10 本地秘密持续决定与设备撤销菜单

已实施：新协议 PaymentService 的本次允许/否决、当前 USB 连接内持续允许/持续否决、精确操作+scope 匹配、修订撤权栅栏；ScopeGrants 为有界易失状态，容量 8，与原设备菜单容量一致，不自动淘汰持续否决。断链清空、旧准备请求失效；付款渠道/会话账本不因这些操作清空。产品能力更新为 Draft 0x226，请求结构和承诺保持不变，主机没有设置持续决定的接口。

三按钮：基础内容读完后短按 B 切换本次/会话，长按 B 同意，长按 A 否决。原“会话决定”菜单已改读新协议授权，完整显示一项的操作、允许/否决及范围；A/C 前后项，B 短按撤当前、长按撤全部，A 长按返回。共享 UTF-8 安全分行，避免截断字符或用截短标签识别待撤权限。软件本地秘密仍由已解锁 Worker 直接执行，没有增加软件确认窗。

验证：正式产品 PaymentService、真实密码、磁盘 Store 的持续决定测试通过，包括本次不持久、跨操作不共用、持续否决不重复弹出、两种决定撤销后重新询问、撤销使旧请求失效、满额不淘汰、断链清空和 UTF-8 完整性。Keymaster 产品集成更新为 8/8；现有软件/C++ v3 密文兼容测试仍通过；类型、107 契约结构、73 契约用例及 311 模块 Worker 边界与自检通过。生产构建通过。RocKey 英文/简体中文固件与发布 ELF 扫描通过，构建 ID `20261009T182700Z-0156bb1`。

宿主测试的决定来自明确标记的 HostDecision 输入适配，不冒充实体按钮。尚未做真 USB/按键/掉电验收，也未刷机或广播真实资金。硬件公开钱包记录、解锁/USB 生命周期装配、同 Key 双向迁移和其它原施工项仍未完成，不勾整项通过。


## 2026-10-10：硬件业务会话、设备额度与无签名转账预览

已接通正式 Coordinator 的硬件业务解锁：设备 PIN 本地解锁、USB 双端配对和预期公钥持有权证明通过后，再核对当前记录/Root/身份世代并建立新业务 epoch。Worker 不装入硬件私钥。断开真实设备字节流、页面撤权、全局锁或 Root 撤权均锁定钱包；登录组件因成功解锁而卸载不会关闭属于 Window 的串口租约，Window pagehide 和 Worker close 负责释放。

新增 HardwareWalletPayments，与软件 WalletPayments 使用同一注册、配置、会话和整笔签名命令。硬件渠道/累计预算以设备账本为唯一权威，渠道列表来自设备，不复制一份浏览器 used 或以主机 withinLimit 放行；额度内无确认，超额仅设备实体批准，网页 answer 明确拒绝。当前 Key 设置页复用同一渠道设置 UI，硬件的 PIN/备份管理指向设备，隐藏软件改密/KeyHold 导出。公开地址派生和 v3 本地秘密已接入硬件会话；无语义 Profile 的通用摘要签名仍拒绝。

App 会话和 USB 会话解耦。TS/C++ 账本重载保留 active/closed、limit、used，reserved 仍转 unknown。重复 open 同 active/owner 复用原预算；指定 close 幂等撤权并保留金额/墓碑，不能复活。取消使用实际 submit ID/承诺绕过设备确认队列；前序读取中的申请和排队申请一并撤权。Coordinator 付款控制面独立于普通 FIFO，避免批准或取消被业务请求堵住。产品 Draft 更新为 0x227，新增 channel-list/session-close，完整数据结构见 VLP spec/v2/02。

普通 P2PKH prepare 只构造未签名交易、用解锁脚本长度上界估费，txid 为空，不注册渠道、不签名、不占消费额度。submit 重查当前 UTXO 与 owner、核对有期限的内存票据及全部 DTO 后，才注册渠道/取得完整前序/请求签名一次，生成真实 txid 并写入广播审计。修改收款/金额/渠道、重复提交、过期或取消不会沿用旧预览签署。中心重试使用实际已签提交结果作为前序，保留 signed/unknown 占用。

验证：81 文件 / 993 用例回归通过，产品 SDK/真实 C++ 协议集成 10/10，VLP 39/39，类型、107 契约结构、73 契约用例、315 Worker 模块边界及自检通过，Keymaster 生产构建通过。RocKey 1489 项宿主检查及英文/简体中文发布固件、ELF 扫描通过，构建 ID 20261010T014114Z-0156bb1。C++ 按钮决定来自明确宿主 ApprovalUI，不算实体 USB/按键/断电验收；未刷机或广播资金。

剩余工序仍未完成：硬件新建绑定向导、同 Key 双向迁移及 journal/预算转移、Connect/Channel 语义签名与消息解封、BitFS 卖方开池预签、安全归档和真实浏览器/设备门禁。发现旧软件 payments.json 时当前硬件启用明确拒绝 hardware-policy-migration-required，不能以空硬件预算冒充迁移成功。原施工单的整项复选框继续保留未完成，不将这些能力标为完整产品交付。

后续状态（2026-10-10）：Keymaster 首次硬件绑定和 App 硬件认证已接通。Connect SDK 显式注册渠道、付款携带 channelId；真实 Coordinator/C++ 测试验证两渠道共享一次 App 连接的总额，重复打开同一会话不重置已用金额。未新增 USB PIN/信用服务接口。五语言发布构建、ELF 扫描及逐语言二进制/字体清单归档通过，构建 ID 20261010T030909Z-0156bb1，详细证据与尚未完成项见 `docs/施工单.md`。浏览器宿主/实体设备验收须分别记录。

## 2026-10-10：受限签名收口与迁移账本转换（阶段记录）

本节是截至本次施工的当前状态；前面各日期/增量记录保留为历史证据，不把旧的“尚未支持”作为当前支持清单。

| 范围 | 当前代码及验证 |
|---|---|
| Connect 身份/意图 | exact Connect v1 CBOR 信封；公钥、内容摘要、规范编码核验；设备本次物理决定，返回严格 low-S DER，主机验证后转换为 compact；无通用摘要回退 |
| Channel | 实际 SDK 0.6.0 public/hash/private、seal/open 双向兼容；有界 JCS 与固定域分隔；设备 ECDH/HKDF/AES-GCM；按操作/对方/协议持续许可、否决、撤销与断线失效 |
| BitFS 消息 | exact wire 文档 kinds 1/6/8/9/10/11；设备重建原业务域摘要并解释基础字段；Kind 5 不得绕过金额核心 |
| BitFS Kind 5 付款授权 | 完整 funding、退款及未签付款原文核验，先按累计增量占用额度再签署；随后 Kind 7 同一付款不重复计额；未知结果保留占用 |
| BitFS 卖方开池 | Kind 2→3 的独立 bsv-feepool-bitfs-opening；按实际 v4 规范退款和费率推导池金额，核验买方 low-S DER || 0x41；未收到 Kind 4 时不伪造前序交易；后续协签读取真实日志 funding |
| 网络身份 | 设备重建 Noise 固定域或自己的无地址 Peer Record，覆盖 uint64 序列号；主机仍执行 executor 租约/世代/单调性校验；无任意签名、PeerId 或地址输入 |
| 迁移账本基础 | encode/decodePaymentPolicy 使用实际 C++ v2 bank，完整保留 uint64、关闭会话、已消费及未知付款、池基线、修订；同 Key 和容量/支持检查，不授予导入/清空账本权限 |

当前产品声明 wire 2 / SDK 0.2.0-draft.1 / Draft 0x22d。0x228 是 Connect；0x229 是 Channel；0x22a 是 BitFS 文档；0x22b 纳入 Kind 5 金额；0x22c 是网络身份；0x22d 是卖方开池预签。具体规范见 VLP spec/v2/04..07，握手及三消息不变。

本次验证：VLP SDK 52/52（包含实际 C++ Policy、磁盘账本与 ASAN/UBSAN）；Keymaster SDK/实际 RocKey C++ 宿主互通 12/12；Connect/Channel/BitFS/网络签名与原 SDK 独立验签，双向 Channel 封装；相关软件/买方状态/卖方协议/契约回归 5 文件 42 用例。类型、107 契约结构、73 契约用例和 324 个 Worker 模块边界/自检通过。插件依赖索引按真实当前源码重新生成，743 调用点。

RocKey 最新五语言发布构建 ID 20261010T064015Z-0156bb1，en/zh-Hans/zh-Hant/zh-Hk/ja 全部编译及 ELF 扫描通过；248 条译文齐全。逐语言 firmware.elf、firmware.bin、font-MANIFEST.md 已归档在 .pio/releases/<build-id>/<env>。构建后默认简体中文字体重新生成，462 字形、位图 64774 字节。两端 SDK vendor 全部文件哈希逐项核验，sourceOverrides 明确标注未提交工作区增量，不冒称基准提交已有这些代码。

未完成部分仍明确保留：同 Key 双向私钥迁移及设备重新 PIN、导入/主动导出、迁移 journal、崩溃恢复和真正预算转移；安全归档/回收；Keymaster 信用服务的实际来源配置与接入；真实浏览器/USB、实体按钮/PIN、重启及掉电验收。账本转换和仓储 CAS 是迁移基础，不能据此把 K5/R4 或完整迁移勾成完成。账本满额仍 fail closed，不能删签名/未知付款、关闭会话或池基线来清空额度。信用查询/Markdown 继续只归 Keymaster，不新增设备信用业务。

宿主 C++ 审核决定由明确标记的 HostApproval/UI 适配提供，不能算实体按钮通过。当前机器只发现 Bluetooth/debug/wlan 串口，未发现 M5Stack；未刷机、熔丝或广播真实资金。迁移仍显式不支持，硬件启用发现软件旧 payments.json 时拒绝，不能以空设备预算代替迁移。

## 2026-10-10：迁移恢复存储与设备持久记录修复（阶段记录）

本节优先于前面的历史施工记录。信用信息接入已由用户取消本期施工：不需要信用服务器地址或接口联调；软件 Vault、RocKey、VLP 均无信用信息功能。取消不计实现通过，也不列作待完成阻断。

- [x] Worker 内部迁移 journal：固定私有路径，严格公开字段与阶段；绑定 Key/meta/付款账本 revision 和规范 bank hash，不包含密码、PIN、私钥或旧 KeyHold 副本。普通插件和 Connect 无访问端口。
- [x] 浏览器迁移提交基础：同一 IndexedDB 事务写目标 key.json、实际付款账本及 local-committed journal，条件比较源记录和 journal；并发只允许一个成功，联系人等业务数据保持。真实仓储解析拒绝不同公钥或钱包世代。
- [x] 冷启动门禁：未完成/损坏 journal 禁止普通解锁和新建；已完成 journal 必须与当前钱包世代、公钥及后端一致。不能本地删除 journal 就重新启用旧后端。
- [x] 公开 bank 与重连继续性核验：Draft 0x22e / payment.policy-export，以 1–8192 字节分块读取最大 65536 字节 bank；整次读取拥有业务 FIFO，完整 SHA-256/规范 CBOR/公钥校验。迁入后普通重连只接受 completed 同 Key journal 和精确浏览器基线，设备当前 bank 必须保留已消费/未知付款、关闭会话和池累计；不得以空 bank 重置预算。
- [x] SDK 响应处理：业务结果允许有界大消息；超出查询包容量的结果保留完成水位但不复制进 query，设备支持单次敏感结果不进入重放缓存并清理秘密缓冲。这不是设备私钥导出能力声明。
- [x] RocKey 持久记录：通过流式 CRC 校验整个旧记录，修复旧 1KB scratch 导致大付款 bank 世代从 1 重新开始的问题；最大 64KB、世代溢出和路径截断均明确拒绝，已有但损坏的文件不能被普通写入当成新文件覆盖。
- [x] RocKey PIN/擦除错误处理：重新解锁先清旧 RAM Key；损坏 PIN 计数不恢复零次状态，持久更新失败不报告成功解锁；损坏密钥仍占用原身份，禁止新 Key 覆盖；设备保护秘密使用自动清零缓冲。擦除检查 live/tmp 删除、保护秘密轮换及状态写入，失败不能进入新建或返回成功。
- [x] 硬迁软后的删除规则已冻结：浏览器原子保存新软件密码 KeyHold/付款账本成功后，用户在硬件上独立确认擦除旧私钥；得到可恢复核对的擦除结果后才结束迁移。此项只确认规则，不代表设备流程完成。

验证：Keymaster 完整回归 312 文件 / 2699 用例通过；类型、743 调用点、107 契约结构、73 契约用例、326 Worker 模块边界及自检通过，生产构建和 10 个 HTML/JS/CSS 产物扫描通过。VLP SDK 54/54；现有真实 SDK/RocKey C++ 产品互通 12/12。新增 journal 用例使用实际 IndexedDB 仓储和真实密码封装，覆盖重启、并发 CAS、源记录变化、同 Key 迁回新密码及错误设备 bank；不假称真实设备已经导入/导出私钥。

RocKey 宿主检查 1519 项通过，包含 64KB 账本递增世代、流式 CRC、损坏记录不覆盖、世代耗尽和损坏 PIN/Key 拒绝。该检查运行真实固件源实现，LittleFS 使用已标明的宿主适配，不替代 Flash 掉电测试。五语言发布构建 ID `20261010T094935Z-0156bb1`：en/zh-Hans/zh-Hant/zh-Hk/ja 全部构建与 ELF 扫描通过，逐语言产物和字体 MANIFEST 已归档；未刷机。两端 vendor 的 50/42 个文件哈希全部核验，生产文件与同源 SDK 一致；消费方 package.json 和未提交 sourceOverrides 明确标记。

仍未完成：设备同 Key 私钥导入/主动导出、重新 PIN、浏览器/设备跨提交点恢复与实际迁移向导；有界账本的安全归档回收；Connect 费用池 ProtocolSpend prepare 因下一阶段依赖已签 funding txid，仍需完成预签与普通无签名预览的施工收口；真实浏览器 USB、实体三按钮/PIN、重启和 Flash 掉电验收。host journal/账本转换已完成其基础部分，不能据此勾选 K5/R4 整项或宣称完整软硬替代。当前私钥迁移仍显式不支持，普通业务不开放私钥导出，满账本继续明确拒绝而不删除预算或付款墓碑。


## 2026-10-10：硬迁软、独立擦除与回执恢复（阶段进度，已由最终记录更新）

本节替代此前“所有私钥迁移显式不支持”的阶段状态，只收口已有同 Key 迁移需求；不新增信用查询或业务解释功能。

- [x] VLP 设备公开 journal：SDK TS/C++ 严格九字段、规范 CBOR、同绑定及线性阶段校验；真实记录持久化。Draft 0x22f / migration.status 只读公开状态，不授予密钥操作。
- [x] RocKey 主动导出与重新 PIN：本机菜单开启导出；A/C 选择数字、B 输入、长按 B 删除、长按 A 拒绝。复用 KeyStore 真实失败计数与等待；PIN 输入清零，成功后重新松键、读完摘要/风险、长按仅本次确认。持续许可和浏览器字段均不能代替。
- [x] Draft 0x230：migration.export 输出前持久化 device-committed；私钥经原加密 USB 仅传一次，query/replay 只保留完成状态。Worker 实际派生核对公钥，生成并解密回读验证新密码 KeyHold。源私钥、回读副本及异常路径缓冲清零。
- [x] Keymaster 硬迁软主流程：Worker 钱包迁移门禁排空已有 I/O，阻断新业务读写/签名；同一 IndexedDB 事务写目标 KeyHold、完整真实额度 bank 和 local-committed journal，保留身份世代、公钥、联系人、消息和其余业务记录。Window/插件只取得公开 DTO。
- [x] 独立硬件擦除：浏览器真实提交后发送公开 host-commit，不能由此自动擦除。设备再一次 PIN 与实体仅本次确认，先记录 erasing，再执行真实清理并清除 KeyStore/运行时两份 RAM 私钥，最后记录 erased。只有匹配浏览器提交的擦除回执才完成 journal；钱包锁定后用新密码解锁。
- [x] 旧 Key 仍在的恢复：专用连接重新验证同一原 Key，核对原 journal；prepared/device-committed 仍需本机重新开启导出、重新 PIN。local-committed 只继续原目标的确认/擦除，不重新封装或改写目标。恢复期间没有普通业务解锁。
- [x] 已无旧 Key 的回执恢复：Draft 0x231 使用 RAM 临时身份和实体配对，只核对浏览器已经原子提交的同一 journal/KeyHold/bank。临时公钥不写钱包记录、不冒充旧私钥持有权。设备只开放 status、recover-erased、complete；普通签名明确拒绝。erasing 的剩余清理需独立实体确认，存在任何 Key 文件时绝不走此入口；已持久化 erased 只核对回执。
- [x] 产品 UI：Key 管理页“迁回软件钱包”收集新密码；存储阻断页通过 Vault 私有恢复组件继续同一迁移，可明确选择“设备已擦除，仅恢复回执”。配对、PIN、导出与擦除决定保留在设备。设备保留公开回执；确认浏览器完成后，用户才能独立长按重置设备，USB 不自动创建新身份。
- [x] SDK 清理：关闭期间晚返回的一次性结果、无等待方/绑定不合法的 decoded 回复清零；通用 query 无再次获取私钥的路径。Consumer 固定 SDK 包及 manifest 同步真实文件 SHA-256，并明确登记未提交源覆盖，不伪装已发布版本。

本阶段证据：SDK 57/57；产品原生加密互通 14/14；Keymaster 全量 315 文件 / 2713 用例；类型、744 调用点依赖、107 契约、74 契约测试及 331 Worker 模块边界通过；生产构建及 10 个产物扫描通过。RocKey 主机 1564 项检查通过，五语言发布构建及 ELF 门禁全部通过，Build ID `20261010T113241Z-0156bb1`。

测试执行真实生产协议、KeyStore/PIN 状态机、密码学、KeyHold、账本和事务代码。Node IndexedDB 介质、HOST LittleFS、按钮/配对决定均为明确命名的测试环境适配；erasing/erased 恢复测试明确使用提交点夹具，不冒充之前已经发生过的实体会话或 Flash 断电。当前串口只有 Bluetooth/debug/wlan，未连接 M5Stack；没有刷机、熔丝或真实资金广播，实体验收没有勾选。

剩余施工继续按原边界：软件同 Key 迁入新设备的私有 provisioner、设备进口 PIN/导入阶段恢复与产品向导；有界账本的安全归档回收；Connect ProtocolSpend prepare 的费用池阶段/预签收口；真实浏览器 USB、实体三按钮/PIN、重启和 Flash 掉电验收。migration.import 仍明确不支持，满账本继续 fail closed，不删除未知/已消费资金或防重放证据。K5/R4 整项及完整软硬替代不据此标记完成。信用信息本期完全不实施，也不作为交付阻断。

### 软件迁入施工细化（2026-10-10，沿用既定需求）

- 空设备在本机重复设置 PIN 后选择新建或导入；PIN 仅留在设备 RAM。
- 只提供临时加密配对与迁移端点，不将临时公钥作为钱包身份。账本分块原子暂存，完整哈希、规范格式和容量检查通过后才能确认导入。
- 导入必须重新输入本机 PIN、读完并实体长按确认。按账本落盘、设备 PIN 封装验证、设备提交记录的顺序施工。
- 浏览器验证实际导入私钥的挑战签名，再原子替换同身份的后端、账本和迁移记录。断线只恢复同一迁移，不自动创建新身份，不保留软件密码封装。
- 有 Key 的设备走原 PIN 解锁后的迁移证明；无 Key 的暂存恢复重新在本机设置 PIN，不能通过主机提供 PIN。

2026-10-11 Git 归档：VLP SDK 已提交为 `e15c9d061dd3d379167941590b67a4e8439d49f3`。本项目消费清单的 sourceCommit 已固定到该提交，移除此前未提交增量的 sourceOverrides；逐文件校验仍全部通过。上文未提交状态为对应日期的施工历史。
