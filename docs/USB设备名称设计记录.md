# USB 设备名称设计记录

> 2026-10-11 用户决定：改名超出固件边界，不再管理 USB 桥名称。此项关闭，不进行 OTP 检查或写入，以下内容仅保留调研记录。

2026-10-11 用户希望连接选择器显示 `RocKey 1 [本机序号]`。

只读枚举当前设备：CP2104，产品字符串 `CP2104 USB to UART Bridge Controller`，序列号 `02010546`，VID/PID `10c4:ea60`。拟用名称 `RocKey 1 [02010546]`，保留原序列号及 VID/PID，避免改变当前驱动和端口识别约定。该序号是 USB 桥标识，不是钱包公钥，也不用于身份认证。

浏览器系统选择器读取系统枚举的 USB 信息，ESP32 钱包固件不能替 USB 桥更改产品描述。CP2104 支持通过专用配置工具定制产品描述，但它采用 OTP；必须先核实芯片是否尚可编程、板上 VPP 所需电容及供电条件，然后提供具体写入配置供用户确认。当前仅完成只读识别和设计，没有向芯片写入。名称修改也不保证所有浏览器的附加端口文字完全一致。

依据：[Silicon Labs CP2104 数据手册 §8](https://www.silabs.com/documents/public/data-sheets/cp2104.pdf)、[AN721 配置指南](https://www.silabs.com/documents/public/application-notes/AN721.pdf)。
