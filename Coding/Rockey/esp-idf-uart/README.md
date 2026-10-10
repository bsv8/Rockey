# 固定版 ESP-IDF UART IRAM 驱动

来源：ESP-IDF v4.4.7，Apache-2.0，URL 与原始/本地 SHA256 见 MANIFEST.json。

Arduino-ESP32 2.0.17 预编译 SDK 未启用 CONFIG_UART_ISR_IN_IRAM；其默认接收中断与 FIFO HAL 在 Flash。LittleFS 写入/擦除暂停 Flash 缓存时，中断不能及时搬运 CP2104 收到的字节，128-byte UART FIFO 可能溢出，协议随后丢帧/断链。8192-byte 软件环形缓冲不能修复中断暂停。

仅两项配置性修改：UART 驱动启用上游 IRAM 编译选项；HAL 的五个 FIFO 函数显式 IRAM_ATTR，替代完整 IDF 构建的 linker fragment。其余上游算法保持原样。pio_espidf_libs.py 将两个对象加入所有产品构建，先于框架静态库解析，Arduino Serial 接口不变。正式发布扫描确认中断及读写 FIFO 函数实际落入 IRAM。

不调整协议、心跳或批准策略，不加入流量重试或伪造成功。
