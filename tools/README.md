# RocKey 工具目录

每个工具一个目录，Python 入口为 `main.py`，Shell 入口为 `main.sh`；资源与依赖随工具放置。原 `scripts/` 已合并到这里，不保留旧入口。

| 目录 | 职责 |
| --- | --- |
| `rockey/` | 列设备、刷固件、清空钱包数据、产品归档 |
| `build/` | 主机门禁、字体、发布构建、归档及部署 |
| `host-tests/` | 真实产品代码的主机回归 |
| `syntax/` | C++ 语法检查 |
| `wire-encoding/` | 协议编码检查 |
| `test-vectors/` | 密码学向量检查 |
| `i18n/` | 多语言文案检查 |
| `release-check/` | 发布 ELF 扫描 |
| `espidf-libs/` | PlatformIO 构建钩子 |
| `fonts/` | 字库生成；`sources/` 保存字体、许可证与清单 |

项目根目录统一维护命令：

```sh
./rockey list
./rockey products
./rockey flash /完整路径/xxx.bin
./rockey flash /完整路径/xxx.bin --port /dev/cu.usbserial-设备号
./rockey clear-data
```

`list` 列出 CP2104 钱包候选设备，不读取私钥，也不将 USB 序号当作钱包公钥。多台设备必须指定 `--port`。

`flash` 检查固件和归档 SHA256、备份启动/分区/NVS 和钱包区、验证设备分区表，只写 app0 `0x10000`。esptool 验证写入哈希后重启，不更新 Bootloader、分区表、NVS 或钱包数据区。

`clear-data` 输入 `CLEAR` 确认后先备份，再只将钱包区 `0x350000`、`0xB0000` 写为有效空 LittleFS。删除私钥、PIN、配对、渠道和迁移记录，保留固件。非交互且已有明确授权时使用 `--yes`。不提供整片擦除。

备份默认在 `~/.codex/private/rockey-backups/`，目录 0700、文件 0600，含 SHA256 和操作结果。可用 `ROCKEY_BACKUP_DIR` 指定私有目录。

`tools/build/main.sh` 自动归档到 `releases/日期/构建ID/环境/`；UTC 日期、SHA256、字体清单，禁止覆盖同构建的不同内容。产品二进制不提交 Git。

环境：PlatformIO 的 esptool、mklittlefs，以及 pyserial。入口优先使用 `ROCKEY_PYTHON`，其次本项目或相邻 VLP 项目的工具环境。也可直接 `python tools/rockey/main.py ...`。包路径可由 `PLATFORMIO_CORE_DIR`、`ROCKEY_ESPTOOL`、`ROCKEY_MKLITTLEFS` 指定。
