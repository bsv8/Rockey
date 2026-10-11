# RocKey 最终产品

发布固件按 UTC 构建时间归档：`YYYY-MM-DD/构建ID/环境/rockey-环境-构建ID.bin`。随附 SHA256 清单和实际字体清单。同一构建禁止覆盖不同内容。

`tools/build/main.sh` 自动归档；`./rockey products` 列出产品，`./rockey flash 文件.bin` 更新设备。二进制是本机生成物，不提交 Git。
