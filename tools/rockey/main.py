#!/usr/bin/env python3
"""Physical maintenance: validate partitions, back up data, write ONE region.
No erase_flash, PIN, private-key or signing API. CP2104 enumeration identifies
candidates, not wallet identity. Clear writes valid empty LittleFS because
production firmware deliberately refuses to format a failed mount.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PRODUCTS = ROOT / "releases"
APP_OFFSET, APP_SIZE, DATA_OFFSET, DATA_SIZE = 0x10000, 0x1A0000, 0x350000, 0xB0000


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def tool(package, filename, variable):
    path = Path(os.environ[variable]).expanduser() if variable in os.environ else Path(os.environ.get("PLATFORMIO_CORE_DIR", str(Path.home() / ".platformio"))) / "packages" / package / filename
    if not path.is_file():
        raise ValueError(f"找不到 {filename}，请安装 PlatformIO 或设置 {variable}")
    return path


def esp(port=None):
    args = [sys.executable, str(tool("tool-esptoolpy", "esptool.py", "ROCKEY_ESPTOOL")), "--chip", "esp32"]
    return args + (["--port", port, "--baud", "115200"] if port else [])


def devices():
    try:
        from serial.tools import list_ports
    except ImportError as error:
        raise ValueError("缺少 pyserial；设置 ROCKEY_PYTHON 或安装 tools/rockey/requirements.txt") from error
    return sorted([p for p in list_ports.comports() if (p.vid, p.pid) == (0x10C4, 0xEA60)], key=lambda p: p.device)


def port(requested):
    ports = devices()
    if requested and any(p.device == requested for p in ports):
        return requested
    if not requested and len(ports) == 1:
        return ports[0].device
    raise ValueError("请先 list 检查连接；多台设备时用 --port 指定 CP2104 串口")


def validate_partitions(boot):
    entries = {}
    for at in range(0x8000, 0x9000, 32):
        magic, kind, sub, offset, size, label, flags = struct.unpack_from("<HBBII16sI", boot, at)
        if magic in (0xFFFF, 0xEBEB):
            break
        if magic != 0x50AA:
            raise ValueError("设备分区表损坏；未写入")
        name = label.split(b"\0", 1)[0].decode("ascii")
        if name in entries:
            raise ValueError("设备分区表重复；未写入")
        entries[name] = (kind, sub, offset, size)
    expected = {}
    for row in csv.reader((ROOT / "partitions/partitions_rockey.csv").read_text().splitlines()):
        if not row or row[0].lstrip().startswith("#"):
            continue
        name, kind, sub, offset, size = [v.strip() for v in row[:5]]
        expected[name] = ({"app": 0, "data": 1}[kind], {"nvs": 2, "ota": 0, "ota_0": 16, "ota_1": 17, "spiffs": 130}[sub], int(offset, 0), int(size, 0))
    if entries != expected or entries["app0"][2:] != (APP_OFFSET, APP_SIZE) or entries["rockey"][2:] != (DATA_OFFSET, DATA_SIZE):
        raise ValueError("设备布局与当前 RocKey 分区不一致；未写入")


def backup(device, action):
    base = Path(os.environ.get("ROCKEY_BACKUP_DIR", str(Path.home() / ".codex/private/rockey-backups"))).expanduser()
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder = Path(tempfile.mkdtemp(prefix=f"before-{action}-{stamp}-", dir=base))
    regions = {}
    for name, offset, size in [("boot-partition-nvs.bin", 0, APP_OFFSET), ("wallet-littlefs.bin", DATA_OFFSET, DATA_SIZE)]:
        path = folder / name
        subprocess.run(esp(device) + ["read_flash", hex(offset), hex(size), str(path)], check=True)
        path.chmod(0o600)
        if path.stat().st_size != size:
            raise ValueError("备份长度错误；未写入")
        regions[name] = {"offset": offset, "size": size, "sha256": sha(path)}
    validate_partitions((folder / "boot-partition-nvs.bin").read_bytes())
    save(folder / "metadata.json", {"port": device, "action": action, "regions": regions})
    print(f"备份完成：{folder}", flush=True)
    return folder


def write(device, offset, image, folder):
    result = {"port": device, "offset": offset, "bytes": image.stat().st_size, "sha256": sha(image), "completed": False}
    save(folder / "operation.json", result)
    subprocess.run(esp(device) + ["write_flash", "-z", "--flash_mode", "keep", "--flash_freq", "keep", "--flash_size", "keep", hex(offset), str(image)], check=True)
    result["completed"] = True  # esptool checks the written hash before success.
    save(folder / "operation.json", result)


def archive(build_id, environment):
    if not re.fullmatch(r"\d{8}T\d{6}Z-[A-Za-z0-9]+", build_id) or not re.fullmatch(r"m5stack-core-[a-zA-Z0-9-]+", environment) or any(v in environment for v in ("e2e", "debug", "dev")):
        raise ValueError("最终产品只接收有效发布构建")
    source = ROOT / ".pio/releases" / build_id / environment
    firmware = source / "firmware.bin"
    if not firmware.is_file():
        raise ValueError("未找到通过发布检查的固件")
    folder = PRODUCTS / f"{build_id[:4]}-{build_id[4:6]}-{build_id[6:8]}" / build_id / environment
    name = f"rockey-{environment}-{build_id}.bin"
    if folder.exists():
        m = json.loads((folder / "manifest.json").read_text())
        if m["sha256"] != sha(firmware) or sha(folder / name) != sha(firmware):
            raise ValueError("已有同时间不同内容归档，禁止覆盖")
    else:
        folder.mkdir(parents=True)
        shutil.copy2(firmware, folder / name)
        shutil.copy2(source / "font-MANIFEST.md", folder / "font-MANIFEST.md")
        save(folder / "manifest.json", {"buildId": build_id, "environment": environment, "timeBasis": "UTC", "firmware": name, "bytes": firmware.stat().st_size, "sha256": sha(firmware), "appOffset": APP_OFFSET, "appCapacity": APP_SIZE})
    return folder / name


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="RocKey 统一维护工具，不操作浏览器钱包")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="列出已连接的钱包候选设备，不读取私钥")
    flash = sub.add_parser("flash", help="刷入 xxx.bin，只写固件 app0")
    flash.add_argument("firmware", type=Path)
    flash.add_argument("--port")
    clear = sub.add_parser("clear-data", help="清空设备私钥、PIN、配对、渠道和迁移记录")
    clear.add_argument("--port")
    clear.add_argument("--yes", action="store_true", help="已明确同意删除，用于非交互调用")
    sub.add_parser("products", help="列出按时间归档的最终产品")
    pack = sub.add_parser("archive", help="归档已通过发布检查的构建")
    pack.add_argument("build_id")
    pack.add_argument("environment")
    args = parser.parse_args()
    if args.command == "list":
        ports = devices()
        for p in ports:
            print(f"{p.device}\tM5Stack / CP2104（候选）\t序号：{p.serial_number or '未知'}")
        if not ports:
            print("没有已连接的钱包候选设备")
    elif args.command == "products":
        for path in sorted(PRODUCTS.glob("*/*/*/manifest.json")):
            m = json.loads(path.read_text())
            print(f"{m['buildId']}\t{m['environment']}\t{path.parent / m['firmware']}")
    elif args.command == "archive":
        print(archive(args.build_id, args.environment))
    elif args.command == "flash":
        image = args.firmware.expanduser().resolve()
        if not image.is_file() or not 0 < image.stat().st_size <= APP_SIZE:
            raise ValueError("固件不存在或超过 app0 容量")
        manifest = image.parent / "manifest.json"
        if manifest.is_file():
            m = json.loads(manifest.read_text())
            if m.get("firmware") != image.name or m.get("sha256") != sha(image):
                raise ValueError("固件与归档清单不一致；未写入")
        subprocess.run(esp() + ["image_info", str(image)], check=True)
        device = port(args.port)
        folder = backup(device, "flash")
        write(device, APP_OFFSET, image, folder)
        print("固件更新完成，钱包数据区未写入。")
    else:
        if not args.yes and (not sys.stdin.isatty() or input("将删除设备钱包数据。输入 CLEAR 确认：") != "CLEAR"):
            raise ValueError("未确认清空；未写入")
        device = port(args.port)
        formatter = tool("tool-mklittlefs", "mklittlefs", "ROCKEY_MKLITTLEFS")
        with tempfile.TemporaryDirectory(prefix="rockey-empty-") as temporary:
            empty = Path(temporary) / "empty"
            empty.mkdir()
            image = Path(temporary) / "littlefs.bin"
            subprocess.run([str(formatter), "-c", str(empty), "-b", "4096", "-p", "256", "-s", str(DATA_SIZE), str(image)], check=True)
            if image.stat().st_size != DATA_SIZE:
                raise ValueError("空文件系统长度错误；未写入")
            folder = backup(device, "clear-data")
            write(device, DATA_OFFSET, image, folder)
        print("钱包数据清空完成，固件保留；首页可创建私钥或连接 Keymaster 导入。")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, KeyboardInterrupt) as error:
        print(f"RocKey：{error}", file=sys.stderr)
        sys.exit(1)
